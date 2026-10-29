"""Redacted repository checks using only the Python standard library."""

from __future__ import annotations

import argparse
from bisect import bisect_right
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import threading
import time

MAX_BYTES = 2 * 1024 * 1024
MAX_TERMS = 128
MAX_EXCEPTIONS = 4096
MAX_FIELD_NAME = 128
MAX_GIT_OUTPUT = 8 * 1024 * 1024
MAX_HISTORY_OBJECTS = 100_000
MAX_HISTORY_BYTES = 64 * 1024 * 1024
HISTORY_TIMEOUT = 120
OBJECT_ID = re.compile(rb"[0-9a-f]{40}|[0-9a-f]{64}")
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"}
EMAIL = re.compile(r"\b[A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,253}\.[A-Z]{2,63}(?![A-Z0-9-])", re.I)
PERSONAL_PATH = re.compile(r"(?:[A-Z]:[\\/]Users[\\/][^\\/\s]+|/(?:Users|home)/[^/\s]+)", re.I)
TOKEN = re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,}|sk-(?:proj-)?[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16}|sk_live_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|AIza[A-Za-z0-9_-]{35})")
FIELD_PATTERN = (r"(?<![\w-])(?=[a-z0-9_-]{0," + str(MAX_FIELD_NAME - 1)
                 + r"}(?:api[_-]?key|token|password|secret|credential))"
                 + r"[a-z0-9_-]{1," + str(MAX_FIELD_NAME) + r"}(?![\w-])")
ASSIGNMENT = re.compile(r"[\"']?" + FIELD_PATTERN + r"[\"']?\s*[:=]\s*(?:\(\s*)?[\"']([^\"'\r\n]{8,})[\"']", re.I)
ENV_ASSIGNMENT = re.compile(r"^[ \t]*(?:export[ \t]+)?" + FIELD_PATTERN + r"[ \t]*[:=][ \t]*([^\s\"'#$({][^\s#;]{7,})[ \t\r]*$", re.I | re.M)
FALLBACK = re.compile(FIELD_PATTERN + r"\s*=\s*(?:process\.env\.[A-Z0-9_]+|os\.environ\.get\([^()\r\n]{0,1024}\)|os\.getenv\([^()\r\n]{0,1024}\))\s*(?:\|\||or)\s*[\"']([^\"'\r\n]{8,})[\"']", re.I)
PLACEHOLDER = re.compile(r"^(?:your[-_ ].*|replace[-_ ].*|example|example[-_ ].*|placeholder|placeholder[-_ ].*|changeme|<.*>|\$\{.*\}|test[-_ ].*)$", re.I)
PRIVATE_KEY = re.compile(r"-----BEGIN (?:(?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----")


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    line: int
    fingerprint: str
    revision: str = ""


class HistoryScanError(ValueError):
    pass


def finding(rule: str, path: str, line: int, value: str, revision: str = "") -> Finding:
    digest = hashlib.sha256((rule + "\0" + value).encode()).hexdigest()[:20]
    return Finding(rule, path, line, digest, revision)


def scan_bytes(path: str, data: bytes, revision: str = "", terms: tuple[str, ...] = ()) -> list[Finding]:
    output: list[Finding] = []
    folded_terms = tuple(term.casefold() for term in terms)
    base = Path(path).name.lower()
    if (base == ".env" or base.startswith(".env.")) and not base.endswith((".example", ".template", ".sample")):
        output.append(finding("environment-file", path, 0, path, revision))
    if len(data) > MAX_BYTES:
        return output + [finding("oversized-file", path, 0, str(len(data)), revision)]
    try:
        if data.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
            content = data.decode("utf-32")
        elif data.startswith((b"\xff\xfe", b"\xfe\xff")):
            content = data.decode("utf-16")
        elif b"\0" in data:
            if path in {"[commit-metadata].txt", "[tag-metadata].txt"}:
                return output + [finding("unreadable-text", path, 0, path, revision)]
            return output
        else:
            content = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return output + [finding("unreadable-text", path, 0, path, revision)]
    for number, line in enumerate(content.splitlines(), 1):
        for rule, pattern in (("credential-token", TOKEN), ("private-key", PRIVATE_KEY), ("email", EMAIL), ("personal-path", PERSONAL_PATH)):
            candidate = line.replace("\\\\", "\\").replace("\\/", "/") if rule == "personal-path" else line
            for match in pattern.finditer(candidate):
                output.append(finding(rule, path, number, match.group(), revision))
        if chr(0x2014) in line:
            output.append(finding("em-dash", path, number, line, revision))
        folded = line.casefold() if terms else ""
        for term in folded_terms:
            if term in folded:
                output.append(finding("blocked-term", path, number, term, revision))
    patterns = [ASSIGNMENT, FALLBACK]
    if Path(path).suffix.lower() in {".txt", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".sh"} or base in {".profile", ".bash_profile", ".bashrc", ".zprofile", ".zshrc"} or base.startswith(".env") or path == "[unnamed-blob]":
        patterns.append(ENV_ASSIGNMENT)
    line_starts = [0] + [match.end() for match in re.finditer("\n", content)]
    for pattern in patterns:
        for match in pattern.finditer(content):
            value = match.group(1)
            if re.match(r"[\"']?credentials[\"']?\s*:", match.group(), re.I) and value in {"same-origin", "omit", "include"}:
                continue
            if not PLACEHOLDER.fullmatch(value) and not value.startswith(("os.environ", "process.env")):
                number = bisect_right(line_starts, match.start())
                output.append(finding("credential-assignment", path, number, value, revision))
    return list(dict.fromkeys(output))


def git(root: Path, *args: str, deadline: float | None = None, input: bytes | None = None) -> bytes:
    location = shutil.which("git")
    if not location:
        raise ValueError("Git is not installed")
    executable = Path(location).resolve()
    if executable.is_relative_to(root) or executable.parent == Path.cwd().resolve():
        raise ValueError("Refusing a Git executable from the scanned repository or current directory")
    environment = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    environment.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "GIT_GRAFT_FILE": os.devnull,
                        "GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": ""})
    command = [str(executable), "--no-pager", "--no-replace-objects", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull,
               "-c", "log.showSignature=false", "-c", "maintenance.auto=false", "-c", "gc.auto=0", "-C", str(root), *args]
    timeout = 60.0 if deadline is None else min(60.0, deadline - time.monotonic())
    if timeout <= 0:
        raise HistoryScanError("History deadline reached. The scan is incomplete; reduce the scope and rerun.")
    stdin = subprocess.DEVNULL if input is None else subprocess.PIPE
    with subprocess.Popen(command, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=environment) as process:
        def stop():
            try:
                process.kill()
            except OSError:
                pass
        def feed():
            try:
                process.stdin.write(input)
                process.stdin.close()
            except (OSError, ValueError):
                pass
        timer = threading.Timer(timeout, stop)
        timer.daemon = True
        timer.start()
        writer = None
        if input is not None:
            writer = threading.Thread(target=feed, daemon=True)
            writer.start()
        try:
            data = process.stdout.read(MAX_GIT_OUTPUT + 1)
            if len(data) > MAX_GIT_OUTPUT:
                stop()
                raise HistoryScanError("Git output exceeds the scan limit. Reduce the scan scope and rerun.")
            status = process.wait(timeout=2)
            if deadline is not None and time.monotonic() >= deadline:
                raise HistoryScanError("History deadline reached. The scan is incomplete; reduce the scope and rerun.")
            if status:
                raise ValueError("Git operation failed; confirm the directory is a repository")
            return data
        finally:
            timer.cancel()
            if process.poll() is None:
                stop()
            process.wait(timeout=2)
            if writer is not None:
                writer.join(timeout=2)


def current_files(root: Path, tracked: bool):
    if tracked:
        names = git(root, "ls-files", "-z").decode("utf-8").split("\0")
        paths = [root / name for name in names if name]
    else:
        paths = walk_files(root)
    for path in paths:
        relative = path.relative_to(root)
        if any(part in SKIP_DIRS for part in relative.parts) or path.is_symlink():
            continue
        if path.is_file():
            if not path.resolve().is_relative_to(root):
                continue
            with path.open("rb") as stream:
                data = stream.read(MAX_BYTES + 1)
            yield relative.as_posix(), data, ""


def walk_files(root: Path):
    def fail(error):
        raise error
    for directory, folders, files in os.walk(root, onerror=fail):
        base = Path(directory)
        folders[:] = sorted(name for name in folders if name not in SKIP_DIRS and not is_link(base / name))
        for name in sorted(files):
            yield base / name


def is_link(path: Path) -> bool:
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode):
        return True
    if getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        if getattr(info, "st_reparse_tag", 0) in {0xA0000003, 0xA000000C}:
            return True
        raise ValueError("Unsupported reparse point. The scan is incomplete; use a fully local checkout.")
    return False


def history_files(root: Path):
    deadline = time.monotonic() + HISTORY_TIMEOUT
    def check_deadline():
        if time.monotonic() >= deadline:
            raise HistoryScanError("History deadline reached. The scan is incomplete; reduce the scope and rerun.")
    def read(*args, input=None):
        check_deadline()
        return git(root, *args, deadline=deadline, input=input)
    def read_cost(item):
        return item[2] + 128 if item[2] <= MAX_BYTES else 0
    if read("rev-parse", "--is-shallow-repository").strip() == b"true":
        raise HistoryScanError("History scan requires a full clone. Fetch complete history (for example, git fetch --unshallow) and rerun.")
    listing = read("rev-list", "--objects", "--all").split(b"\n")
    if listing[-1] == b"":
        listing.pop()
    if len(listing) > MAX_HISTORY_OBJECTS:
        raise HistoryScanError("History exceeds the object-count limit. Reduce the scan scope and rerun.")
    entries = []
    for line in listing:
        oid, _, name = line.partition(b" ")
        if not OBJECT_ID.fullmatch(oid):
            raise ValueError("Unexpected Git object listing")
        entries.append((oid, name.decode("utf-8")))
    if not entries:
        return
    checks = read("cat-file", "--batch-check", "--buffer", input=b"".join(oid + b"\n" for oid, _ in entries)).split(b"\n")
    if len(checks) != len(entries) + 1 or checks[-1] != b"":
        raise ValueError("Git object check is incomplete")
    selected = []
    scanned_bytes = 0
    for (oid, name), check in zip(entries, checks):
        fields = check.split(b" ")
        if len(fields) != 3 or fields[0] != oid or not fields[2].isdigit():
            raise ValueError("Git object is missing or unreadable")
        kind, size = fields[1], int(fields[2])
        if kind not in {b"blob", b"commit", b"tag"}:
            continue
        path = name or "[unnamed-blob]"
        if kind != b"blob":
            path = "[commit-metadata].txt" if kind == b"commit" else "[tag-metadata].txt"
        scanned_bytes += min(size, MAX_BYTES + 1)
        if scanned_bytes > MAX_HISTORY_BYTES:
            raise HistoryScanError("History exceeds the byte budget. Reduce the scan scope and rerun.")
        selected.append((oid, kind, size, path))
    start = 0
    while start < len(selected):
        end, output = start, 0
        while end < len(selected) and (end == start or output + read_cost(selected[end]) <= MAX_GIT_OUTPUT):
            output += read_cost(selected[end])
            end += 1
        group = selected[start:end]
        wanted = [item for item in group if item[2] <= MAX_BYTES]
        data = read("cat-file", "--batch", "--buffer", input=b"".join(oid + b"\n" for oid, *_ in wanted)) if wanted else b""
        position = 0
        for oid, kind, size, path in group:
            if size > MAX_BYTES:
                yield path, b"x" * (MAX_BYTES + 1), oid.decode("ascii")
                check_deadline()
                continue
            header_end = data.find(b"\n", position)
            body_end = header_end + 1 + size
            if header_end < 0 or data[position:header_end] != b"%s %s %d" % (oid, kind, size) or data[body_end:body_end + 1] != b"\n":
                raise ValueError("Git object content is incomplete")
            yield path, data[header_end + 1:body_end], oid.decode("ascii")
            position = body_end + 1
            check_deadline()
        if position != len(data):
            raise ValueError("Git object content is incomplete")
        start = end


def _unique_config_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate config fields")
        result[key] = value
    return result


def load_config(path: Path | None) -> tuple[tuple[str, ...], list[dict]]:
    if path is None:
        return (), []
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("Config exceeds the size limit")
    try:
        config = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique_config_fields)
    except (RecursionError, OverflowError):
        raise ValueError("Config nesting or number is unsupported") from None
    if type(config) is not dict or set(config) - {"blocked_terms", "allow"}:
        raise ValueError("Config must contain only blocked_terms and allow")
    terms = config.get("blocked_terms", [])
    allows = config.get("allow", [])
    if not isinstance(terms, list) or len(terms) > MAX_TERMS or any(not isinstance(term, str) or not term.strip() for term in terms):
        raise ValueError("blocked_terms must be a list of nonempty strings")
    if not isinstance(allows, list) or len(allows) > MAX_EXCEPTIONS:
        raise ValueError("allow must be a list")
    for item in allows:
        if not isinstance(item, dict) or not all(isinstance(item.get(key), str) and item[key].strip() for key in ("rule", "path", "fingerprint", "reason")):
            raise ValueError("Each exception requires rule, exact path, fingerprint, and reason")
    return tuple(terms), allows


def allowed(item: Finding, entries: list[dict]) -> bool:
    return any(entry["rule"] == item.rule and entry["path"] == item.path and entry["fingerprint"] == item.fingerprint for entry in entries)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan a repository without printing matched content.")
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--tracked", action="store_true", help="Scan only Git-tracked working files")
    parser.add_argument("--history", action="store_true", help="Also scan reachable Git blobs, commit metadata and annotated tags")
    parser.add_argument("--config", type=Path, help="JSON rules and exact fingerprint exceptions")
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)
    try:
        root = Path(args.root).resolve(strict=True)
        if not root.is_dir():
            raise ValueError("Root must be a directory")
        terms, exceptions = load_config(args.config)
        found: list[Finding] = []
        count = 0
        for name, data, revision in current_files(root, args.tracked):
            count += 1
            found.extend(scan_bytes(name, data, revision, terms))
        if args.history:
            for name, data, revision in history_files(root):
                count += 1
                found.extend(scan_bytes(name, data, revision, terms))
        found = list(dict.fromkeys(item for item in found if not allowed(item, exceptions)))
    except HistoryScanError as error:
        print(str(error), file=sys.stderr)
        return 2
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        print("Scan could not complete. Check paths, config, permissions, and Git installation.", file=sys.stderr)
        return 2
    if args.as_json:
        print(json.dumps({"scanned": count, "findings": [asdict(item) for item in found]}, indent=2))
    else:
        for item in found:
            print(f"{item.path}:{item.line} {item.rule} [{item.fingerprint}]" + (f" blob={item.revision}" if item.revision else ""))
        print(f"Scanned {count} files/objects. {len(found)} findings. Matched values are never printed.")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
