"""Redacted repository checks using only the Python standard library."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

MAX_BYTES = 2 * 1024 * 1024
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"}
EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
PERSONAL_PATH = re.compile(r"(?:[A-Z]:[\\/]Users[\\/][^\\/\s]+|/(?:Users|home)/[^/\s]+)", re.I)
TOKEN = re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,}|sk-(?:proj-)?[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16}|sk_live_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|AIza[A-Za-z0-9_-]{35})")
FIELD_PATTERN = r"[a-z0-9_]*(?:api[_-]?key|token|password|secret|credential)[a-z0-9_]*"
ASSIGNMENT = re.compile(r"[\"']?\b" + FIELD_PATTERN + r"\b[\"']?\s*[:=]\s*(?:\(\s*)?[\"']([^\"'\r\n]{8,})[\"']", re.I)
ENV_ASSIGNMENT = re.compile(r"^\s*" + FIELD_PATTERN + r"\s*[:=]\s*([^\s\"'#$({][^\s#;]{7,})\s*$", re.I | re.M)
FALLBACK = re.compile(r"\b" + FIELD_PATTERN + r"\b\s*=\s*(?:process\.env\.[A-Z0-9_]+|os\.environ\.get\([^\r\n]*?\)|os\.getenv\([^\r\n]*?\))\s*(?:\|\||or)\s*[\"']([^\"'\r\n]{8,})[\"']", re.I)
PLACEHOLDER = re.compile(r"^(?:your[-_ ].*|replace[-_ ].*|example|example[-_ ].*|placeholder|placeholder[-_ ].*|changeme|<.*>|\$\{.*\}|test[-_ ].*)$", re.I)
PRIVATE_KEY = re.compile(r"-----BEGIN (?:(?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----")


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    line: int
    fingerprint: str
    revision: str = ""


def finding(rule: str, path: str, line: int, value: str, revision: str = "") -> Finding:
    digest = hashlib.sha256((rule + "\0" + value).encode()).hexdigest()[:20]
    return Finding(rule, path, line, digest, revision)


def scan_bytes(path: str, data: bytes, revision: str = "", terms: tuple[str, ...] = ()) -> list[Finding]:
    output: list[Finding] = []
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
        for term in terms:
            if term.casefold() in line.casefold():
                output.append(finding("blocked-term", path, number, term.casefold(), revision))
    patterns = [ASSIGNMENT, FALLBACK]
    if Path(path).suffix.lower() in {".txt", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf"} or base.startswith(".env"):
        patterns.append(ENV_ASSIGNMENT)
    for pattern in patterns:
        for match in pattern.finditer(content):
            value = match.group(1)
            if re.match(r"[\"']?credentials[\"']?\s*:", match.group(), re.I) and value in {"same-origin", "omit", "include"}:
                continue
            if not PLACEHOLDER.fullmatch(value) and not value.startswith(("os.environ", "process.env")):
                number = content.count("\n", 0, match.start()) + 1
                output.append(finding("credential-assignment", path, number, value, revision))
    return list(dict.fromkeys(output))


def git(root: Path, *args: str) -> bytes:
    location = shutil.which("git")
    if not location:
        raise ValueError("Git is not installed")
    executable = Path(location).resolve()
    if executable.is_relative_to(root) or executable.parent == Path.cwd().resolve():
        raise ValueError("Refusing a Git executable from the scanned repository or current directory")
    environment = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    environment.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"})
    command = [str(executable), "--no-pager", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull,
               "-c", "log.showSignature=false", "-c", "maintenance.auto=false", "-c", "gc.auto=0", "-C", str(root), *args]
    result = subprocess.run(command, capture_output=True, check=False, env=environment, timeout=60)
    if result.returncode:
        raise ValueError("Git operation failed; confirm the directory is a repository")
    return result.stdout


def current_files(root: Path, tracked: bool):
    if tracked:
        names = git(root, "ls-files", "-z").decode("utf-8").split("\0")
        paths = [root / name for name in names if name]
    else:
        paths = root.rglob("*")
    for path in paths:
        relative = path.relative_to(root)
        if any(part in SKIP_DIRS for part in relative.parts) or path.is_symlink():
            continue
        if path.is_file():
            if not path.resolve().is_relative_to(root):
                continue
            if path.stat().st_size > MAX_BYTES:
                yield relative.as_posix(), b"x" * (MAX_BYTES + 1), ""
            else:
                yield relative.as_posix(), path.read_bytes(), ""


def history_files(root: Path):
    objects = git(root, "rev-list", "--objects", "--all").decode("utf-8").splitlines()
    for entry in objects:
        oid, _, name = entry.partition(" ")
        if not name or git(root, "cat-file", "-t", oid).strip() != b"blob":
            continue
        size = int(git(root, "cat-file", "-s", oid))
        data = b"x" * (MAX_BYTES + 1) if size > MAX_BYTES else git(root, "cat-file", "blob", oid)
        yield name, data, oid


def load_config(path: Path | None) -> tuple[tuple[str, ...], list[dict]]:
    if path is None:
        return (), []
    config = json.loads(path.read_text(encoding="utf-8"))
    terms = config.get("blocked_terms", [])
    allows = config.get("allow", [])
    if not isinstance(terms, list) or any(not isinstance(term, str) or not term.strip() for term in terms):
        raise ValueError("blocked_terms must be a list of nonempty strings")
    if not isinstance(allows, list):
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
    parser.add_argument("--history", action="store_true", help="Also scan all reachable Git blobs and commit identities")
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
            metadata = git(root, "log", "--no-show-signature", "--all", "--format=%H%x09%an%x09%ae%x09%cn%x09%ce").decode("utf-8")
            found.extend(scan_bytes("[commit-identities]", metadata.encode(), terms=terms))
        found = list(dict.fromkeys(item for item in found if not allowed(item, exceptions)))
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        print("Scan could not complete. Check paths, config, permissions, and Git installation.", file=sys.stderr)
        return 2
    if args.as_json:
        print(json.dumps({"scanned": count, "findings": [asdict(item) for item in found]}, indent=2))
    else:
        for item in found:
            print(f"{item.path}:{item.line} {item.rule} [{item.fingerprint}]" + (f" blob={item.revision}" if item.revision else ""))
        print(f"Scanned {count} files/blobs. {len(found)} findings. Matched values are never printed.")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
