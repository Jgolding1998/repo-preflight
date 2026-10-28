import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import preflight


class PreflightTests(unittest.TestCase):
    def test_repository_git_executable_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with mock.patch.object(preflight.shutil, "which", return_value=str(root / "git.exe")), mock.patch.object(preflight.subprocess, "run") as child:
                with self.assertRaises(ValueError):
                    preflight.git(root, "ls-files")
                child.assert_not_called()

    def test_sensitive_values_never_enter_report(self):
        token = "gh" + "p_" + "aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0"
        email = "private" + "@" + "example.org"
        path = "C:" + chr(92) + "Users" + chr(92) + "someone" + chr(92) + "work"
        data = f"{token}\n{email}\n{path}\nhello{chr(0x2014)}world".encode()
        findings = preflight.scan_bytes("sample.txt", data)
        self.assertEqual({item.rule for item in findings}, {"credential-token", "email", "personal-path", "em-dash"})
        report = json.dumps([preflight.asdict(item) for item in findings])
        for value in (token, email, path):
            self.assertNotIn(value, report)

    def test_placeholder_and_real_assignment(self):
        data = ('api_' + 'key = "your-own-key"\n' + 'pass' + 'word = "fixture-private-value"').encode()
        self.assertEqual([item.rule for item in preflight.scan_bytes("a.py", data)], ["credential-assignment"])

    def test_quoted_multiline_fallback_and_unquoted_config(self):
        key = "pass" + "word"
        samples = [json.dumps({key: "synthetic-private-value"}), key + ' = (\n "synthetic-private-value"\n)', 'MONGO_' + 'TOKEN = process.env.OWN_TOKEN ||\n "synthetic-private-value"', key.upper() + '=synthetic-private-value']
        for sample in samples:
            with self.subTest(sample=sample[:12]):
                self.assertIn("credential-assignment", [item.rule for item in preflight.scan_bytes("config.txt", sample.encode())])

    def test_utf16_and_json_escaped_paths(self):
        email = "synthetic" + "@" + "example.org"
        self.assertIn("email", [item.rule for item in preflight.scan_bytes("utf16.txt", email.encode("utf-16"))])
        personal = "C:" + chr(92) + "Users" + chr(92) + "someone" + chr(92) + "work"
        self.assertIn("personal-path", [item.rule for item in preflight.scan_bytes("config.json", json.dumps({"path": personal}).encode())])

    def test_fetch_credentials_policy_is_not_a_secret(self):
        self.assertFalse(preflight.scan_bytes("app.js", b'credentials: "same-origin"'))
        self.assertTrue(preflight.scan_bytes("config.json", ('"credentials": "' + 'fixture-private-value"').encode()))

    def test_yaml_plain_value_and_private_key_headers(self):
        sample = "pass" + "word: fixture-private-value\n"
        self.assertIn("credential-assignment", [item.rule for item in preflight.scan_bytes("a.yaml", sample.encode())])
        for kind in ("ENCRYPTED PRIVATE KEY", "PGP PRIVATE KEY BLOCK"):
            data = ("-----BEGIN " + kind + "-----").encode()
            self.assertIn("private-key", [item.rule for item in preflight.scan_bytes("key.txt", data)])

    def test_additional_provider_shapes_and_placeholder_prefix(self):
        samples = ["sk" + "_live_" + "a1B2c3D4e5F6g7H8j9K0", "xo" + "xb-" + "1234567890-" + "a1B2c3D4e5F6g7H8j9K0", "AI" + "za" + "a" * 35]
        for sample in samples:
            self.assertIn("credential-token", [item.rule for item in preflight.scan_bytes("a.txt", sample.encode())])
        sample = 'tok' + 'en = "example' + 'a1B2c3D4e5F6g7H8j9K0"'
        self.assertIn("credential-assignment", [item.rule for item in preflight.scan_bytes("a.py", sample.encode())])
        text = "synthetic" + "@" + "example.org"
        self.assertIn("email", [item.rule for item in preflight.scan_bytes("a.txt", text.encode("utf-32"))])

    def test_untrusted_git_helpers_are_not_executed(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "repo"
            root.mkdir()
            def run(*args, **kwargs):
                return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, **kwargs)
            run("init", "-q")
            run("config", "user.name", "Fixture")
            run("config", "user.email", "")
            (root / "a.txt").write_text("hello")
            run("add", ".")
            run("commit", "-qm", "Fixture")
            marker = base / "executed"
            helper = base / "helper.sh"
            helper.write_text("#!/bin/sh\nprintf done > '" + marker.as_posix() + "'\n")
            helper.chmod(0o755)
            tree = run("rev-parse", "HEAD^{tree}").stdout.decode().strip()
            signature = "-----BEGIN PGP SIGNATURE-----\n \n -----END PGP SIGNATURE-----"
            body = f"tree {tree}\nauthor Fixture <> 0 +0000\ncommitter Fixture <> 0 +0000\ngpgsig {signature}\n\nfixture\n"
            oid = run("hash-object", "-t", "commit", "-w", "--stdin", input=body.encode()).stdout.decode().strip()
            run("update-ref", "refs/heads/signed", oid)
            run("config", "core.fsmonitor", helper.as_posix())
            run("config", "log.showSignature", "true")
            run("config", "gpg.program", helper.as_posix())
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(preflight.main([str(root), "--tracked", "--history"]), 0)
            self.assertFalse(marker.exists())

    def test_environment_and_large_file(self):
        self.assertEqual(preflight.scan_bytes(".env", b"")[0].rule, "environment-file")
        self.assertFalse(preflight.scan_bytes(".env.example", b""))
        self.assertEqual(preflight.scan_bytes("large", b"x" * (preflight.MAX_BYTES + 1))[0].rule, "oversized-file")

    def test_binary_skipped_but_non_utf8_is_visible(self):
        self.assertEqual(preflight.scan_bytes("a.png", b"\0\xff"), [])
        self.assertEqual(preflight.scan_bytes("a.txt", b"\xff")[0].rule, "unreadable-text")

    def test_exact_exception(self):
        item = preflight.finding("email", "a.txt", 1, "synthetic")
        entry = {"rule": item.rule, "path": item.path, "fingerprint": item.fingerprint, "reason": "Synthetic fixture"}
        self.assertTrue(preflight.allowed(item, [entry]))
        self.assertFalse(preflight.allowed(preflight.finding("email", "b.txt", 1, "synthetic"), [entry]))

    def test_cli_exit_codes_and_config_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "clean.txt").write_text("plain text")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(preflight.main([directory]), 0)
                (root / "dirty.txt").write_text("synthetic" + "@" + "example.org")
                self.assertEqual(preflight.main([directory]), 1)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(preflight.main([directory, "--config", str(root / "missing")]), 2)

    def test_invalid_exception_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"allow": [{"rule": "email", "path": "*"}]}))
            with self.assertRaises(ValueError):
                preflight.load_config(path)

    def test_symlink_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "real.txt").write_text("hello")
            try:
                (root / "linked.txt").symlink_to(root / "real.txt")
            except OSError:
                self.skipTest("Creating symlinks requires OS permission")
            self.assertEqual([item[0] for item in preflight.current_files(root, False)], ["real.txt"])

    def test_history_detects_removed_value(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def run(*args):
                subprocess.run(["git", "-C", directory, *args], check=True, capture_output=True)
            run("init", "-q")
            run("config", "user.name", "Fixture")
            run("config", "user.email", "")
            path = root / "notes.txt"
            path.write_text("private" + "@" + "example.org")
            run("add", ".")
            run("commit", "-qm", "Synthetic fixture")
            path.write_text("clean")
            run("add", ".")
            run("commit", "-qm", "Remove fixture")
            found = [item for name, data, rev in preflight.history_files(root) for item in preflight.scan_bytes(name, data, rev)]
            self.assertEqual([item.rule for item in found], ["email"])


if __name__ == "__main__":
    unittest.main()
