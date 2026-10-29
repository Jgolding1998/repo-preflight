import contextlib
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import preflight


class PreflightTests(unittest.TestCase):
    def test_overall_history_deadline_spans_successful_git_calls(self):
        now = [0.0]
        calls = []
        oid = b"ab" * 20
        def successful_git(root, *args, deadline=None, input=None):
            calls.append((args,deadline))
            now[0] += 2
            if args[0] == "rev-parse":
                return b"false\n"
            if args[0] == "rev-list":
                return oid + b" fixture.txt\n"
            return oid + b" blob 5\n"
        with tempfile.TemporaryDirectory() as directory:
            errors, output = io.StringIO(), io.StringIO()
            with mock.patch.object(preflight, "HISTORY_TIMEOUT", 5), mock.patch.object(preflight.time, "monotonic", side_effect=lambda:now[0]), mock.patch.object(preflight, "git", side_effect=successful_git), contextlib.redirect_stderr(errors), contextlib.redirect_stdout(output):
                self.assertEqual(preflight.main([directory,"--history","--json"]), 2)
            self.assertEqual(len(calls), 3)
            self.assertTrue(all(deadline == 5 for _,deadline in calls))
            self.assertIn("deadline", errors.getvalue())
            self.assertIn("incomplete", errors.getvalue())
            self.assertEqual(output.getvalue(), "")

    def test_git_deadline_uses_the_remaining_history_time(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(preflight.time, "monotonic", return_value=100), mock.patch.object(preflight.subprocess,"Popen") as launch, mock.patch.object(preflight.threading,"Timer") as timer:
                process = launch.return_value.__enter__.return_value
                process.stdout.read.return_value = b""
                process.wait.return_value = 0
                process.poll.return_value = 0
                self.assertEqual(preflight.git(Path(directory).resolve(),"rev-parse",deadline=103), b"")
                self.assertEqual(timer.call_args.args[0], 3)

    def test_exported_environment_and_profile_values_are_complete_and_redacted(self):
        value = "fixture-private-123456789"
        key = "GITHUB_" + "TOKEN"
        for path in (".env", ".profile", "profile.txt", "setup.sh"):
            for prefix in ("export ", "\texport\t", "  export  "):
                with self.subTest(path=path,prefix_spaces=len(prefix)):
                    found = [item for item in preflight.scan_bytes(path,(prefix+key+" = "+value+"\r\n").encode()) if item.rule == "credential-assignment"]
                    self.assertEqual(len(found), 1)
                    self.assertEqual(found[0].fingerprint, preflight.finding("credential-assignment",path,1,value).fingerprint)
                    self.assertNotIn(value,json.dumps([preflight.asdict(item) for item in found]))

    def test_many_incomplete_export_lines_have_bounded_scan_time(self):
        script = "import preflight; unit=b'export TOKEN \\n'; data=(unit*(preflight.MAX_BYTES//len(unit)+1))[:preflight.MAX_BYTES]; assert preflight.scan_bytes('.profile',data) == []"
        result = subprocess.run([sys.executable,"-c",script],cwd=Path(__file__).resolve().parents[1],capture_output=True,timeout=12)
        self.assertEqual(result.returncode,0)

    def make_repository(self, root):
        def run(*args, data=None):
            return subprocess.check_output(["git", "-C", str(root), *args], input=data, stderr=subprocess.DEVNULL)
        run("init", "-q")
        run("config", "user.name", "Fixture")
        run("config", "user.email", "")
        (root / "a.txt").write_text("clean")
        run("add", ".")
        run("commit", "-qm", "Initial fixture")
        return run

    def test_graft_file_cannot_hide_an_ancestor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self.make_repository(root)
            (root / "a.txt").write_text("gh" + "p_" + "A" * 24)
            run("add", ".")
            run("commit", "-qm", "Synthetic fixture")
            (root / "a.txt").write_text("clean")
            run("add", ".")
            run("commit", "-qm", "Remove fixture")
            graft = root / ".git/info/grafts"
            graft.write_bytes(run("rev-parse", "HEAD"))
            found = [item for name, data, revision in preflight.history_files(root) for item in preflight.scan_bytes(name, data, revision)]
            self.assertIn("credential-token", [item.rule for item in found])

    def test_a_directly_tagged_blob_without_a_filename_is_scanned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self.make_repository(root)
            content = ("gh" + "p_" + "B" * 24 + "\npass" + "word=synthetic-private-value").encode()
            oid = run("hash-object", "-w", "--stdin", data=content).decode().strip()
            run("tag", "fixture-blob", oid)
            found = [item for name, data, revision in preflight.history_files(root) for item in preflight.scan_bytes(name, data, revision)]
            item = next(item for item in found if item.rule == "credential-token")
            self.assertEqual(item.path, "[unnamed-blob]")
            self.assertEqual(item.revision, oid)
            self.assertIn("credential-assignment", [item.rule for item in found if item.path == "[unnamed-blob]"])

    def test_shallow_history_is_incomplete_with_fetch_guidance(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            source.mkdir()
            run = self.make_repository(source)
            (source / "a.txt").write_text("new clean revision")
            run("add", ".")
            run("commit", "-qm", "Second fixture")
            clone = Path(directory) / "shallow"
            subprocess.run(["git", "clone", "-q", "--depth", "1", source.as_uri(), str(clone)], check=True, capture_output=True)
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(preflight.main([str(clone), "--tracked", "--history"]), 2)
            self.assertIn("full clone", errors.getvalue())
            self.assertIn("git fetch --unshallow", errors.getvalue())
            self.assertNotIn(str(clone), errors.getvalue())

    def test_commit_and_annotated_tag_messages_and_tagger_identity_are_redacted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self.make_repository(root)
            token = "gh" + "p_" + "C" * 24
            email = "fixture" + chr(64) + "example.org"
            run("commit", "--allow-empty", "-qm", token)
            run("-c", "user.email=" + email, "-c", "user.name=PrivateFixtureName", "tag", "-a", "fixture-tag", "-m", "pass" + "word=synthetic-private-value")
            found = [item for name, data, revision in preflight.history_files(root) for item in preflight.scan_bytes(name, data, revision, ("PrivateFixtureName",))]
            self.assertIn(("credential-token", "[commit-metadata].txt"), [(item.rule,item.path) for item in found])
            for rule in ("email", "blocked-term", "credential-assignment"):
                self.assertIn((rule, "[tag-metadata].txt"), [(item.rule,item.path) for item in found])
            report = json.dumps([preflight.asdict(item) for item in found])
            for value in (token, email, "PrivateFixtureName", "synthetic-private-value"):
                self.assertNotIn(value, report)

    def test_history_object_byte_and_git_output_budgets_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repository(root)
            for limit in ("MAX_HISTORY_OBJECTS", "MAX_HISTORY_BYTES", "MAX_GIT_OUTPUT"):
                with self.subTest(limit=limit), mock.patch.object(preflight, limit, 1), self.assertRaises(preflight.HistoryScanError):
                    list(preflight.history_files(root))

    def scan_history(self, root):
        return sorted((item.rule, item.path, item.revision) for name, data, revision in preflight.history_files(root) for item in preflight.scan_bytes(name, data, revision))

    def test_history_reads_objects_in_bounded_batches(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self.make_repository(root)
            for number in range(12):
                (root / f"note{number}.txt").write_text(f"line {number}\n" * 200)
                if number == 5:
                    (root / "secret.txt").write_text("gh" + "p_" + "D" * 24)
                run("add", ".")
                run("commit", "-qm", f"Fixture {number}")
            calls = []
            original = preflight.git
            def counting(root, *args, **options):
                calls.append(args)
                return original(root, *args, **options)
            with mock.patch.object(preflight, "git", side_effect=counting):
                expected = self.scan_history(root)
            self.assertIn("credential-token", [rule for rule, _, _ in expected])
            self.assertEqual(len(calls), 4)
            calls.clear()
            with mock.patch.object(preflight, "git", side_effect=counting), mock.patch.object(preflight, "MAX_GIT_OUTPUT", 8192):
                self.assertEqual(self.scan_history(root), expected)
            self.assertGreater(sum(args[:2] == ("cat-file", "--batch") for args in calls), 1)

    def test_history_paths_keep_unicode_line_separators(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self.make_repository(root)
            blob = run("hash-object", "-w", "--stdin", data=("gh" + "p_" + "E" * 24).encode()).decode().strip()
            name = "odd name\x1cfile.txt"
            tree = run("mktree", data=f"100644 blob {blob}\t{name}\n".encode()).decode().strip()
            commit = run("commit-tree", tree, "-p", "HEAD", "-m", "Fixture").decode().strip()
            run("update-ref", "refs/heads/odd", commit)
            self.assertIn(("credential-token", name, blob), self.scan_history(root))

    def test_incomplete_batch_output_fails_closed(self):
        oid = b"cd" * 20
        replies = {"rev-parse": b"false\n", "rev-list": oid + b" a.txt\n", "--batch-check": oid + b" blob 10\n", "--batch": oid + b" blob 10\nshort\n"}
        def fake_git(root, *args, deadline=None, input=None):
            return replies[args[1] if args[0] == "cat-file" else args[0]]
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(preflight, "git", side_effect=fake_git):
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(preflight.main([directory, "--history"]), 2)
                replies["--batch-check"] = oid + b" missing\n"
                self.assertEqual(preflight.main([directory, "--history"]), 2)
            self.assertNotIn("Traceback", errors.getvalue())

    def test_missing_promisor_object_cannot_run_a_remote_helper(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self.make_repository(root)
            oid = run("rev-parse", "HEAD:a.txt").decode().strip()
            missing = root / ".git/objects" / oid[:2] / oid[2:]
            self.assertTrue(missing.resolve().is_relative_to(root.resolve()))
            missing.chmod(0o600)
            missing.unlink()
            marker = root / "unexpected-helper"
            script = "__import__('pathlib').Path(" + repr(marker.as_posix()) + ").write_text('ran')"
            def escape(argument):
                return argument.replace("%", "%%").replace(" ", "% ")
            url = "ext::" + escape(Path(sys.executable).as_posix()) + " -c " + escape(script)
            run("config", "extensions.partialClone", "origin")
            run("config", "remote.origin.promisor", "true")
            run("config", "remote.origin.url", url)
            run("config", "protocol.ext.allow", "always")
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(preflight.main([str(root), "--tracked", "--history"]), 2)
            self.assertFalse(marker.exists())
            self.assertNotIn("Traceback", errors.getvalue())

    def test_binary_or_oversized_metadata_is_flagged(self):
        for path in ("[commit-metadata].txt", "[tag-metadata].txt"):
            self.assertEqual(preflight.scan_bytes(path, b"metadata\0binary")[0].rule, "unreadable-text")
            self.assertEqual(preflight.scan_bytes(path, b"x" * (preflight.MAX_BYTES + 1))[0].rule, "oversized-file")

    def test_bounded_field_names_cover_normal_forms_without_matching_partial_tails(self):
        value = '"synthetic-private-value"'
        for name in ("clientApiKey", "service-api-key", "AUTH_TOKEN", "db_password", "my_secret", "credentials", "x" * 123 + "token"):
            with self.subTest(name_length=len(name)):
                self.assertIn("credential-assignment", [item.rule for item in preflight.scan_bytes("a.json", (name + "=" + value).encode())])
        for name in ("x" * 124 + "token", "token" * 30, "\u00e9token", "token\u00e9"):
            with self.subTest(name_length=len(name)):
                self.assertNotIn("credential-assignment", [item.rule for item in preflight.scan_bytes("a.json", (name + "=" + value).encode())])

    def test_two_mebibytes_of_repeated_keywords_have_bounded_scan_time(self):
        script = "import preflight; data=(b'token' * (preflight.MAX_BYTES // 5 + 1))[:preflight.MAX_BYTES]; assert preflight.scan_bytes('long.txt', data) == []"
        result = subprocess.run([sys.executable, "-c", script], cwd=Path(__file__).resolve().parents[1], capture_output=True, timeout=12)
        self.assertEqual(result.returncode, 0)

    def test_repeated_incomplete_fallback_calls_have_bounded_scan_time(self):
        script = "import preflight; unit=b'token = os.getenv('; data=(unit * (preflight.MAX_BYTES // len(unit) + 1))[:preflight.MAX_BYTES]; assert preflight.scan_bytes('long.txt', data) == []"
        result = subprocess.run([sys.executable, "-c", script], cwd=Path(__file__).resolve().parents[1], capture_output=True, timeout=12)
        self.assertEqual(result.returncode, 0)

    def test_many_blank_lines_have_bounded_scan_time(self):
        script = "import preflight; assert preflight.scan_bytes('long.txt', b' \\n' * (preflight.MAX_BYTES // 2)) == []"
        result = subprocess.run([sys.executable, "-c", script], cwd=Path(__file__).resolve().parents[1], capture_output=True, timeout=12)
        self.assertEqual(result.returncode, 0)

    def test_plain_environment_assignments_are_line_scoped_and_support_crlf(self):
        self.assertTrue(preflight.scan_bytes("a.txt", ("pass" + "word=synthetic-private-value\r\n").encode()))
        self.assertFalse(preflight.scan_bytes("a.txt", ("pass" + "word\n=synthetic-private-value").encode()))

    def test_blocked_terms_are_folded_once_with_existing_fingerprints_preserved(self):
        class CountedTerm(str):
            calls = 0
            def casefold(self):
                self.calls += 1
                return super().casefold()
        term = CountedTerm("MiXeDMarker")
        found = preflight.scan_bytes("a.txt", b"mixedmarker\nMIXEDMARKER\nMixedMarker", terms=(term,))
        self.assertEqual(term.calls, 1)
        self.assertEqual([item.line for item in found], [1, 2, 3])
        self.assertTrue(all(item.fingerprint == preflight.finding("blocked-term", "a.txt", item.line, "mixedmarker").fingerprint for item in found))
        self.assertNotIn(str(term), json.dumps([preflight.asdict(item) for item in found]))

    def test_invalid_config_shapes_and_duplicate_fields_fail_without_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.json"
            cases = [json.dumps(value) for value in ([], None, 1, "text", {"unknown": True})]
            cases += ['{"allow": [], "allow": []}', "[" * 4000 + "]" * 4000]
            for raw in cases:
                with self.subTest(raw_type=raw[:12]):
                    path.write_text(raw, encoding="utf-8")
                    errors = io.StringIO()
                    with contextlib.redirect_stderr(errors):
                        self.assertEqual(preflight.main([directory, "--config", str(path)]), 2)
                    self.assertNotIn("Traceback", errors.getvalue())
                    self.assertNotIn(str(path), errors.getvalue())

    def test_config_limits_are_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.json"
            for data in ({"blocked_terms": ["fixture"] * (preflight.MAX_TERMS + 1)}, {"allow": [{}] * (preflight.MAX_EXCEPTIONS + 1)}):
                path.write_text(json.dumps(data))
                with self.assertRaises(ValueError):
                    preflight.load_config(path)
            path.write_bytes(b" " * (preflight.MAX_BYTES + 1))
            with self.assertRaises(ValueError):
                preflight.load_config(path)

    def test_assignment_line_numbers_preserve_multiline_boundaries(self):
        data = ('heading\npass' + 'word = (\n "fixture-private-value"\n)\n\napi_' + 'key = "second-private-value"\n').encode()
        found = [item.line for item in preflight.scan_bytes("file.py", data) if item.rule == "credential-assignment"]
        self.assertEqual(found, [2, 6])
    def test_email_after_a_long_separator_or_artifact_prefix_is_detected(self):
        suffix = "ops.team" + chr(64) + "example.org"
        for prefix in ("-" * 70, "build-artifact-v1.2.3-release-candidate-final-final-2-notify-"):
            with self.subTest(prefix=prefix[:10]):
                self.assertIn("email", [item.rule for item in preflight.scan_bytes("log.txt", (prefix + suffix).encode())])

    def test_long_hyphenated_input_has_bounded_scan_time(self):
        script = "import preflight; assert preflight.scan_bytes('long.txt', b'a-' * 1000000) == []"
        result = subprocess.run([sys.executable, "-c", script], cwd=Path(__file__).resolve().parents[1], capture_output=True, timeout=8)
        self.assertEqual(result.returncode, 0)

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

    def test_skipped_directories_are_not_traversed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for folder in ("node_modules/pkg/lib", ".git/objects", "src"):
                (root / folder).mkdir(parents=True)
            (root / "node_modules/pkg/lib/index.js").write_text("x")
            (root / "src/app.py").write_text("x")
            visited = []
            real_scandir = os.scandir
            def recording(path):
                visited.append(Path(path))
                return real_scandir(path)
            with mock.patch.object(os, "scandir", side_effect=recording):
                self.assertEqual([item[0] for item in preflight.current_files(root, False)], ["src/app.py"])
            self.assertEqual(sorted(path.relative_to(root).as_posix() for path in visited), [".", "src"])

    def test_directory_reparse_points_are_not_traversed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for folder in ("linked", "plain"):
                (root / folder).mkdir()
                (root / folder / "a.txt").write_text("x")
            real_lstat, real_scandir = os.lstat, os.scandir
            def reparse(path, *args, **kwargs):
                if Path(path).name == "linked":
                    return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_file_attributes=stat.FILE_ATTRIBUTE_DIRECTORY | stat.FILE_ATTRIBUTE_REPARSE_POINT, st_reparse_tag=0xA0000003)
                return real_lstat(path, *args, **kwargs)
            visited = []
            def recording(path):
                visited.append(Path(path).name)
                return real_scandir(path)
            with mock.patch.object(os, "lstat", side_effect=reparse), mock.patch.object(os, "scandir", side_effect=recording):
                self.assertEqual([item[0] for item in preflight.current_files(root, False)], ["plain/a.txt"])
            self.assertNotIn("linked", visited)

    def test_unknown_directory_reparse_points_are_incomplete_instead_of_silently_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "cloud").mkdir()
            (Path(directory) / "cloud/source.txt").write_text("fixture")
            real_lstat = os.lstat
            def placeholder(path, *args, **kwargs):
                if Path(path).name == "cloud":
                    return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_file_attributes=stat.FILE_ATTRIBUTE_DIRECTORY | stat.FILE_ATTRIBUTE_REPARSE_POINT, st_reparse_tag=0x9000001A)
                return real_lstat(path, *args, **kwargs)
            with mock.patch.object(os, "lstat", side_effect=placeholder), contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(preflight.main([directory]), 2)

    def test_unreadable_link_attributes_make_the_scan_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "child").mkdir()
            real_lstat = os.lstat
            def denied(path, *args, **kwargs):
                if Path(path).name == "child":
                    raise PermissionError(13, "denied")
                return real_lstat(path, *args, **kwargs)
            with mock.patch.object(os, "lstat", side_effect=denied), contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(preflight.main([directory]), 2)

    def test_unreadable_directory_makes_the_scan_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "locked").mkdir()
            (root / "locked/config.txt").write_text("pass" + "word = 'synthetic-private-value'")
            real_scandir = os.scandir
            def denied(path):
                if Path(path).name == "locked":
                    raise PermissionError(13, "denied")
                return real_scandir(path)
            errors = io.StringIO()
            with mock.patch.object(os, "scandir", side_effect=denied), contextlib.redirect_stderr(errors), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(preflight.main([directory]), 2)
            self.assertNotIn("synthetic-private-value", errors.getvalue())

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

    def test_replacement_refs_cannot_hide_original_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def run(*args, data=None):
                return subprocess.check_output(["git", "-C", directory, *args], input=data, stderr=subprocess.DEVNULL)
            run("init", "-q")
            run("config", "user.name", "Fixture")
            run("config", "user.email", "")
            path = root / "fixture.txt"
            path.write_text("gh" + "p_" + "A" * 24)
            run("add", ".")
            run("commit", "-qm", "First fixture")
            original = run("rev-parse", "HEAD").decode().strip()
            path.write_text("clean")
            run("add", ".")
            run("commit", "-qm", "Clean tree")
            tree = run("rev-parse", "HEAD^{tree}").decode().strip()
            replacement = run("commit-tree", tree, data=b"Clean replacement\n").decode().strip()
            run("replace", original, replacement)
            found = [item for name, data, revision in preflight.history_files(root) for item in preflight.scan_bytes(name, data, revision)]
            self.assertIn("credential-token", [item.rule for item in found])


if __name__ == "__main__":
    unittest.main()
