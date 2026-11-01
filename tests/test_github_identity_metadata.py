"""Technical GitHub identities do not suppress real contacts or secret rules."""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import preflight


REVISION = "1" * 40


def privacy_address(login="Fixture-User", numeric=True):
    return ("12345+" if numeric else "") + login + chr(64) + "users.noreply.github.com"


def identity_header(address, kind="author", name="Fixture"):
    return f"{kind} {name} <{address}> 1 +0000\n"


class GithubIdentityMetadata(unittest.TestCase):
    def test_modern_legacy_and_web_privacy_identities_are_not_personal_contacts(self):
        for address in (privacy_address(), privacy_address(numeric=False), "noreply" + chr(64) + "github.com"):
            for kind in ("author", "committer", "tagger"):
                path = "[tag-metadata].txt" if kind == "tagger" else "[commit-metadata].txt"
                with self.subTest(kind=kind, modern="+" in address):
                    data = (identity_header(address, kind) + "\nordinary message\n").encode()
                    self.assertEqual(preflight.scan_bytes(path, data, REVISION), [])

    def test_actual_personal_and_lookalike_addresses_still_report(self):
        addresses = ["person" + chr(64) + "example.org", "person" + chr(64) + "github.com",
                     privacy_address() + ".example.org", "noreply" + chr(64) + "github.com.example.org",
                     privacy_address("not.a.github.login"), "noreply+private" + chr(64) + "github.com"]
        for address in addresses:
            with self.subTest(suffix=address.rsplit(chr(64), 1)[-1]):
                for kind in ("author", "committer", "tagger"):
                    path = "[tag-metadata].txt" if kind == "tagger" else "[commit-metadata].txt"
                    found = preflight.scan_bytes(path, identity_header(address, kind).encode(), REVISION)
                    self.assertIn("email", [item.rule for item in found])
                    self.assertNotIn(address, json.dumps([preflight.asdict(item) for item in found]))

    def test_source_current_metadata_and_commit_message_emails_are_still_scanned(self):
        address = privacy_address()
        header = identity_header(address)
        for path, revision, text in (("README.md", REVISION, header),
                                     ("[commit-metadata].txt", "", header),
                                     ("[commit-metadata].txt", REVISION, "tree " + "2" * 40 + "\n\n" + header),
                                     ("[tag-metadata].txt", REVISION, "object " + "2" * 40 + "\n\n" + identity_header(address, "tagger"))):
            with self.subTest(path=path, historical=bool(revision)):
                self.assertIn("email", [item.rule for item in preflight.scan_bytes(path, text.encode(), revision)])

    def test_an_email_in_the_display_name_is_not_the_technical_identity_field(self):
        personal = "person" + chr(64) + "example.org"
        data = identity_header(privacy_address(), name=personal).encode()
        findings = [item for item in preflight.scan_bytes("[commit-metadata].txt", data, REVISION) if item.rule == "email"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].fingerprint, preflight.finding("email", "unused", 1, personal).fingerprint)

    def test_a_long_identity_name_is_classified_once_without_dropping_its_contacts(self):
        personal = "person" + chr(64) + "example.org"
        data = identity_header(privacy_address(), name=" ".join([personal] * 2000)).encode()
        with mock.patch.object(preflight, "GIT_IDENTITY_HEADER", wraps=preflight.GIT_IDENTITY_HEADER) as classifier:
            findings = preflight.scan_bytes("[commit-metadata].txt", data, REVISION)
        # Findings with the same value/line deduplicate, but all email matches
        # must not cause a full rescan of the long header for each occurrence.
        self.assertEqual(len([item for item in findings if item.rule == "email"]), 1)
        classifier.fullmatch.assert_called_once()

    def test_privacy_identity_does_not_skip_credentials_terms_paths_or_style(self):
        token = "gh" + "p_" + "Q" * 24
        assignment = ("pass" + "word") + "=" + json.dumps("synthetic-private-value")
        private_path = "/" + "home/" + "synthetic-user"
        name = " ".join((token, assignment, private_path, "BlockedFixture", chr(0x2014)))
        data = identity_header(privacy_address(), name=name).encode()
        findings = preflight.scan_bytes("[commit-metadata].txt", data, REVISION, ("BlockedFixture",), check_style=True)
        rules = {item.rule for item in findings}
        self.assertNotIn("email", rules)
        self.assertTrue({"credential-token", "credential-assignment", "personal-path", "blocked-term", "em-dash"}.issubset(rules))

    def test_real_git_history_keeps_personal_contact_findings_and_redacts_values(self):
        with tempfile.TemporaryDirectory(prefix="preflight-technical-identity-") as directory:
            root = Path(directory)
            executable = shutil.which("git")
            self.assertIsNotNone(executable)
            env = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
            env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0"})

            def run(*args):
                return subprocess.run([executable, "-c", "core.hooksPath=" + os.devnull, "-c", "commit.gpgsign=false", "-C", str(root), *args],
                                      env=env, check=True, capture_output=True, timeout=10)

            run("init", "-q")
            run("config", "user.name", "Fixture")
            run("config", "user.email", privacy_address())
            (root / "a.txt").write_text("ordinary synthetic fixture\n")
            run("add", "a.txt")
            run("commit", "-qm", "Ordinary fixture")
            run("tag", "-a", "fixture", "-m", "Ordinary tag")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(preflight.main([str(root), "--tracked", "--history"]), 0)
            personal = "person" + chr(64) + "example.org"
            run("-c", "user.email=" + personal, "commit", "--allow-empty", "-qm", "Ordinary second fixture")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(preflight.main([str(root), "--tracked", "--history", "--json"]), 1)
            findings = json.loads(output.getvalue())["findings"]
            self.assertTrue(any(item["rule"] == "email" and item["path"] == "[commit-metadata].txt" for item in findings))
            self.assertNotIn(personal, output.getvalue())
            self.assertNotIn(privacy_address(), output.getvalue())


if __name__ == "__main__":
    unittest.main()
