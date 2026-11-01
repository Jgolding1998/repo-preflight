"""Adversarial local Git metadata fixtures; no network or project code runs."""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import preflight


class LocalGitBoundaryTests(unittest.TestCase):
    def make_repository(self, root, text="ordinary fixture\n"):
        root.mkdir()
        executable = shutil.which("git")
        self.assertIsNotNone(executable)
        environment = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
        environment.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                            "GIT_TERMINAL_PROMPT": "0"})

        def run(*arguments):
            return subprocess.run([executable, "--no-pager", "-c", "core.hooksPath=" + os.devnull,
                "-c", "core.fsmonitor=false", "-c", "commit.gpgsign=false", "-C", str(root),
                *arguments], check=True, capture_output=True, env=environment, timeout=10).stdout

        run("init", "-q")
        run("config", "user.name", "Fixture")
        run("config", "user.email", "")
        (root / "a.txt").write_bytes(text.encode("utf-8"))
        (root / ".gitattributes").write_bytes(b"*.txt filter=fixture diff=fixture\n")
        run("add", ".")
        run("commit", "-qm", "Fixture")
        return run

    def test_included_local_config_cannot_run_helpers_hooks_or_filters(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "source with spaces"
            run = self.make_repository(root)
            marker = base / "unexpected-execution"
            helper = base / "helper.sh"
            helper.write_bytes(("#!/bin/sh\nprintf ran > '" + marker.as_posix() + "'\n").encode("utf-8"))
            helper.chmod(0o755)
            hooks = base / "hooks"
            hooks.mkdir()
            for name in ("pre-commit", "post-checkout", "post-index-change"):
                hook = hooks / name
                hook.write_bytes(helper.read_bytes())
                hook.chmod(0o755)
            included = base / "included.cfg"
            quoted = json.dumps(helper.as_posix())
            included.write_text(
                "[core]\nfsmonitor = " + quoted + "\npager = " + quoted
                + "\nhooksPath = " + json.dumps(hooks.as_posix())
                + "\nalternateRefsCommand = " + quoted
                + "\n[log]\nshowSignature = true\n[gpg]\nprogram = " + quoted
                + "\n[diff]\nexternal = " + quoted
                + "\n[filter \"fixture\"]\nclean = " + quoted + "\nsmudge = " + quoted + "\n",
                encoding="utf-8")
            run("config", "include.path", included.as_posix())
            index_before = (root / ".git/index").read_bytes()
            files = list(preflight.current_files(root, True))
            self.assertIn(("a.txt", b"ordinary fixture\n", ""), files)
            self.assertTrue(any(name == "a.txt" for name, _, _ in preflight.history_files(root)))
            self.assertFalse(marker.exists(), "Repository config triggered an external helper")
            self.assertEqual((root / ".git/index").read_bytes(), index_before)

    def test_reachable_alternate_objects_are_scanned_raw_and_remain_redacted(self):
        # A shared local object store is legitimate Git metadata. It is not a
        # command to enumerate the other repository's refs or run its helpers.
        value = "gh" + "p_" + "Q" * 36
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            donor, target = base / "donor", base / "shared"
            donor_run = self.make_repository(donor, value + "\n")
            target_run = self.make_repository(target)
            oid = donor_run("rev-parse", "HEAD").decode().strip()
            unrelated = "gh" + "p_" + "Z" * 36
            (donor / "a.txt").write_bytes((unrelated + "\n").encode())
            donor_run("add", "a.txt")
            donor_run("commit", "-qm", "Unreferenced donor-only fixture")
            (target / ".git/objects/info/alternates").write_bytes(
                ((donor / ".git/objects").as_posix() + "\n").encode("utf-8"))
            target_run("update-ref", "refs/heads/shared-fixture", oid)
            marker = base / "unexpected-alternate-command"
            helper = base / "alternate.sh"
            helper.write_bytes(("#!/bin/sh\nprintf ran > '" + marker.as_posix() + "'\n").encode("utf-8"))
            helper.chmod(0o755)
            target_run("config", "core.alternateRefsCommand", helper.as_posix())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = preflight.main([str(target), "--history", "--json"])
            report = output.getvalue()
            self.assertEqual(result, 1)
            findings = json.loads(report)["findings"]
            self.assertTrue(any(item["rule"] == "credential-token" and item["path"] == "a.txt"
                                for item in findings))
            self.assertNotIn(value, report)
            self.assertNotIn(preflight.finding("credential-token", "a.txt", 1, unrelated).fingerprint, report)
            self.assertNotIn(str(donor), report)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
