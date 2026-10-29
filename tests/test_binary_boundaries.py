import json
import unittest
from dataclasses import asdict

import preflight


class BinaryBoundaryTests(unittest.TestCase):
    def test_dense_binary_findings_count_newlines_with_linear_work(self):
        class CountedBytes(bytes):
            work = 0
            def count(self, value, start=0, end=None):
                end = len(self) if end is None else end
                self.work += end - start
                return super().count(value, start, end)
        token = ("AK" + "IA" + "A" * 16).encode()
        data = CountedBytes(b"\0\xff" + (token + b"\n") * 10000)
        findings = preflight.scan_bytes("dense.bin", data)
        self.assertEqual(len(findings), 10000)
        self.assertEqual((findings[0].line, findings[-1].line), (1, 10000))
        self.assertLessEqual(data.work, 2 * len(data))

    def test_nul_does_not_hide_a_token_in_text_or_binary_content(self):
        token = "gh" + "p_" + "A" * 36
        for content in (b"\0" + token.encode(), token.encode() + b"\n\0", b"\0\xff" + token.encode()):
            with self.subTest(content_type=content[:2]):
                findings = preflight.scan_bytes("capture.bin", content)
                self.assertTrue(any(item.rule == "credential-token" for item in findings))
                self.assertNotIn(token, json.dumps([asdict(item) for item in findings]))

    def test_nul_does_not_hide_private_key_header(self):
        marker = "-----BEGIN " + "PRIVATE KEY-----"
        found = preflight.scan_bytes("capture.bin", b"\0\xff" + marker.encode())
        self.assertEqual([item.rule for item in found], ["private-key"])

    def test_ordinary_binary_remains_quiet_and_binary_metadata_fails_closed(self):
        self.assertEqual(preflight.scan_bytes("image.png", b"\0\xff\x89PNG"), [])
        self.assertEqual(preflight.scan_bytes("[commit-metadata].txt", b"message\0")[0].rule, "unreadable-text")

    def test_shell_control_operators_do_not_hide_unquoted_literals(self):
        key, value = "API_" + "TOKEN", "owned-" + "synthetic-literal-4728"
        for separator in ("&&", "||", "&", ";"):
            for space in ("", " "):
                with self.subTest(separator=separator, space=space):
                    content = "export " + key + "=" + value + space + separator + " echo ready"
                    found = preflight.scan_bytes("setup.sh", content.encode())
                    self.assertEqual(found, [preflight.finding("credential-assignment", "setup.sh", 1, value)])

    def test_escaped_operators_and_expansions_keep_their_boundaries(self):
        key, value = "API_" + "TOKEN", "owned-" + "synthetic-literal-4728"
        escaped = value + r"\&tail"
        self.assertEqual(preflight.scan_bytes("setup.sh", (key + "=" + escaped + "&& echo ready").encode()),
                         [preflight.finding("credential-assignment", "setup.sh", 1, escaped)])
        for content in (key + "=$OTHER && echo ready", key + "=$(printenv OTHER) || exit 1",
                        key + "=your-token-here && echo ready"):
            self.assertEqual(preflight.scan_bytes("setup.sh", content.encode()), [])
        self.assertEqual(preflight.scan_bytes("source.py", (key + "=" + value + "&& ready").encode()), [])
