import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from alg_audit.cli import main

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class JwksCommandTests(unittest.TestCase):
    def test_text_report_on_weak_set(self):
        code, out, _ = run(["jwks", str(FIXTURES / "jwks_weak.json")])
        self.assertEqual(code, 0)
        self.assertIn("verdict FAIL", out)
        self.assertIn("JOSE005", out)

    def test_json_report_on_good_set(self):
        code, out, _ = run(["jwks", str(FIXTURES / "jwks_good.json"),
                            "--format", "json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["verdict"], "PASS")
        self.assertEqual(payload["findings"], [])

    def test_fail_on_high(self):
        code, _, _ = run(["jwks", str(FIXTURES / "jwks_weak.json"),
                          "--fail-on", "high"])
        self.assertEqual(code, 1)

    def test_fail_on_passes_when_threshold_not_met(self):
        code, _, _ = run(["jwks", str(FIXTURES / "jwks_good.json"),
                          "--fail-on", "critical"])
        self.assertEqual(code, 0)

    def test_missing_file_is_error(self):
        code, _, err = run(["jwks", "does-not-exist.json"])
        self.assertEqual(code, 2)
        self.assertIn("error:", err)

    def test_invalid_json_is_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text("{not json", encoding="utf-8")
            code, _, err = run(["jwks", str(path)])
        self.assertEqual(code, 2)
        self.assertIn("error:", err)

    def test_out_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "report.json"
            code, _, err = run(["jwks", str(FIXTURES / "jwks_weak.json"),
                                "--format", "json", "--out", str(target)])
            self.assertEqual(code, 0)
            self.assertIn("wrote", err)
            self.assertEqual(json.loads(target.read_text(encoding="utf-8"))
                             ["verdict"], "FAIL")


class TokenCommandTests(unittest.TestCase):
    def test_token_alone_is_clean(self):
        code, out, _ = run(["token", str(FIXTURES / "token_hs256.txt"),
                            "--format", "json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["verdict"], "PASS")
        self.assertEqual(payload["token"]["alg"], "HS256")

    def test_token_against_weak_jwks_fails(self):
        code, out, _ = run([
            "token", str(FIXTURES / "token_hs256.txt"),
            "--jwks", str(FIXTURES / "jwks_weak.json"),
            "--format", "json",
        ])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["verdict"], "FAIL")
        ids = {finding["id"] for finding in payload["findings"]}
        self.assertIn("JWT003", ids)

    def test_poc_payload(self):
        code, out, _ = run([
            "token", str(FIXTURES / "token_hs256.txt"),
            "--jwks", str(FIXTURES / "jwks_good.json"),
            "--poc", "--format", "json",
        ])
        self.assertEqual(code, 0)
        poc = json.loads(out)["poc"]
        self.assertTrue(poc["hs256_confusion_verified"])
        self.assertIn("hs256_confusion", poc)
        self.assertTrue(poc["alg_none"].endswith("."))
        self.assertIn("BEGIN PUBLIC KEY", poc["hmac_secret"])

    def test_poc_text_mentions_verification(self):
        code, out, _ = run([
            "token", str(FIXTURES / "token_hs256.txt"),
            "--jwks", str(FIXTURES / "jwks_good.json"), "--poc",
        ])
        self.assertEqual(code, 0)
        self.assertIn("HS256 confusion signature verifies", out)

    def test_inline_token_argument(self):
        raw = (FIXTURES / "token_hs256.txt").read_text(encoding="utf-8").strip()
        code, out, _ = run(["token", raw, "--format", "json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["token"]["kid"], "rsa-1")

    def test_malformed_token_is_error(self):
        code, _, err = run(["token", "not.a.token"])
        self.assertEqual(code, 2)
        self.assertIn("error:", err)

    def test_fail_on_critical(self):
        code, _, _ = run([
            "token", str(FIXTURES / "token_hs256.txt"),
            "--jwks", str(FIXTURES / "jwks_weak.json"),
            "--fail-on", "critical",
        ])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
