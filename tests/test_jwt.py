import base64
import json
import unittest
from pathlib import Path

from alg_audit.jwt import TokenError, decode, sign_hs256, verify_hs256

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"


def fixture_token():
    return (FIXTURES / "token_hs256.txt").read_text(encoding="utf-8").strip()


class DecodeTests(unittest.TestCase):
    def test_decode_header_and_payload(self):
        token = decode(fixture_token())
        self.assertEqual(token.alg, "HS256")
        self.assertEqual(token.kid, "rsa-1")
        self.assertEqual(token.claim("sub"), "1234567890")

    def test_two_segments_rejected(self):
        with self.assertRaises(TokenError):
            decode("abc.def")

    def test_bad_json_rejected(self):
        with self.assertRaises(TokenError):
            decode("!!!.!!!.!!!")

    def test_non_object_rejected(self):
        segment = base64.urlsafe_b64encode(b"[1,2,3]").rstrip(b"=").decode()
        with self.assertRaises(TokenError):
            decode(f"{segment}.{segment}.")


class HmacTests(unittest.TestCase):
    def test_sign_and_verify(self):
        token = fixture_token()
        self.assertTrue(verify_hs256(b"demo-secret-not-a-real-key", token))
        # The fixture includes the signature over the exact segments, so this
        # only passes if signing and verification agree on encoding.

    def test_wrong_secret_fails(self):
        self.assertFalse(verify_hs256(b"wrong", fixture_token()))

    def test_tampered_payload_fails(self):
        token = fixture_token()
        header, payload, signature = token.split(".")
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        claims["sub"] = "admin"
        forged_payload = base64.urlsafe_b64encode(
            json.dumps(claims, separators=(",", ":")).encode()).rstrip(b"=").decode()
        tampered = f"{header}.{forged_payload}.{signature}"
        self.assertFalse(verify_hs256(b"demo-secret-not-a-real-key", tampered))

    def test_sign_hs256_is_deterministic(self):
        first = sign_hs256("secret", "a.b")
        second = sign_hs256("secret", "a.b")
        self.assertEqual(first, second)

    def test_verify_rejects_other_alg(self):
        from alg_audit.jwt import encode_segment

        header = encode_segment({"alg": "none", "typ": "JWT"})
        payload = encode_segment({"sub": "x"})
        self.assertFalse(verify_hs256(b"x", f"{header}.{payload}."))


if __name__ == "__main__":
    unittest.main()
