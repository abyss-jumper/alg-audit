import json
import unittest
from pathlib import Path

from alg_audit.jwk import parse_jwks
from alg_audit.jwt import decode, verify_hs256
from alg_audit.poc import (
    alg_none_token,
    first_rsa_pem,
    hs256_confusion_token,
    kid_traversal_header,
)

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"


def load(name):
    return parse_jwks(json.loads((FIXTURES / name).read_text(encoding="utf-8")))


CLAIMS = {"sub": "1234567890", "role": "user"}


class AlgNoneTests(unittest.TestCase):
    def test_three_segments_with_empty_signature(self):
        token = alg_none_token(CLAIMS)
        self.assertEqual(token.count("."), 2)
        self.assertTrue(token.endswith("."))
        decoded = decode(token)
        self.assertEqual(decoded.alg, "none")
        self.assertEqual(decoded.payload, CLAIMS)

    def test_header_extras(self):
        token = alg_none_token(CLAIMS, {"kid": "rsa-1"})
        self.assertEqual(decode(token).kid, "rsa-1")


class ConfusionTests(unittest.TestCase):
    def test_token_verifies_with_public_key_pem(self):
        jwks = load("jwks_good.json")
        forged = hs256_confusion_token(jwks, CLAIMS)
        self.assertIsNotNone(forged)
        token, pem = forged
        self.assertTrue(pem.startswith("-----BEGIN PUBLIC KEY-----"))
        self.assertTrue(verify_hs256(pem, token))

    def test_token_header_keeps_kid(self):
        jwks = load("jwks_good.json")
        token, _ = hs256_confusion_token(jwks, CLAIMS)
        decoded = decode(token)
        self.assertEqual(decoded.alg, "HS256")
        self.assertEqual(decoded.kid, "k-2026-01")

    def test_kid_selection(self):
        jwks = load("jwks_weak.json")
        token, _ = hs256_confusion_token(jwks, CLAIMS, kid="rsa-2")
        self.assertEqual(decode(token).kid, "rsa-2")

    def test_no_rsa_key_returns_none(self):
        jwks = parse_jwks([
            {"kty": "oct", "kid": "h", "k": "AAAA"},
        ])
        self.assertIsNone(hs256_confusion_token(jwks, CLAIMS))

    def test_first_rsa_pem(self):
        kid, pem = first_rsa_pem(load("jwks_good.json"))
        self.assertEqual(kid, "k-2026-01")
        self.assertIn("-----BEGIN PUBLIC KEY-----", pem)


class KidTraversalTests(unittest.TestCase):
    def test_default_kid_is_a_path(self):
        header = json.loads(kid_traversal_header())
        self.assertIn("..", header["kid"])
        self.assertEqual(header["alg"], "HS256")

    def test_custom_kid(self):
        header = json.loads(kid_traversal_header("https://evil.test/k"))
        self.assertEqual(header["kid"], "https://evil.test/k")


if __name__ == "__main__":
    unittest.main()
