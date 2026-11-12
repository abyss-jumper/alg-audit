import unittest
from pathlib import Path

from alg_audit.jwk import (
    JwksError,
    b64url_decode,
    b64url_encode,
    parse_jwks,
    rsa_material,
    rsa_public_pem,
    rsa_spki_der,
)

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"


def load(name):
    return parse_jwks(__import__("json").loads(
        (FIXTURES / name).read_text(encoding="utf-8")), source=name)


class Base64Tests(unittest.TestCase):
    def test_round_trip(self):
        data = bytes(range(32))
        self.assertEqual(b64url_decode(b64url_encode(data)), data)

    def test_padding_tolerated(self):
        self.assertEqual(b64url_decode("YQ"), b"a")

    def test_invalid_rejected(self):
        with self.assertRaises(JwksError):
            b64url_decode("!!!!")


class JwksTests(unittest.TestCase):
    def test_good_key_bits(self):
        jwks = load("jwks_good.json")
        self.assertEqual(len(jwks.keys), 1)
        self.assertEqual(jwks.keys[0].bits, 2048)
        self.assertEqual(jwks.keys[0].kid, "k-2026-01")

    def test_weak_set_shapes(self):
        jwks = load("jwks_weak.json")
        kinds = sorted(k.kty for k in jwks.keys)
        self.assertEqual(kinds, ["EC", "RSA", "RSA", "RSA", "oct"])

    def test_ec_curve_bits(self):
        jwks = load("jwks_weak.json")
        ec = next(k for k in jwks.keys if k.kty == "EC")
        self.assertEqual(ec.bits, 256)
        self.assertEqual(ec.curve, "P-256")

    def test_oct_key_bits(self):
        jwks = load("jwks_weak.json")
        oct_key = next(k for k in jwks.keys if k.kty == "oct")
        self.assertGreater(oct_key.bits, 0)

    def test_duplicate_kid_lookup(self):
        jwks = load("jwks_weak.json")
        self.assertEqual(len(jwks.by_kid("rsa-1")), 2)

    def test_empty_set_allowed(self):
        self.assertEqual(parse_jwks({"keys": []}).keys, [])

    def test_bad_payload(self):
        with self.assertRaises(JwksError):
            parse_jwks("nope")

    def test_missing_rsa_fields(self):
        jwks = parse_jwks([{"kty": "RSA", "kid": "x"}])
        self.assertTrue(jwks.keys[0].error)

    def test_unsupported_kty(self):
        jwks = parse_jwks([{"kty": "DSA", "kid": "x"}])
        self.assertIn("unsupported kty", jwks.keys[0].error)


class PemTests(unittest.TestCase):
    def test_spki_starts_with_sequence(self):
        der = rsa_spki_der(1 << 2047, 65537)
        self.assertEqual(der[0], 0x30)

    def test_pem_wrapping(self):
        pem = rsa_public_pem((1 << 2047) | 1, 65537)
        self.assertTrue(pem.startswith("-----BEGIN PUBLIC KEY-----"))
        self.assertTrue(pem.endswith("-----END PUBLIC KEY-----\n"))
        body = "".join(line for line in pem.splitlines()
                       if not line.startswith("-----"))
        self.assertEqual(b64url_decode(str(body).translate(
            str.maketrans("+/", "-_")))[0], 0x30)

    def test_rsa_material(self):
        jwk = load("jwks_good.json").keys[0].jwk
        material = rsa_material(jwk)
        self.assertIsNotNone(material)
        self.assertEqual(material[0].bit_length(), 2048)
        self.assertEqual(material[1], 65537)

    def test_rsa_material_missing(self):
        self.assertIsNone(rsa_material({"kty": "RSA"}))


if __name__ == "__main__":
    unittest.main()
