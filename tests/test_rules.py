import json
import unittest
from pathlib import Path

from alg_audit.jwk import parse_jwks
from alg_audit.jwt import decode, encode_segment
from alg_audit.rules import RANK, audit, audit_keys, audit_token

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"


def load_jwks(name):
    payload = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return parse_jwks(payload, source=name)


def token_from(header: dict, payload: dict) -> str:
    return f"{encode_segment(header)}.{encode_segment(payload)}."


GOOD_HEADER = {"alg": "RS256", "typ": "JWT", "kid": "k-2026-01"}
GOOD_CLAIMS = {
    "sub": "alice", "iss": "https://issuer.example", "aud": "api.example",
    "iat": 1_800_000_000, "exp": 1_800_003_600,
}
NOW = 1_800_000_100


def ids(findings):
    return {finding.id for finding in findings}


class JwksRuleTests(unittest.TestCase):
    def test_weak_fixture_fires_expected_rules(self):
        report = audit(jwks=load_jwks("jwks_weak.json"))
        found = ids(report.findings)
        self.assertEqual(
            found,
            {"JOSE003", "JOSE005", "JOSE007", "JOSE008", "JOSE011"},
        )

    def test_good_fixture_is_clean(self):
        report = audit(jwks=load_jwks("jwks_good.json"))
        self.assertEqual(report.findings, [])
        self.assertEqual(report.verdict, "PASS")

    def test_published_oct_key_is_critical(self):
        report = audit(jwks=load_jwks("jwks_weak.json"))
        finding = next(f for f in report.findings if f.id == "JOSE005")
        self.assertEqual(finding.severity, "critical")

    def test_duplicate_kid_is_high(self):
        report = audit(jwks=load_jwks("jwks_weak.json"))
        finding = next(f for f in report.findings if f.id == "JOSE011")
        self.assertEqual(finding.severity, "high")
        self.assertIn("rsa-1", finding.title)

    def test_1024_bit_key_is_high(self):
        report = audit(jwks=load_jwks("jwks_weak.json"))
        finding = next(f for f in report.findings if f.id == "JOSE007")
        self.assertEqual(finding.severity, "high")
        self.assertIn("1024", finding.title)

    def test_sub_1024_bit_key_is_critical(self):
        import base64

        raw = bytes([0x80]) + b"\x00" * 63  # 512-bit modulus
        n = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        jwks = parse_jwks([{
            "kty": "RSA", "kid": "tiny", "alg": "RS256",
            "n": n, "e": "AQAB",
        }])
        finding = next(f for f in audit_keys(jwks) if f.id == "JOSE006")
        self.assertEqual(finding.severity, "critical")

    def test_empty_key_set(self):
        report = audit(jwks=parse_jwks({"keys": []}))
        self.assertEqual(ids(report.findings), {"JOSE001"})

    def test_unparseable_key(self):
        jwks = parse_jwks([{"kty": "RSA", "kid": "broken"}])
        self.assertIn("JOSE002", ids(audit_keys(jwks)))

    def test_non_signing_use(self):
        jwks = parse_jwks([{
            "kty": "RSA", "kid": "enc", "use": "enc",
            "n": "AQAB", "e": "AQAB",
        }])
        self.assertIn("JOSE004", ids(audit_keys(jwks)))

    def test_deprecated_ec_curve(self):
        jwks = parse_jwks([{"kty": "EC", "kid": "old", "crv": "P-192"}])
        self.assertIn("JOSE009", ids(audit_keys(jwks)))

    def test_unsupported_key_type(self):
        jwks = parse_jwks([{"kty": "DSA", "kid": "dsa"}])
        self.assertIn("JOSE010", ids(audit_keys(jwks)))

    def test_verdict_fails_on_high(self):
        report = audit(jwks=load_jwks("jwks_weak.json"))
        self.assertEqual(report.verdict, "FAIL")
        self.assertEqual(report.worst, "critical")


class TokenRuleTests(unittest.TestCase):
    def test_clean_token_against_matching_jwks(self):
        jwks = load_jwks("jwks_good.json")
        token = decode(token_from(GOOD_HEADER, GOOD_CLAIMS))
        self.assertEqual(audit_token(token, jwks, now=NOW), [])

    def test_missing_alg(self):
        token = decode(token_from({"typ": "JWT"}, GOOD_CLAIMS))
        self.assertIn("JWT001", ids(audit_token(token, None, now=NOW)))

    def test_alg_none(self):
        token = decode(token_from({"alg": "none"}, GOOD_CLAIMS))
        finding = next(f for f in audit_token(token, None, now=NOW)
                       if f.id == "JWT002")
        self.assertEqual(finding.severity, "critical")

    def test_hs256_against_rsa_set_is_critical(self):
        token = decode(token_from({"alg": "HS256", "kid": "k-2026-01"},
                                  GOOD_CLAIMS))
        findings = audit_token(token, load_jwks("jwks_good.json"), now=NOW)
        self.assertIn("JWT003", ids(findings))
        self.assertEqual(
            next(f for f in findings if f.id == "JWT003").severity, "critical")

    def test_algorithm_not_in_key_set(self):
        token = decode(token_from({"alg": "ES256", "kid": "k-2026-01"},
                                  GOOD_CLAIMS))
        self.assertIn("JWT004", ids(audit_token(
            token, load_jwks("jwks_good.json"), now=NOW)))

    def test_missing_kid(self):
        header = dict(GOOD_HEADER)
        header.pop("kid")
        token = decode(token_from(header, GOOD_CLAIMS))
        self.assertIn("JWT005", ids(audit_token(
            token, load_jwks("jwks_good.json"), now=NOW)))

    def test_unknown_kid(self):
        header = dict(GOOD_HEADER, kid="ghost")
        token = decode(token_from(header, GOOD_CLAIMS))
        self.assertIn("JWT006", ids(audit_token(
            token, load_jwks("jwks_good.json"), now=NOW)))

    def test_kid_alg_mismatch(self):
        header = dict(GOOD_HEADER, alg="RS512")
        token = decode(token_from(header, GOOD_CLAIMS))
        findings = audit_token(token, load_jwks("jwks_good.json"), now=NOW)
        self.assertIn("JWT007", ids(findings))

    def test_wrong_key_type_for_kid(self):
        # The weak set resolves rsa-1 to an RSA key, so an HS256 token with
        # that kid cannot be verified by it.
        token = decode(token_from({"alg": "HS256", "kid": "rsa-1"},
                                  GOOD_CLAIMS))
        findings = audit_token(token, load_jwks("jwks_weak.json"), now=NOW)
        self.assertIn("JWT008", ids(findings))

    def test_remote_and_embedded_key_headers(self):
        for name, ident in (("jku", "JWT009"), ("x5u", "JWT010"),
                            ("jwk", "JWT011"), ("crit", "JWT012")):
            header = dict(GOOD_HEADER, **{name: "https://evil.test/keys"})
            token = decode(token_from(header, GOOD_CLAIMS))
            found = ids(audit_token(token, load_jwks("jwks_good.json"),
                                    now=NOW))
            self.assertIn(ident, found, name)

    def test_unexpected_typ(self):
        header = dict(GOOD_HEADER, typ="JWE")
        token = decode(token_from(header, GOOD_CLAIMS))
        self.assertIn("JWT013", ids(audit_token(
            token, load_jwks("jwks_good.json"), now=NOW)))

    def test_missing_exp(self):
        claims = dict(GOOD_CLAIMS)
        claims.pop("exp")
        token = decode(token_from(GOOD_HEADER, claims))
        self.assertIn("JWT014", ids(audit_token(
            token, load_jwks("jwks_good.json"), now=NOW)))

    def test_exp_not_numeric(self):
        claims = dict(GOOD_CLAIMS, exp="tomorrow")
        token = decode(token_from(GOOD_HEADER, claims))
        self.assertIn("JWT015", ids(audit_token(
            token, load_jwks("jwks_good.json"), now=NOW)))

    def test_expired_token(self):
        claims = dict(GOOD_CLAIMS, exp=NOW - 10)
        token = decode(token_from(GOOD_HEADER, claims))
        self.assertIn("JWT016", ids(audit_token(
            token, load_jwks("jwks_good.json"), now=NOW)))

    def test_decade_long_expiry(self):
        claims = dict(GOOD_CLAIMS, exp=NOW + 20 * 365 * 24 * 3600)
        token = decode(token_from(GOOD_HEADER, claims))
        found = ids(audit_token(token, load_jwks("jwks_good.json"), now=NOW))
        self.assertIn("JWT017", found)
        self.assertIn("JWT018", found)

    def test_nbf_in_the_future(self):
        claims = dict(GOOD_CLAIMS, nbf=NOW + 600)
        token = decode(token_from(GOOD_HEADER, claims))
        self.assertIn("JWT019", ids(audit_token(
            token, load_jwks("jwks_good.json"), now=NOW)))

    def test_missing_registered_claims(self):
        claims = {"sub": "alice"}
        token = decode(token_from(GOOD_HEADER, claims))
        found = ids(audit_token(token, load_jwks("jwks_good.json"), now=NOW))
        for ident in ("JWT020", "JWT021", "JWT022"):
            self.assertIn(ident, found)

    def test_fixture_token_against_weak_set(self):
        raw = (FIXTURES / "token_hs256.txt").read_text(encoding="utf-8").strip()
        report = audit(jwks=load_jwks("jwks_weak.json"),
                       token=decode(raw), source="fixture")
        found = ids(report.findings)
        self.assertIn("JWT003", found)
        self.assertIn("JOSE005", found)
        self.assertEqual(report.verdict, "FAIL")
        self.assertEqual(report.counts["critical"] >= 2, True)


class ReportShapeTests(unittest.TestCase):
    def test_counts_and_order(self):
        report = audit(jwks=load_jwks("jwks_weak.json"))
        severities = [f.severity for f in report.sorted_findings()]
        ranks = [RANK[s] for s in severities]
        self.assertEqual(ranks, sorted(ranks))
        self.assertEqual(sum(report.counts.values()), len(report.findings))

    def test_as_dict_is_json_serialisable(self):
        report = audit(jwks=load_jwks("jwks_weak.json"))
        payload = report.as_dict()
        self.assertEqual(payload["verdict"], "FAIL")
        self.assertEqual(len(payload["keys"]), 5)
        json.dumps(payload)


if __name__ == "__main__":
    unittest.main()
