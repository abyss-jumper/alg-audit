"""The rule set.

Severities are about *exploitability today*, not theoretical purity:

* critical — a working forgery path (alg none, published symmetric key, HS/RS
  confusion) or a factorable key;
* high — a missing control that makes a forgery path easier (remote key URLs,
  kid not resolvable, algorithm outside the key set);
* medium — hygiene that should be fixed but needs another bug to matter;
* low/info — best practice.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .jwk import Jwks, KeyInfo
from .jwt import DecodedToken

ORDER = ("critical", "high", "medium", "low", "info")
RANK = {severity: index for index, severity in enumerate(ORDER)}
DECADE = 10 * 365 * 24 * 3600


@dataclass(frozen=True)
class Finding:
    id: str
    severity: str
    title: str
    detail: str
    remediation: str = ""
    ref: str = ""

    def as_dict(self) -> dict:
        return {
            "id": self.id, "severity": self.severity, "title": self.title,
            "detail": self.detail, "remediation": self.remediation,
            "ref": self.ref,
        }


@dataclass
class Report:
    source: str = ""
    keys: list[KeyInfo] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    token_alg: str = ""
    token_kid: str = ""
    poc: dict = field(default_factory=dict)

    @property
    def counts(self) -> dict[str, int]:
        out = {severity: 0 for severity in ORDER}
        for finding in self.findings:
            out[finding.severity] = out.get(finding.severity, 0) + 1
        return out

    @property
    def worst(self) -> str:
        for severity in ORDER:
            if self.counts[severity]:
                return severity
        return "none"

    @property
    def verdict(self) -> str:
        return "FAIL" if self.counts["critical"] or self.counts["high"] else "PASS"

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (RANK.get(f.severity, 99), f.id))

    def as_dict(self) -> dict:
        return {
            "source": self.source,
            "verdict": self.verdict,
            "worst": self.worst,
            "counts": self.counts,
            "keys": [
                {"kid": k.kid, "kty": k.kty, "alg": k.alg, "bits": k.bits,
                 "curve": k.curve, "use": k.use, "error": k.error}
                for k in self.keys
            ],
            "token": {"alg": self.token_alg, "kid": self.token_kid},
            "findings": [f.as_dict() for f in self.sorted_findings()],
            "poc": self.poc,
        }


# ---------------------------------------------------------------------------
# JWKS rules
# ---------------------------------------------------------------------------
def audit_keys(jwks: Jwks) -> list[Finding]:
    out: list[Finding] = []
    if not jwks.keys:
        out.append(Finding(
            "JOSE001", "high", "JWKS contains no usable keys",
            "The key set is empty, so no token can be verified against it.",
            "Publish at least one signing key.",
            "RFC 7517 §5",
        ))
        return out

    kids: dict[str, list[KeyInfo]] = {}
    for key in jwks.keys:
        if key.error:
            out.append(Finding(
                "JOSE002", "medium", "Unparseable key in JWKS",
                f"{key.summary()}: {key.error}",
                "Remove or repair the key.",
                "RFC 7517 §4",
            ))
        if key.kid:
            kids.setdefault(key.kid, []).append(key)
        else:
            out.append(Finding(
                "JOSE003", "medium", "Key has no kid",
                f"{key.summary()} cannot be selected deterministically by tokens.",
                "Give every key a unique kid and reference it from the header.",
                "RFC 7515 §4.1.4",
            ))
        if key.use and key.use.lower() != "sig":
            out.append(Finding(
                "JOSE004", "low", f"Key use is '{key.use}', not 'sig'",
                f"{key.summary()} is published for a purpose other than signatures.",
                "Publish signing keys with use=sig.",
                "RFC 7517 §4.2",
            ))
        if key.kty == "oct":
            out.append(Finding(
                "JOSE005", "critical", "Symmetric key material published in JWKS",
                f"{key.summary()} exposes an HMAC secret to anyone who can read "
                "the key set. Tokens can be forged offline.",
                "Never publish oct keys. Use asymmetric signing keys.",
                "RFC 7517 §6.4",
            ))
        if key.kty == "RSA" and key.bits is not None:
            if key.bits < 1024:
                out.append(Finding(
                    "JOSE006", "critical", f"RSA key is {key.bits} bits",
                    "Below 1024 bits is factorable with modest resources.",
                    "Rotate to at least 2048 bits.",
                    "RFC 7518 §3.3",
                ))
            elif key.bits < 2048:
                out.append(Finding(
                    "JOSE007", "high", f"RSA key is {key.bits} bits",
                    "RFC 7518 requires a minimum of 2048 bits for RSA JWKs.",
                    "Rotate to 2048 bits or more.",
                    "RFC 7518 §3.3",
                ))
        if key.alg and key.bits is not None and not key.supports(key.alg):
            out.append(Finding(
                "JOSE008", "high", f"`alg` does not match key type ({key.summary()})",
                f"A token declaring {key.alg} cannot be verified with this key. "
                "Receivers may fall back to another algorithm.",
                "Align alg, kty and the actual key material.",
                "RFC 7517 §4.4",
            ))
        if key.kty == "EC" and key.curve in {"P-192", "secp192r1",
                                             "P-224", "secp224r1"}:
            out.append(Finding(
                "JOSE009", "medium", f"EC curve {key.curve} is deprecated",
                f"{key.summary()} uses a curve below the 256-bit baseline.",
                "Rotate to P-256 or stronger.",
                "RFC 7518 §3.4",
            ))
        if key.kty not in {"RSA", "EC", "OKP", "oct"}:
            out.append(Finding(
                "JOSE010", "medium", f"Unsupported key type: {key.kty}",
                f"{key.summary()} cannot be used by standard JOSE libraries.",
                "Publish RSA, EC or OKP keys.",
                "RFC 7518 §6",
            ))

    for kid, keys in kids.items():
        if len(keys) > 1:
            out.append(Finding(
                "JOSE011", "high", f"Duplicate kid '{kid}'",
                f"{len(keys)} keys share this kid. Depending on the library, "
                "one silently shadows the other — a classic algorithm-confusion "
                "setup.",
                "Make kids unique across the key set.",
                "RFC 7515 §4.1.4",
            ))
    return out


# ---------------------------------------------------------------------------
# Token rules
# ---------------------------------------------------------------------------
def audit_token(token: DecodedToken, jwks: Jwks | None,
                now: int | None = None) -> list[Finding]:
    out: list[Finding] = []
    now = int(time.time()) if now is None else now
    header, payload = token.header, token.payload
    alg = token.alg.upper()

    if not alg:
        out.append(Finding(
            "JWT001", "high", "Token header has no alg",
            "Libraries differ in what they do with a missing algorithm; some "
            "fall back to the key's default.",
            "Always emit an explicit alg.",
            "RFC 7515 §4.1.1",
        ))
    elif alg == "NONE":
        out.append(Finding(
            "JWT002", "critical", "Token uses alg=none",
            "The token is unsigned. Any receiver that accepts it will accept "
            "arbitrary claims.",
            "Reject alg=none at the verifier and never issue it.",
            "RFC 8725 §3.1",
        ))

    if jwks and jwks.keys:
        if alg.startswith("HS") and jwks.rsa_keys():
            out.append(Finding(
                "JWT003", "critical", "HS256 token against an RSA key set",
                "If the verifier selects the algorithm from the header, the "
                "RSA public key can be used as the HMAC secret. This is the "
                "classic algorithm-confusion forgery.",
                "Pin the expected algorithm per key; never let the token "
                "choose between HMAC and asymmetric verification.",
                "RFC 8725 §2.1",
            ))
        if alg not in {"NONE", ""} and not any(k.supports(alg) for k in jwks.keys):
            out.append(Finding(
                "JWT004", "high", f"Algorithm {alg} is not represented in the JWKS",
                "No published key can verify this token's algorithm.",
                "Publish a key for the algorithm you actually sign with, or "
                "stop issuing tokens with it.",
                "RFC 8725 §3.2",
            ))
        if not token.kid:
            out.append(Finding(
                "JWT005", "medium", "Token has no kid",
                "Without kid the verifier must try every key, which widens the "
                "confusion surface and hides rotation mistakes.",
                "Add a kid and keep it unique per key.",
                "RFC 7515 §4.1.4",
            ))
        else:
            matches = jwks.by_kid(token.kid)
            if not matches:
                out.append(Finding(
                    "JWT006", "medium", f"kid '{token.kid}' is not in the JWKS",
                    "Verification will fail unless the receiver has another "
                    "key source; if it silently falls back, that is a bug.",
                    "Publish the key or correct the kid.",
                    "RFC 7515 §4.1.4",
                ))
            else:
                key = matches[0]
                if key.alg and key.alg.upper() != alg:
                    out.append(Finding(
                        "JWT007", "medium",
                        f"kid '{token.kid}' resolves to a key declaring "
                        f"{key.alg} but the token says {alg}",
                        "A mismatch here is either stale key metadata or an "
                        "algorithm-substitution attempt.",
                        "Keep key.alg and the issued header in sync.",
                        "RFC 7517 §4.4",
                    ))
                if not key.supports(alg):
                    out.append(Finding(
                        "JWT008", "high",
                        f"kid '{token.kid}' cannot verify {alg}",
                        f"The key is {key.summary()}; it is the wrong type for "
                        "this token.",
                        "Reject the token and fix the issuer.",
                        "RFC 8725 §3.2",
                    ))

    for header_name, ident, severity, why in (
        ("jku", "JWT009", "high",
         "The token supplies a URL for the key set. A verifier that follows it "
         "fetches attacker-controlled keys (SSRF + forgery)."),
        ("x5u", "JWT010", "high",
         "The token supplies a certificate URL. Same trust problem as jku."),
        ("jwk", "JWT011", "high",
         "The token embeds its own verification key."),
        ("crit", "JWT012", "high",
         "A crit header forces the receiver to understand an extension or "
         "reject the token; it is frequently mishandled."),
    ):
        if header_name in header:
            out.append(Finding(
                ident, severity, f"Token header contains '{header_name}'",
                why,
                f"Reject tokens with '{header_name}' unless the issuer is "
                "explicitly trusted and allow-listed.",
                "RFC 8725 §3.5",
            ))

    typ = header.get("typ")
    if typ and str(typ).upper() not in {"JWT", "AT+JWT"}:
        out.append(Finding(
            "JWT013", "info", f"Unexpected typ '{typ}'",
            "Not a security issue by itself, but some middleware routes on typ.",
            "Use typ=JWT consistently.",
            "RFC 7519 §5.1",
        ))

    exp = payload.get("exp")
    if exp is None:
        out.append(Finding(
            "JWT014", "medium", "Token has no exp",
            "Without an expiry the token is valid until the key is rotated.",
            "Always set exp; keep access tokens short-lived.",
            "RFC 7519 §4.1.4",
        ))
    else:
        try:
            exp_int = int(exp)
        except (TypeError, ValueError):
            out.append(Finding(
                "JWT015", "medium", "exp is not a numeric date",
                f"Got {exp!r}; strict verifiers will reject the token.",
                "Emit exp as NumericDate seconds.",
                "RFC 7519 §2",
            ))
            exp_int = None
        if exp_int is not None:
            if exp_int <= now:
                out.append(Finding(
                    "JWT016", "info", "Token is expired",
                    "Expected for a historical sample, alarming for a freshly "
                    "issued one.",
                    "No action if this is a sample.",
                    "RFC 7519 §4.1.4",
                ))
            elif exp_int - now > DECADE:
                out.append(Finding(
                    "JWT017", "low", "Token expires more than 10 years from now",
                    "Long-lived signed tokens turn a single key compromise into "
                    "a decade of forgery.",
                    "Shorten exp and rely on refresh tokens.",
                    "RFC 8725 §3.10",
                ))
            iat = payload.get("iat")
            if isinstance(iat, (int, float)) and exp_int - int(iat) > DECADE:
                out.append(Finding(
                    "JWT018", "low", "Token lifetime exceeds 10 years",
                    f"exp - iat = {exp_int - int(iat)} seconds.",
                    "Reduce the lifetime.",
                    "RFC 8725 §3.10",
                ))

    nbf = payload.get("nbf")
    if isinstance(nbf, (int, float)) and nbf > now:
        out.append(Finding(
            "JWT019", "medium", "Token is not valid yet (nbf in the future)",
            f"nbf={nbf}, now={now}.",
            "Check clock skew between issuer and verifier.",
            "RFC 7519 §4.1.5",
        ))

    for claim, ident, title in (
        ("iat", "JWT020", "Token has no iat"),
        ("aud", "JWT021", "Token has no aud"),
        ("iss", "JWT022", "Token has no iss"),
    ):
        if claim not in payload:
            out.append(Finding(
                ident, "low", title,
                f"'{claim}' is absent; audience and issuer confusion attacks "
                "become easier.",
                f"Set {claim} explicitly and validate it at the receiver.",
                "RFC 7519 §4.1",
            ))

    return out


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def audit(jwks: Jwks | None = None, token: DecodedToken | None = None,
          source: str = "", now: int | None = None) -> Report:
    report = Report(source=source)
    if token is not None:
        report.token_alg = token.alg
        report.token_kid = token.kid
    if jwks is not None:
        report.keys = jwks.keys
        report.findings += audit_keys(jwks)
    if token is not None:
        report.findings += audit_token(token, jwks, now=now)
    return report
