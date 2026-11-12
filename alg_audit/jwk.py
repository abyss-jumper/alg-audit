"""JWK / JWKS parsing and RSA public-key re-encoding.

The re-encoding matters: the HS256 confusion proof-of-concept signs with the
victim's *public key PEM* as the HMAC secret, which is exactly what a library
that picks the verifier from the token's `alg` header will do.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any


class JwksError(ValueError):
    pass


CURVE_BITS = {
    "P-256": 256, "P-384": 384, "P-521": 521, "secp256k1": 256,
    "Ed25519": 256, "Ed448": 456, "X25519": 253, "X448": 448,
}

KTY_ALGS = {
    "RSA": ("RS", "PS"),
    "EC": ("ES",),
    "OKP": ("EdDSA",),
    "oct": ("HS",),
}

# Canonical spelling for the registered key types (RFC 7518 §6).
KTY_CANONICAL = {name.lower(): name for name in KTY_ALGS}


def b64url_decode(value: str) -> bytes:
    value = value.strip()
    padding = "=" * (-len(value) % 4)
    try:
        return base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise JwksError(f"invalid base64url: {exc}") from exc


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _int_from_b64(value: str) -> int:
    return int.from_bytes(b64url_decode(value), "big")


# ---------------------------------------------------------------------------
# Minimal DER encoder (public keys only, nothing secret)
# ---------------------------------------------------------------------------
def _der_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(payload)) + payload


def _integer(value: int) -> bytes:
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _tlv(0x02, raw)


RSA_OID = bytes.fromhex("06092a864886f70d010101")


def rsa_spki_der(modulus: int, exponent: int) -> bytes:
    algorithm = _tlv(0x30, RSA_OID + b"\x05\x00")
    public_key = _tlv(0x30, _integer(modulus) + _integer(exponent))
    return _tlv(0x30, algorithm + _tlv(0x03, b"\x00" + public_key))


def rsa_public_pem(modulus: int, exponent: int) -> str:
    der = rsa_spki_der(modulus, exponent)
    body = base64.b64encode(der).decode()
    lines = "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
    return f"-----BEGIN PUBLIC KEY-----\n{lines}\n-----END PUBLIC KEY-----\n"


# ---------------------------------------------------------------------------
# Key model
# ---------------------------------------------------------------------------
@dataclass
class KeyInfo:
    kid: str
    kty: str
    alg: str = ""
    use: str = ""
    bits: int | None = None
    curve: str = ""
    error: str = ""
    jwk: dict = field(default_factory=dict)

    def algorithm_family(self) -> str:
        for family, prefixes in KTY_ALGS.items():
            if self.kty == family:
                return prefixes[0] if prefixes else family
        return self.kty

    def supports(self, alg: str) -> bool:
        alg = (alg or "").upper()
        if alg in {"NONE", ""}:
            return False
        expected = KTY_ALGS.get(self.kty, ())
        if self.kty == "OKP":
            return alg in {"EDDSA", "ED25519", "ED448"}
        return any(alg.startswith(prefix) for prefix in expected)

    def summary(self) -> str:
        bits = f"{self.bits}" if self.bits else "?"
        return f"{self.kty}-{bits}" + (f" kid={self.kid}" if self.kid else "")


@dataclass
class Jwks:
    keys: list[KeyInfo] = field(default_factory=list)
    source: str = ""

    def by_kid(self, kid: str) -> list[KeyInfo]:
        return [k for k in self.keys if k.kid and k.kid == kid]

    def algorithms(self) -> set[str]:
        return {k.alg for k in self.keys if k.alg}

    def rsa_keys(self) -> list[KeyInfo]:
        return [k for k in self.keys if k.kty == "RSA" and k.bits]


def _key_info(jwk: dict) -> KeyInfo:
    kid = str(jwk.get("kid", "") or "")
    raw_kty = str(jwk.get("kty", "") or "")
    kty = KTY_CANONICAL.get(raw_kty.lower(), raw_kty.upper())
    info = KeyInfo(kid=kid, kty=kty, alg=str(jwk.get("alg", "") or ""),
                   use=str(jwk.get("use", "") or ""), jwk=jwk)

    if kty == "RSA":
        if not jwk.get("n") or not jwk.get("e"):
            info.error = "RSA key missing n or e"
            return info
        try:
            info.bits = _int_from_b64(str(jwk["n"])).bit_length()
        except JwksError as exc:
            info.error = str(exc)
    elif kty == "EC":
        info.curve = str(jwk.get("crv", "") or "")
        info.bits = CURVE_BITS.get(info.curve)
        if info.bits is None:
            info.error = f"unknown EC curve: {info.curve or '(missing)'}"
    elif kty == "OKP":
        info.curve = str(jwk.get("crv", "") or "")
        info.bits = CURVE_BITS.get(info.curve)
        if info.bits is None:
            info.error = f"unknown OKP curve: {info.curve or '(missing)'}"
    elif kty == "oct":
        try:
            info.bits = len(b64url_decode(str(jwk.get("k", "")))) * 8
        except JwksError as exc:
            info.error = str(exc)
    else:
        info.error = f"unsupported kty: {kty or '(missing)'}"
    return info


def parse_jwks(payload: Any, source: str = "") -> Jwks:
    if isinstance(payload, dict):
        payload = payload.get("keys", [])
    if not isinstance(payload, list):
        raise JwksError("JWKS must be an object with a 'keys' array")
    keys = [_key_info(jwk) for jwk in payload if isinstance(jwk, dict)]
    return Jwks(keys=keys, source=source)


def rsa_material(jwk: dict) -> tuple[int, int] | None:
    """Return (modulus, exponent) for an RSA JWK, or None."""
    try:
        return _int_from_b64(str(jwk["n"])), _int_from_b64(str(jwk["e"]))
    except (KeyError, JwksError):
        return None
