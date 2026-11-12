#!/usr/bin/env python3
"""Generate deterministic JOSE fixtures.

Keys are synthetic: the modulus is a number with the right bit length, not a
product of two primes. That is fine for testing *size* checks and confusion
PoCs, and it means no real key material is ever committed.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "fixtures"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def modulus(bits: int, seed: bytes) -> int:
    raw = bytearray(hashlib.sha256(seed).digest() * ((bits // 8) // 32 + 1))
    raw = raw[: bits // 8]
    raw[0] |= 0x80
    raw[-1] |= 1
    return int.from_bytes(raw, "big")


def rsa_jwk(kid: str, bits: int, alg: str = "RS256") -> dict:
    n = modulus(bits, kid.encode())
    return {
        "kty": "RSA", "use": "sig", "alg": alg, "kid": kid,
        "n": b64url(n.to_bytes(bits // 8, "big")),
        "e": b64url((65537).to_bytes(3, "big")),
    }


def weak() -> dict:
    return {"keys": [
        rsa_jwk("rsa-1", 1024),
        rsa_jwk("rsa-1", 2048),          # duplicate kid
        rsa_jwk("rsa-2", 2048, "ES256"),  # alg/kty mismatch
        {
            "kty": "oct", "use": "sig", "alg": "HS256", "kid": "hmac-1",
            "k": b64url(b"not-a-real-secret-but-published"),
        },
        {
            "kty": "EC", "use": "sig", "alg": "ES256", "crv": "P-256",
            "x": b64url(bytes(range(32))), "y": b64url(bytes(range(32, 64))),
        },
    ]}


def good() -> dict:
    return {"keys": [
        rsa_jwk("k-2026-01", 2048),
    ]}


def hs256_token() -> str:
    header = {"alg": "HS256", "typ": "JWT", "kid": "rsa-1"}
    payload = {
        "sub": "1234567890",
        "iss": "https://issuer.example",
        "aud": "api.example",
        "iat": 1800000000,
        "exp": 1800003600,
    }

    def seg(value: dict) -> str:
        return b64url(json.dumps(value, separators=(",", ":")).encode())

    signing_input = f"{seg(header)}.{seg(payload)}"
    signature = hmac.new(b"demo-secret-not-a-real-key",
                         signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{b64url(signature)}"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "jwks_weak.json").write_text(json.dumps(weak(), indent=2) + "\n",
                                        encoding="utf-8")
    (OUT / "jwks_good.json").write_text(json.dumps(good(), indent=2) + "\n",
                                        encoding="utf-8")
    (OUT / "token_hs256.txt").write_text(hs256_token() + "\n", encoding="utf-8")
    print(f"wrote {OUT / 'jwks_weak.json'}")
    print(f"wrote {OUT / 'jwks_good.json'}")
    print(f"wrote {OUT / 'token_hs256.txt'}")


if __name__ == "__main__":
    main()
