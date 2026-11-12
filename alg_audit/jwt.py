"""JWT decoding, HMAC signing, and structural checks.

Nothing here verifies a *real* signature — that needs the issuer's private key
or a trusted key set. The helpers exist for the confusion proof-of-concept.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass

from .jwk import b64url_decode, b64url_encode


class TokenError(ValueError):
    pass


@dataclass
class DecodedToken:
    raw: str
    header: dict
    payload: dict
    signature: bytes
    signing_input: str

    @property
    def alg(self) -> str:
        return str(self.header.get("alg", "") or "")

    @property
    def kid(self) -> str:
        return str(self.header.get("kid", "") or "")

    def claim(self, name: str, default=None):
        return self.payload.get(name, default)


def decode(token: str) -> DecodedToken:
    token = token.strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise TokenError(f"expected 3 segments, found {len(parts)}")
    header_b64, payload_b64, signature_b64 = parts
    try:
        header = json.loads(b64url_decode(header_b64) or b"{}")
        payload = json.loads(b64url_decode(payload_b64) or b"{}")
    except (ValueError, json.JSONDecodeError) as exc:
        raise TokenError(f"invalid JSON segment: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise TokenError("header and payload must be JSON objects")
    return DecodedToken(
        raw=token, header=header, payload=payload,
        signature=b64url_decode(signature_b64) if signature_b64 else b"",
        signing_input=f"{header_b64}.{payload_b64}",
    )


def encode_segment(value: dict) -> str:
    return b64url_encode(json.dumps(value, separators=(",", ":")).encode())


def sign_hs256(secret: bytes | str, signing_input: str) -> str:
    if isinstance(secret, str):
        secret = secret.encode()
    digest = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
    return b64url_encode(digest)


def verify_hs256(secret: bytes | str, token: str) -> bool:
    """Verify the token's HS256 signature with the given secret."""
    try:
        decoded = decode(token)
    except TokenError:
        return False
    if decoded.alg.upper() != "HS256":
        return False
    expected = sign_hs256(secret, decoded.signing_input)
    return hmac.compare_digest(expected, b64url_encode(decoded.signature))


def _b64_to_bytes(value: str) -> bytes:
    return base64.b64decode(value + "=" * (-len(value) % 4))
