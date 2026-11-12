# alg-audit

A cryptographic-agility linter for JOSE. Point it at a JWKS endpoint or a JWT
and it reports the algorithm choices that make **algorithm-confusion and
key-substitution attacks** possible — then prints a working forgery so you can
prove the finding instead of arguing about it.

No dependencies, no network required for the demo, and no private key material
anywhere in the repo.

```text
$ alg-audit jwks fixtures/jwks_weak.json
alg-audit · fixtures/jwks_weak.json
keys    RSA-1024 kid=rsa-1, RSA-2048 kid=rsa-1, RSA-2048 kid=rsa-2, oct-248 kid=hmac-1, EC-256
verdict FAIL — 1 critical, 3 high, 1 medium
========================================================================
[CRITICAL] JOSE005  Symmetric key material published in JWKS
           oct-248 kid=hmac-1 exposes an HMAC secret to anyone who can read the
           key set. Tokens can be forged offline.
           fix: Never publish oct keys. Use asymmetric signing keys.
           ref: RFC 7517 §6.4

[HIGH    ] JOSE007  RSA key is 1024 bits
           RFC 7518 requires a minimum of 2048 bits for RSA JWKs.
           fix: Rotate to 2048 bits or more.
           ref: RFC 7518 §3.3

[HIGH    ] JOSE008  `alg` does not match key type (RSA-2048 kid=rsa-2)
           A token declaring ES256 cannot be verified with this key. Receivers
           may fall back to another algorithm.
           fix: Align alg, kty and the actual key material.
           ref: RFC 7517 §4.4

[HIGH    ] JOSE011  Duplicate kid 'rsa-1'
           2 keys share this kid. Depending on the library, one silently
           shadows the other — a classic algorithm-confusion setup.
           fix: Make kids unique across the key set.
           ref: RFC 7515 §4.1.4

[MEDIUM  ] JOSE003  Key has no kid
           EC-256 cannot be selected deterministically by tokens.
           fix: Give every key a unique kid and reference it from the header.
           ref: RFC 7515 §4.1.4
```

Token mode cross-checks the header against the key set, then (with `--poc`)
prints an `alg:none` token and an HS256 token signed with the RSA **public
key PEM**:

```text
$ alg-audit token fixtures/token_hs256.txt --jwks fixtures/jwks_weak.json --poc
...
[CRITICAL] JWT003  HS256 token against an RSA key set
...
------------------------------------------------------------------------
proof of concept (do not use against systems you do not own)
  alg_none: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMj...
  hs256_confusion: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6...
  HS256 confusion signature verifies with the public key PEM: yes
```

## Install

```bash
git clone https://github.com/YOURNAME/alg-audit
cd alg-audit
python -m pip install -e .
alg-audit jwks fixtures/jwks_weak.json     # offline demo
```

Python 3.9+, standard library only.

## Usage

```bash
# audit a live JWKS endpoint
alg-audit jwks https://issuer.example/.well-known/jwks.json

# audit a saved key set
alg-audit jwks jwks.json --format json --out report.json

# CI gate: fail the job on high or critical findings
alg-audit jwks jwks.json --fail-on high

# audit a token, cross-checked against the issuer's key set
alg-audit token "$TOKEN" --jwks https://issuer.example/.well-known/jwks.json

# add the forgery PoCs
alg-audit token "$TOKEN" --jwks jwks.json --poc --format json

# stdin works too
curl -s https://issuer.example/.well-known/jwks.json | alg-audit jwks -
```

Exit codes: `0` audited, `1` a finding at or above `--fail-on`, `2` bad input
or transport failure.

`--fail-on` takes `critical`, `high`, `medium` or `low`; it fails when a finding
at that severity **or worse** exists.

## Rules

### Key set (JOSE)

| id | severity | condition |
|---|---|---|
| JOSE001 | high | key set contains no usable keys |
| JOSE002 | medium | key cannot be parsed (missing `n`/`e`, bad base64url) |
| JOSE003 | medium | key has no `kid`, so tokens cannot select it deterministically |
| JOSE004 | low | `use` is set to something other than `sig` |
| JOSE005 | **critical** | symmetric (`oct`) key material is published |
| JOSE006 | **critical** | RSA modulus below 1024 bits |
| JOSE007 | high | RSA modulus below 2048 bits (RFC 7518 minimum) |
| JOSE008 | high | `alg` is incompatible with `kty` (e.g. `ES256` on an RSA key) |
| JOSE009 | medium | EC curve below the 256-bit baseline (P-192/P-224) |
| JOSE010 | medium | unsupported `kty` |
| JOSE011 | high | duplicate `kid` within the set |

### Token (JWT)

| id | severity | condition |
|---|---|---|
| JWT001 | high | header has no `alg` |
| JWT002 | **critical** | `alg=none` |
| JWT003 | **critical** | HS* token presented against an RSA key set (classic confusion) |
| JWT004 | high | token's `alg` is not represented anywhere in the JWKS |
| JWT005 | medium | token has no `kid` |
| JWT006 | medium | `kid` is not present in the key set |
| JWT007 | medium | `kid` resolves to a key whose declared `alg` differs from the header |
| JWT008 | high | the selected key cannot verify the declared algorithm |
| JWT009 | high | header contains `jku` (remote key set) |
| JWT010 | high | header contains `x5u` (remote certificate) |
| JWT011 | high | header embeds its own `jwk` |
| JWT012 | high | header contains `crit` |
| JWT013 | info | `typ` is present but not `JWT`/`AT+JWT` |
| JWT014 | medium | no `exp` |
| JWT015 | medium | `exp` is not a NumericDate |
| JWT016 | info | token is already expired (expected for samples) |
| JWT017 | low | `exp` more than 10 years away |
| JWT018 | low | `exp - iat` exceeds 10 years |
| JWT019 | medium | `nbf` is in the future |
| JWT020 | low | no `iat` |
| JWT021 | low | no `aud` |
| JWT022 | low | no `iss` |

The verdict is **FAIL** when any critical or high finding exists, otherwise
**PASS**. Severities describe exploitability *today*, not theoretical purity.

## The PoCs

`--poc` renders two tokens built from the sample's own header and payload:

1. **`alg:none`** — three segments with an empty signature.
2. **HS256 confusion** — the same claims signed with HMAC-SHA256 using the
   **public key PEM** as the secret. The tool then verifies its own forgery with
   that same PEM and reports `yes`.

The second artifact is the interesting one: it is byte-for-byte what a library
that picks the verifier from the token's `alg` header would accept. The output
also shows `hmac_secret` so you can inspect exactly which key was abused.

These functions are deliberately small and offline. **Use them only against
systems you own or are authorised to test.** No attack traffic is generated.

## Fixtures

`fixtures/jwks_weak.json`, `fixtures/jwks_good.json` and
`fixtures/token_hs256.txt` are regenerated deterministically by:

```bash
python tools/make_fixtures.py
```

The RSA moduli are synthetic numbers with the right bit length — structurally
valid DER/JWK material, cryptographically worthless, and safely committable.
CI re-runs the generator and fails if the committed fixtures drift.

## Design notes

- **No verification of real signatures.** Auditing a public key set does not
  require the private key. The PoC verifies only its own HMAC construction.
- **`kid` is treated as data, never a path.** The traversal-style header is a
  documentation artifact (`poc.kid_traversal_header`), not an exploit.
- **Duplicates are called out separately** because "two keys with the same
  `kid`" is the setup that makes several library-specific confusion bugs work.
- **`--fail-on` is severity-ordered**, not exact-match, so `high` also catches
  criticals.

## Layout

```
alg_audit/
  jwk.py      base64url, JWK/JWKS parsing, RSA SPKI/PEM re-encoding
  jwt.py      segment decode, HMAC-SHA256 sign/verify, structural checks
  rules.py    JOSE001–JOSE011, JWT001–JWT022
  poc.py      alg:none and HS256-confusion forgery
  report.py   text / json
  cli.py      jwks and token subcommands
fixtures/     deterministic weak/good key sets and a sample token
tools/make_fixtures.py
tests/        80 unittest cases, no network
```

```bash
python -m unittest discover -s tests -v
python tools/make_fixtures.py
```

## What this does *not* do

- It does not validate a token's signature against a trusted key, replay state,
  issuer configuration, or revocation list.
- It cannot tell whether your verifier actually contains the confusion bug — it
  tells you the inputs that would trigger it.
- Key-size rules are policy (RFC 7518/8301), not a statement that a 1024-bit key
  has already been factored.
- It does not fetch `jku`/`x5u` URLs, by design.

## License

MIT. See `LICENSE`.
