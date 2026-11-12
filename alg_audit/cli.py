"""alg-audit command line."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

from . import __version__
from .jwk import Jwks, JwksError, parse_jwks
from .jwt import TokenError, decode, verify_hs256
from .poc import alg_none_token, first_rsa_pem, hs256_confusion_token
from .report import to_json, to_text
from .rules import RANK, Report, audit

USER_AGENT = "alg-audit/0.1 (+https://github.com/)"


def fetch(source: str) -> object:
    if source.startswith(("http://", "https://")):
        request = urllib.request.Request(source, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=20) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8", "replace"))
    if source == "-":
        return json.loads(sys.stdin.read())
    return json.loads(Path(source).read_text(encoding="utf-8"))


def load_jwks(source: str) -> Jwks:
    return parse_jwks(fetch(source), source=source)


def load_token(arg: str) -> str:
    if arg == "-":
        return sys.stdin.read().strip()
    path = Path(arg)
    if path.exists() and path.is_file():
        return path.read_text(encoding="utf-8").strip()
    return arg


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="alg-audit",
        description="Audit JOSE key sets and JWTs for weak or confusion-prone "
                    "algorithm choices.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    jwks = sub.add_parser("jwks", help="audit a JWKS endpoint or file")
    jwks.add_argument("source", help="URL, file path, or - for stdin")

    token = sub.add_parser("token", help="audit one JWT, optionally against a JWKS")
    token.add_argument("token", help="JWT, file path, or - for stdin")
    token.add_argument("--jwks", help="JWKS URL or file for cross-checks")

    for parser in (jwks, token):
        parser.add_argument("--format", choices=("text", "json"), default="text")
        parser.add_argument("--out", help="write the report to a file")
        parser.add_argument("--fail-on", choices=("critical", "high", "medium", "low"),
                            help="exit 1 if a finding at this severity or worse exists")

    token.add_argument("--poc", action="store_true",
                       help="print alg:none and HS256-confusion forgeries")

    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def maybe_add_poc(report: Report, token, jwks: Jwks | None) -> None:
    report.poc["alg_none"] = alg_none_token(dict(token.payload))
    if jwks is not None:
        forged = hs256_confusion_token(jwks, dict(token.payload), token.kid)
        if forged is not None:
            forged_token, pem = forged
            report.poc["hs256_confusion"] = forged_token
            report.poc["hs256_confusion_verified"] = verify_hs256(pem, forged_token)
            material = first_rsa_pem(jwks)
            if material:
                report.poc["hmac_secret"] = material[1]


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):  # pragma: no cover
                pass

    jwks = None
    token = None
    source = ""

    try:
        if args.command == "jwks":
            jwks = load_jwks(args.source)
            source = args.source
        else:
            token = decode(load_token(args.token))
            source = args.token
            if args.jwks:
                jwks = load_jwks(args.jwks)
                source = f"{args.token} vs {args.jwks}"
    except (JwksError, TokenError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = audit(jwks=jwks, token=token, source=source)
    if args.command == "token" and args.poc and token is not None:
        maybe_add_poc(report, token, jwks)

    rendered = to_json(report) if args.format == "json" else to_text(report)
    if args.out:
        Path(args.out).write_text(rendered, encoding="utf-8")
        print(f"wrote {args.out} ({report.verdict})", file=sys.stderr)
    else:
        sys.stdout.write(rendered)

    if args.fail_on:
        threshold = RANK[args.fail_on]
        if any(RANK[f.severity] <= threshold for f in report.findings):
            return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
