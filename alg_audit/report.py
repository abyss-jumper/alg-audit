"""Text and JSON rendering."""

from __future__ import annotations

import json

from .rules import Report

LABELS = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
          "low": "LOW", "info": "INFO"}


def to_json(report: Report) -> str:
    return json.dumps(report.as_dict(), indent=2, sort_keys=True)


def to_text(report: Report) -> str:
    lines = [f"alg-audit · {report.source or '(inline)'}"]
    if report.keys:
        lines.append("keys    " + ", ".join(k.summary() for k in report.keys))
    if report.token_alg:
        lines.append(f"token   alg={report.token_alg or '(missing)'} "
                     f"kid={report.token_kid or '(missing)'}")
    counts = report.counts
    summary = ", ".join(f"{counts[s]} {s}" for s in LABELS if counts[s])
    lines.append(f"verdict {report.verdict} — {summary or 'no findings'}")
    lines.append("=" * 72)

    if not report.findings:
        lines.append("Nothing to report.")
    for finding in report.sorted_findings():
        lines.append(f"[{LABELS.get(finding.severity, finding.severity):<8}] "
                     f"{finding.id}  {finding.title}")
        for chunk in _wrap(finding.detail, 68):
            lines.append(f"           {chunk}")
        if finding.remediation:
            for chunk in _wrap("fix: " + finding.remediation, 68):
                lines.append(f"           {chunk}")
        if finding.ref:
            lines.append(f"           ref: {finding.ref}")
        lines.append("")

    if report.poc:
        lines.append("-" * 72)
        lines.append("proof of concept (do not use against systems you do not own)")
        for name, value in report.poc.items():
            if isinstance(value, dict) or isinstance(value, bool):
                continue
            text = str(value)
            first = text.splitlines()[0] if text else ""
            lines.append(f"  {name}: {first[:100]}{'…' if len(first) > 100 else ''}")
        if "hs256_confusion_verified" in report.poc:
            lines.append("  HS256 confusion signature verifies with the public key PEM: "
                         + ("yes" if report.poc["hs256_confusion_verified"] else "no"))
    return "\n".join(lines).rstrip() + "\n"


def _wrap(text: str, width: int) -> list[str]:
    words, lines, current = text.split(), [], ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines or [""]
