"""Render findings as console text, JSON, or Markdown."""

from __future__ import annotations

import json
from collections import Counter
from typing import List

from .models import Finding, Severity

_COLORS = {
    Severity.CRITICAL: "\033[1;37;41m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[1;33m",
    Severity.LOW: "\033[1;36m",
    Severity.INFO: "\033[0;37m",
}
_RESET = "\033[0m"


def summary(findings: List[Finding]) -> Counter:
    return Counter(f.severity.label for f in findings)


def render_console(findings: List[Finding], use_color: bool = True) -> str:
    def c(sev, text):
        return f"{_COLORS[sev]}{text}{_RESET}" if use_color else text

    lines = ["privesc-audit — local privilege-escalation audit", "=" * 52, ""]
    if not findings:
        lines.append("No privilege-escalation findings. (Still verify manually.)")
        return "\n".join(lines)

    counts = summary(findings)
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    lines.append("Summary: " + "  ".join(
        c(s, f"{s.label}={counts.get(s.label, 0)}") for s in order if counts.get(s.label, 0)
    ))
    lines.append("")

    for f in findings:
        lines.append(c(f.severity, f"[{f.severity.label.upper()}] {f.title}"))
        lines.append(f"    {f.detail}")
        if f.evidence:
            lines.append(f"    evidence : {f.evidence}")
        lines.append(f"    fix      : {f.remediation}")
        if f.mitre:
            lines.append(f"    att&ck   : {', '.join(f.mitre)}")
        lines.append("")
    return "\n".join(lines)


def render_json(findings: List[Finding]) -> str:
    return json.dumps(
        {"summary": dict(summary(findings)), "findings": [f.to_dict() for f in findings]},
        indent=2,
    )


def render_markdown(findings: List[Finding]) -> str:
    out = ["# privesc-audit report", ""]
    counts = summary(findings)
    if counts:
        out.append("**Summary:** " + " · ".join(f"{k}: {v}" for k, v in counts.items()))
        out.append("")
    if not findings:
        out.append("_No privilege-escalation findings._")
        return "\n".join(out)
    out += ["| Severity | Finding | Fix |", "|---|---|---|"]
    for f in findings:
        fix = f.remediation.replace("|", "\\|")
        title = f.title.replace("|", "\\|")
        out.append(f"| {f.severity.label} | {title} | {fix} |")
    return "\n".join(out)
