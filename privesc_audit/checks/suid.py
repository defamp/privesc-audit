"""Audit SUID/SGID binaries.

A SUID/SGID bit on a binary that can run commands, spawn a shell, or read/write
arbitrary files lets any local user act with the file owner's (often root)
privileges. This check lists such binaries and flags the ones known to be
dangerous when privileged, with remediation guidance.
"""

from __future__ import annotations

import os
from typing import List

from ..models import Finding, Severity
from ..gtfobins import risk_note, gtfobins_url

REF = "https://attack.mitre.org/techniques/T1548/001/"


def analyze_suid(paths: List[str], mode: str = "suid") -> List[Finding]:
    """Turn a list of SUID (or SGID) binary paths into findings.

    ``paths`` is collected read-only by the scanner (e.g. ``find / -perm -4000``).
    """
    findings: List[Finding] = []
    bit = "SUID" if mode == "suid" else "SGID"
    for path in sorted(set(p for p in paths if p.strip())):
        name = os.path.basename(path.strip())
        note = risk_note(name)
        if note:
            findings.append(
                Finding(
                    check="suid",
                    title=f"{bit} binary known to enable privilege escalation: {name}",
                    severity=Severity.HIGH,
                    detail=(
                        f"'{path}' carries the {bit} bit and '{name}' is known to be "
                        f"abusable for privilege escalation when privileged ({note})."
                    ),
                    remediation=(
                        f"Confirm the {bit} bit is actually required. If not, remove it "
                        f"with 'chmod -s {path}'. If it is required, restrict access to the "
                        f"binary and monitor its use."
                    ),
                    evidence=path,
                    mitre=["T1548.001"],
                    references=[REF, gtfobins_url(name)],
                )
            )
        else:
            findings.append(
                Finding(
                    check="suid",
                    title=f"{bit} binary present: {name}",
                    severity=Severity.INFO,
                    detail=f"'{path}' carries the {bit} bit. Not a known high-risk binary, but worth inventorying.",
                    remediation=f"Verify the {bit} bit is needed; remove it with 'chmod -s {path}' if not.",
                    evidence=path,
                    mitre=["T1548.001"],
                    references=[REF],
                )
            )
    return findings
