"""Audit NFS exports for the classic 'no_root_squash' privilege-escalation misconfig.

With no_root_squash, a user who can mount the export can create root-owned SUID
files on the server, escalating to root. This check reads /etc/exports and flags it.
"""

from __future__ import annotations

from typing import List

from ..models import Finding, Severity

REF = "https://attack.mitre.org/techniques/T1548/"


def analyze_nfs(exports_text: str) -> List[Finding]:
    findings: List[Finding] = []
    for raw in (exports_text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "no_root_squash" in line.lower():
            share = line.split()[0] if line.split() else line
            findings.append(
                Finding(
                    check="nfs",
                    title=f"NFS export with no_root_squash: {share}",
                    severity=Severity.HIGH,
                    detail=(
                        f"Export '{line}' uses no_root_squash. A client that can mount it "
                        f"can create root-owned SUID files on the server, escalating to root."
                    ),
                    remediation="Replace 'no_root_squash' with 'root_squash' in /etc/exports and run 'exportfs -ra'. Restrict the share to trusted hosts and prefer 'ro'.",
                    evidence=line,
                    mitre=["T1548"],
                    references=[REF, "https://wiki.archlinux.org/title/NFS"],
                )
            )
    return findings
