"""Audit sudo rules exposed to the current user.

Parses the output of ``sudo -l`` (collected read-only by the scanner) and flags
rules that grant broad or password-less command execution, or allow binaries
that are known to break out to a root shell.
"""

from __future__ import annotations

import os
import re
from typing import List

from ..models import Finding, Severity
from ..gtfobins import risk_note, gtfobins_url

REF = "https://attack.mitre.org/techniques/T1548/003/"

# Matches lines like "(ALL : ALL) ALL" or "(root) NOPASSWD: /usr/bin/find arg"
_RULE_RE = re.compile(r"\(([^)]*)\)\s*((?:NOPASSWD:|SETENV:|PASSWD:)\s*)?(.+)$")


def analyze_sudo(sudo_l_output: str) -> List[Finding]:
    findings: List[Finding] = []
    if not sudo_l_output:
        return findings

    in_cmds = False
    for raw in sudo_l_output.splitlines():
        line = raw.strip()
        if "may run the following commands" in line:
            in_cmds = True
            continue
        if not in_cmds or not line.startswith("("):
            continue

        m = _RULE_RE.match(line)
        if not m:
            continue
        runas, tag, command = m.group(1), (m.group(2) or "").strip(), m.group(3).strip()
        nopasswd = "NOPASSWD" in tag

        # Full command access == effectively root.
        if command.split() and command.split()[0] == "ALL":
            findings.append(
                Finding(
                    check="sudo",
                    title="Sudo grants ALL commands" + (" without a password" if nopasswd else ""),
                    severity=Severity.CRITICAL if nopasswd else Severity.HIGH,
                    detail=f"Rule '({runas}) {tag}{command}' allows running any command via sudo.",
                    remediation="Restrict the sudoers entry to the specific commands required; avoid 'ALL' and NOPASSWD unless strictly necessary.",
                    evidence=line,
                    mitre=["T1548.003"],
                    references=[REF],
                )
            )
            continue

        # Specific command(s): flag known-risky binaries.
        first = os.path.basename(command.split()[0]) if command.split() else ""
        note = risk_note(first)
        if note:
            findings.append(
                Finding(
                    check="sudo",
                    title=f"Sudo allows a binary that can break out to a shell: {first}",
                    severity=Severity.HIGH if nopasswd else Severity.MEDIUM,
                    detail=f"Rule '({runas}) {tag}{command}' permits '{first}', which is known to run commands as the target user ({note}).",
                    remediation=f"Remove or replace this sudo rule. '{first}' can be used to execute arbitrary commands as ({runas}). Prefer a purpose-built wrapper.",
                    evidence=line,
                    mitre=["T1548.003"],
                    references=[REF, gtfobins_url(first)],
                )
            )
        elif nopasswd:
            findings.append(
                Finding(
                    check="sudo",
                    title=f"Password-less sudo rule: {first or command}",
                    severity=Severity.MEDIUM,
                    detail=f"Rule '({runas}) {tag}{command}' runs without a password prompt.",
                    remediation="Require a password (remove NOPASSWD) unless automation genuinely needs it; scope the command tightly.",
                    evidence=line,
                    mitre=["T1548.003"],
                    references=[REF],
                )
            )
    return findings
