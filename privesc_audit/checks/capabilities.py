"""Audit Linux file capabilities.

Capabilities grant slices of root power to specific binaries. A handful of them
(for example cap_setuid or cap_dac_override) are enough to escalate to root if
set on a binary that can run code or read/write arbitrary files. This check
parses ``getcap -r /`` output and flags the dangerous ones.
"""

from __future__ import annotations

import os
import re
from typing import List

from ..models import Finding, Severity
from ..gtfobins import risk_note

REF = "https://attack.mitre.org/techniques/T1548/"

# Capability -> why it is dangerous on a code-running or file-touching binary.
DANGEROUS_CAPS = {
    "cap_setuid": "can change UID to 0 (root)",
    "cap_setgid": "can change GID to 0",
    "cap_dac_override": "bypasses file read/write permission checks",
    "cap_dac_read_search": "bypasses file read/directory search checks",
    "cap_sys_admin": "broad administrative powers",
    "cap_sys_ptrace": "can inspect/inject into other processes",
    "cap_sys_module": "can load kernel modules",
    "cap_chown": "can change file ownership",
    "cap_fowner": "bypasses ownership checks on files",
    "cap_sys_rawio": "raw I/O access to devices/memory",
}

_LINE_RE = re.compile(r"^(?P<path>\S+)\s*=?\s*(?P<caps>[a-z0-9_,+=]+ep?|[a-z0-9_,+=]+)\s*$", re.I)


def analyze_capabilities(getcap_output: str) -> List[Finding]:
    findings: List[Finding] = []
    for raw in (getcap_output or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        m = _LINE_RE.match(line)
        if not m:
            continue
        path, caps_raw = m.group("path"), m.group("caps").lower()
        name = os.path.basename(path)
        hits = [c for c in DANGEROUS_CAPS if c in caps_raw]
        if not hits:
            continue
        why = "; ".join(f"{c} ({DANGEROUS_CAPS[c]})" for c in hits)
        runs_code = risk_note(name) is not None
        sev = Severity.HIGH if runs_code else Severity.MEDIUM
        findings.append(
            Finding(
                check="capabilities",
                title=f"Dangerous capability on {name}: {', '.join(hits)}",
                severity=sev,
                detail=(
                    f"'{path}' has capability set '{caps_raw}'. Dangerous bits: {why}."
                    + (" This binary can also run code, compounding the risk." if runs_code else "")
                ),
                remediation=f"Remove the capability if not required: 'setcap -r {path}'. Grant the narrowest capability possible, and avoid putting powerful caps on interpreters or shells.",
                evidence=line,
                fix_command=f"setcap -r {path}",
                mitre=["T1548"],
                references=[REF],
            )
        )
    return findings
