"""Read-only collection of local system state, passed to the pure analyzers.

Every collector only *reads*: it runs non-mutating commands (find, getcap,
``sudo -n -l``) with timeouts, or checks access bits. Failures degrade quietly
so the tool is safe to run on any host, including as an unprivileged user.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import List

from .models import Finding
from .checks import suid as suid_check
from .checks import sudo as sudo_check
from .checks import capabilities as cap_check
from .checks import writable as writable_check

_TIMEOUT = 90


def _run(cmd: List[str], timeout: int = _TIMEOUT) -> str:
    """Run a read-only command, returning stdout (empty string on any failure)."""
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            text=True,
            check=False,
        )
        return proc.stdout or ""
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


def collect_suid() -> List[str]:
    out = _run(["find", "/", "-xdev", "-perm", "-4000", "-type", "f"])
    return [l for l in out.splitlines() if l.strip()]


def collect_sgid() -> List[str]:
    out = _run(["find", "/", "-xdev", "-perm", "-2000", "-type", "f"])
    return [l for l in out.splitlines() if l.strip()]


def collect_sudo() -> str:
    # -n: never prompt for a password, so this can't hang or lock an account.
    if not shutil.which("sudo"):
        return ""
    return _run(["sudo", "-n", "-l"], timeout=15)


def collect_capabilities() -> str:
    if not shutil.which("getcap"):
        return ""
    return _run(["getcap", "-r", "/"])


def collect_writable_sensitive() -> List[str]:
    return [p for p in writable_check.SENSITIVE_FILES if os.path.exists(p) and os.access(p, os.W_OK)]


def collect_writable_path_dirs() -> List[str]:
    out = []
    for d in os.environ.get("PATH", "").split(os.pathsep):
        d = d.strip()
        if d and os.path.isdir(d) and os.access(d, os.W_OK):
            out.append(d)
    return out


def collect_writable_cron() -> List[str]:
    candidates = [
        "/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
        "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron", "/var/spool/cron/crontabs",
    ]
    return [p for p in candidates if os.path.exists(p) and os.access(p, os.W_OK)]


def scan(checks=None) -> List[Finding]:
    """Run the selected checks against the live system and return all findings."""
    checks = set(checks or {"suid", "sudo", "capabilities", "writable"})
    findings: List[Finding] = []

    if "suid" in checks:
        findings += suid_check.analyze_suid(collect_suid(), mode="suid")
        findings += suid_check.analyze_suid(collect_sgid(), mode="sgid")
    if "sudo" in checks:
        findings += sudo_check.analyze_sudo(collect_sudo())
    if "capabilities" in checks:
        findings += cap_check.analyze_capabilities(collect_capabilities())
    if "writable" in checks:
        findings += writable_check.analyze_sensitive_writable(collect_writable_sensitive())
        findings += writable_check.analyze_writable_path_dirs(collect_writable_path_dirs())
        findings += writable_check.analyze_writable_cron(collect_writable_cron())

    findings.sort(key=lambda f: (-int(f.severity), f.check, f.title))
    return findings
