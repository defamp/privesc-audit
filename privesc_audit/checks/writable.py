"""Audit writable files/directories that can lead to privilege escalation.

Covers three classic weaknesses:
  * sensitive system files writable by an unprivileged user,
  * writable directories that appear in $PATH (PATH hijacking),
  * writable cron files/directories (scheduled execution as another user).
All inputs are collected read-only by the scanner.
"""

from __future__ import annotations

from typing import List

from ..models import Finding, Severity

# Files whose writability by a non-root user is a direct escalation path.
SENSITIVE_FILES = {
    "/etc/passwd": ("add or alter accounts", Severity.CRITICAL, "T1548"),
    "/etc/shadow": ("set password hashes", Severity.CRITICAL, "T1003.008"),
    "/etc/sudoers": ("grant yourself sudo", Severity.CRITICAL, "T1548.003"),
    "/etc/group": ("add yourself to privileged groups", Severity.HIGH, "T1548"),
    "/etc/crontab": ("schedule a root job", Severity.HIGH, "T1053.003"),
    "/etc/ld.so.preload": ("inject a library into privileged processes", Severity.CRITICAL, "T1574.006"),
}


# Recommended mode when restoring a sensitive file.
_SAFE_MODE = {"/etc/shadow": "640", "/etc/sudoers": "440"}


def analyze_sensitive_writable(writable_paths: List[str]) -> List[Finding]:
    findings: List[Finding] = []
    for path in writable_paths:
        path = path.strip()
        meta = SENSITIVE_FILES.get(path)
        if not meta:
            continue
        impact, sev, tech = meta
        mode = _SAFE_MODE.get(path, "644")
        fix = f"chown root:root {path} && chmod {mode} {path}"
        findings.append(
            Finding(
                check="writable",
                title=f"Sensitive file is writable: {path}",
                severity=sev,
                detail=f"'{path}' is writable by the current user, which would let an attacker {impact}.",
                remediation=f"Restore safe ownership/permissions: {fix}",
                evidence=path,
                fix_command=fix,
                mitre=[tech],
                references=[f"https://attack.mitre.org/techniques/{tech.split('.')[0]}/"],
            )
        )
    return findings


def analyze_writable_path_dirs(dirs: List[str]) -> List[Finding]:
    """Directories that are both in $PATH and writable allow binary planting."""
    findings: List[Finding] = []
    for d in sorted(set(x.strip() for x in dirs if x.strip())):
        findings.append(
            Finding(
                check="writable",
                title=f"Writable directory in $PATH: {d}",
                severity=Severity.MEDIUM,
                detail=f"'{d}' is in $PATH and writable, so a planted binary could be run in place of a legitimate command.",
                remediation=f"Remove '{d}' from $PATH or fix its permissions so unprivileged users cannot write to it.",
                evidence=d,
                mitre=["T1574.007"],
                references=["https://attack.mitre.org/techniques/T1574/007/"],
            )
        )
    return findings


def analyze_writable_cron(paths: List[str]) -> List[Finding]:
    findings: List[Finding] = []
    for p in sorted(set(x.strip() for x in paths if x.strip())):
        findings.append(
            Finding(
                check="writable",
                title=f"Writable cron path: {p}",
                severity=Severity.HIGH,
                detail=f"'{p}' is a cron file/directory writable by the current user; cron jobs typically run as root.",
                remediation=f"Restore root-only ownership and permissions on '{p}'.",
                evidence=p,
                mitre=["T1053.003"],
                references=["https://attack.mitre.org/techniques/T1053/003/"],
            )
        )
    return findings


def analyze_writable_systemd(paths: List[str]) -> List[Finding]:
    """systemd unit files writable by a non-root user run code as root."""
    findings: List[Finding] = []
    for p in sorted(set(x.strip() for x in paths if x.strip())):
        findings.append(
            Finding(
                check="writable",
                title=f"Writable systemd unit: {p}",
                severity=Severity.HIGH,
                detail=f"'{p}' is a systemd unit writable by the current user; system units run as root, so this allows code execution as root.",
                remediation=f"Restore root ownership and safe permissions: chown root:root {p} && chmod 644 {p}",
                evidence=p,
                fix_command=f"chown root:root {p} && chmod 644 {p}",
                mitre=["T1543.002"],
                references=["https://attack.mitre.org/techniques/T1543/002/"],
            )
        )
    return findings
