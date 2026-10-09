"""Audit metadata for binaries that can enable privilege escalation when misconfigured.

This is reference data only — a list of binary *names* that are known (per the
public GTFOBins project) to allow privilege escalation **if** they are granted a
SUID bit or allowed via sudo. It is used to flag such misconfigurations during an
audit so they can be remediated. No exploit commands are stored or produced here.
"""

from __future__ import annotations

GTFOBINS_URL = "https://gtfobins.github.io/gtfobins/{name}/"

# Binary basename -> short note on why it is risky when SUID/sudo-enabled.
# (Names are the audit signal; remediation is "remove the SUID bit / restrict sudo".)
RISKY_WHEN_PRIVILEGED = {
    "bash": "interactive shell",
    "sh": "interactive shell",
    "dash": "interactive shell",
    "zsh": "interactive shell",
    "ksh": "interactive shell",
    "fish": "interactive shell",
    "awk": "runs commands",
    "gawk": "runs commands",
    "find": "runs commands via -exec",
    "vim": "shell escape",
    "vi": "shell escape",
    "nano": "file read/write as owner",
    "less": "shell escape (pager)",
    "more": "shell escape (pager)",
    "man": "shell escape (pager)",
    "nmap": "runs commands (interactive/script)",
    "perl": "runs commands",
    "python": "runs commands",
    "python3": "runs commands",
    "ruby": "runs commands",
    "lua": "runs commands",
    "php": "runs commands",
    "node": "runs commands",
    "gdb": "runs commands",
    "tar": "runs commands via checkpoint action",
    "cpio": "arbitrary file read/write",
    "zip": "runs commands",
    "git": "runs commands via hooks/pager",
    "env": "runs arbitrary programs",
    "nice": "spawns a shell",
    "flock": "spawns a shell",
    "xargs": "runs commands",
    "tcpdump": "runs post-rotate command",
    "ftp": "shell escape",
    "tmux": "spawns a shell",
    "screen": "spawns a shell",
    "ed": "shell escape",
    "ex": "shell escape",
    "docker": "host access via container mount",
    "systemctl": "runs a unit/command",
    "cp": "overwrite sensitive files",
    "dd": "overwrite sensitive files",
    "chmod": "change permissions of sensitive files",
    "chown": "change ownership of sensitive files",
    "sed": "file read/write as owner",
    "rsync": "runs commands",
    "capsh": "spawns a shell",
    "setarch": "spawns a shell",
    "watch": "runs commands",
    "socat": "runs commands",
    "expect": "runs commands",
    "openssl": "file read/write as owner",
    "busybox": "many applets incl. shell",
}


def gtfobins_url(binary_name: str) -> str:
    return GTFOBINS_URL.format(name=binary_name)


import re as _re


def risk_note(binary_name: str):
    """Return the risk note for a basename, or None if not a known-risky binary.

    Handles version-suffixed interpreters, e.g. 'python3.11' -> 'python3'/'python',
    'perl5.36' -> 'perl', 'lua5.4' -> 'lua'.
    """
    if not binary_name:
        return None
    if binary_name in RISKY_WHEN_PRIVILEGED:
        return RISKY_WHEN_PRIVILEGED[binary_name]
    # Drop a single ".<version>" suffix first (keeps e.g. python3).
    one = _re.sub(r"\.\d+$", "", binary_name)
    if one in RISKY_WHEN_PRIVILEGED:
        return RISKY_WHEN_PRIVILEGED[one]
    # Then drop any trailing version/number block (python3.11 -> python).
    stripped = _re.sub(r"[\d.]+$", "", binary_name)
    if stripped and stripped in RISKY_WHEN_PRIVILEGED:
        return RISKY_WHEN_PRIVILEGED[stripped]
    return None
