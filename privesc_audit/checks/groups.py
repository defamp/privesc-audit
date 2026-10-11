"""Audit membership of groups that grant a path to privilege escalation.

Some Unix groups are effectively root-equivalent: a member of ``docker`` or
``lxd`` can start a container that mounts the host filesystem and walk away with
a root shell; a member of ``disk`` can read raw block devices (and therefore
``/etc/shadow``); a member of ``shadow`` can read password hashes directly.

This check is *read-only*: it only reports which non-root accounts sit in those
groups and how each one could be abused. Removing an account from a group can
break a legitimate admin's workflow, so findings here are **manual** (no
auto-fix command) — the operator decides who really needs the membership.
"""

from __future__ import annotations

from typing import Dict, List

from ..models import Finding, Severity

ATTACK = "https://attack.mitre.org/techniques/{}/"

# group name (lowercase) -> how it escalates, severity, ATT&CK ids, reference
DANGEROUS_GROUPS = {
    "docker": dict(
        severity=Severity.HIGH,
        path="can mount the host filesystem into a container and read/write any "
             "file as root, e.g. `docker run -v /:/mnt --rm -it alpine chroot /mnt sh`",
        mitre=["T1548"],
        ref="https://gtfobins.github.io/gtfobins/docker/",
    ),
    "lxd": dict(
        severity=Severity.HIGH,
        path="can launch a privileged container that mounts the host filesystem, "
             "yielding a root shell on the host",
        mitre=["T1548"],
        ref=ATTACK.format("T1611"),
    ),
    "lxc": dict(
        severity=Severity.HIGH,
        path="can create a privileged container mounting the host filesystem to "
             "escalate to root",
        mitre=["T1548"],
        ref=ATTACK.format("T1611"),
    ),
    "disk": dict(
        severity=Severity.HIGH,
        path="has raw read/write access to block devices (e.g. `debugfs /dev/sda`), "
             "so it can read /etc/shadow and overwrite any file on disk",
        mitre=["T1548"],
        ref=ATTACK.format("T1006"),
    ),
    "shadow": dict(
        severity=Severity.HIGH,
        path="can read /etc/shadow directly and crack the password hashes offline",
        mitre=["T1003.008"],
        ref=ATTACK.format("T1003/008"),
    ),
    "adm": dict(
        severity=Severity.MEDIUM,
        path="can read system logs under /var/log, which often leak credentials, "
             "tokens and other sensitive information useful for escalation",
        mitre=["T1552"],
        ref=ATTACK.format("T1552"),
    ),
    "kvm": dict(
        severity=Severity.MEDIUM,
        path="has access to the virtualization layer (/dev/kvm) and can be leveraged "
             "to reach host resources via a crafted VM",
        mitre=["T1548"],
        ref=ATTACK.format("T1548"),
    ),
    "libvirt": dict(
        severity=Severity.MEDIUM,
        path="can manage VMs via libvirt and attach host devices/disks, a path to "
             "reading or writing host files as root",
        mitre=["T1548"],
        ref=ATTACK.format("T1548"),
    ),
    "video": dict(
        severity=Severity.LOW,
        path="can access the framebuffer/GPU devices and capture the screen of other "
             "sessions",
        mitre=["T1113"],
        ref=ATTACK.format("T1113"),
    ),
    "wheel": dict(
        severity=Severity.LOW,
        path="is allowed to use `sudo` on many distributions — expected for admins, "
             "but confirm every member is meant to have root",
        mitre=["T1548.003"],
        ref=ATTACK.format("T1548/003"),
    ),
    "sudo": dict(
        severity=Severity.LOW,
        path="is granted `sudo` rights by the default sudoers policy — expected for "
             "admins, but confirm every member is meant to have root",
        mitre=["T1548.003"],
        ref=ATTACK.format("T1548/003"),
    ),
}


def analyze_groups(memberships: Dict[str, List[str]]) -> List[Finding]:
    """Flag non-root accounts that belong to privilege-granting groups.

    ``memberships`` maps a group name to the usernames in it (as collected from
    /etc/group plus the current user's own groups).
    """
    findings: List[Finding] = []
    for group, members in sorted((memberships or {}).items()):
        info = DANGEROUS_GROUPS.get(group.lower())
        if not info:
            continue
        # root in these groups is not an escalation (it is already root).
        human = sorted({m for m in (members or []) if m and m != "root"})
        if not human:
            continue
        who = ", ".join(human)
        findings.append(
            Finding(
                check="groups",
                title=f"Account(s) in privileged group '{group}': {who}",
                severity=info["severity"],
                detail=(
                    f"The group '{group}' {info['path']}. Member(s): {who}. "
                    f"Any of these accounts can therefore escalate beyond their "
                    f"intended privileges if compromised."
                ),
                remediation=(
                    f"Confirm each member truly needs '{group}'. Remove any that do "
                    f"not with 'gpasswd -d <user> {group}' (or edit /etc/group), and "
                    f"prefer scoped, audited access (e.g. rootless Docker) over broad "
                    f"group membership."
                ),
                evidence=f"{group}: {who}",
                mitre=info["mitre"],
                references=[info["ref"]],
            )
        )
    return findings
