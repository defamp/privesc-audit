from privesc_audit.models import Severity
from privesc_audit.checks.suid import analyze_suid
from privesc_audit.checks.sudo import analyze_sudo
from privesc_audit.checks.capabilities import analyze_capabilities
from privesc_audit.checks.writable import (
    analyze_sensitive_writable,
    analyze_writable_path_dirs,
    analyze_writable_cron,
)


def test_suid_flags_known_risky_binary():
    findings = analyze_suid(["/usr/bin/find", "/usr/bin/somecustomtool"])
    by_title = {f.title: f for f in findings}
    risky = next(f for f in findings if "find" in f.title)
    assert risky.severity == Severity.HIGH
    assert "T1548.001" in risky.mitre
    # a non-GTFOBins binary is only informational
    info = next(f for f in findings if "somecustomtool" in f.title)
    assert info.severity == Severity.INFO


def test_suid_dedupes_and_handles_sgid_mode():
    findings = analyze_suid(["/usr/bin/vim", "/usr/bin/vim"], mode="sgid")
    assert len(findings) == 1
    assert "SGID" in findings[0].title


SUDO_OUT = """User defa may run the following commands on host kali:
    (ALL : ALL) ALL
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/custombackup.sh
"""


def test_sudo_parses_rules():
    findings = analyze_sudo(SUDO_OUT)
    titles = " ".join(f.title for f in findings)
    # full ALL access
    all_rule = next(f for f in findings if "ALL commands" in f.title)
    assert all_rule.severity == Severity.HIGH
    # risky binary via sudo
    assert any("find" in f.title and f.severity == Severity.HIGH for f in findings)
    # password-less but non-risky custom script -> medium
    assert any("custombackup.sh" in (f.evidence or "") and f.severity == Severity.MEDIUM for f in findings)


def test_sudo_empty_is_safe():
    assert analyze_sudo("") == []


def test_capabilities_flags_setuid_on_interpreter():
    out = "/usr/bin/python3.11 = cap_setuid+ep\n/usr/bin/ping = cap_net_raw+ep\n"
    findings = analyze_capabilities(out)
    assert len(findings) == 1  # ping's cap_net_raw is not in the dangerous set
    f = findings[0]
    assert f.severity == Severity.HIGH  # python can run code
    assert "cap_setuid" in f.title


def test_writable_sensitive_files():
    findings = analyze_sensitive_writable(["/etc/shadow", "/etc/passwd", "/not/sensitive"])
    sev = {f.evidence: f.severity for f in findings}
    assert sev["/etc/shadow"] == Severity.CRITICAL
    assert sev["/etc/passwd"] == Severity.CRITICAL
    assert "/not/sensitive" not in sev


def test_writable_path_and_cron():
    assert analyze_writable_path_dirs(["/tmp"])[0].mitre == ["T1574.007"]
    assert analyze_writable_cron(["/etc/crontab"])[0].severity == Severity.HIGH
