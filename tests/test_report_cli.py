import json

from privesc_audit.models import Finding, Severity
from privesc_audit.report import render_json, render_markdown, render_console
from privesc_audit import cli


def _sample():
    return [
        Finding(check="suid", title="SUID binary known to enable privilege escalation: find",
                severity=Severity.HIGH, detail="x", remediation="chmod -s", mitre=["T1548.001"]),
        Finding(check="writable", title="Sensitive file is writable: /etc/shadow",
                severity=Severity.CRITICAL, detail="y", remediation="fix perms", evidence="/etc/shadow"),
    ]


def test_render_json_valid():
    data = json.loads(render_json(_sample()))
    assert data["summary"]["High"] == 1 and data["summary"]["Critical"] == 1
    assert len(data["findings"]) == 2
    assert data["findings"][0]["severity"] in {"High", "Critical"}


def test_render_markdown_has_table():
    md = render_markdown(_sample())
    assert "| Severity | Finding | Fix |" in md
    assert "/etc/shadow" in md


def test_render_console_no_color_plain():
    out = render_console(_sample(), use_color=False)
    assert "\033[" not in out
    assert "CRITICAL" in out


def test_render_console_empty():
    assert "No privilege-escalation findings" in render_console([], use_color=False)


def test_cli_resolve_checks_invalid():
    try:
        cli._resolve_checks("suid,bogus")
        assert False, "expected SystemExit"
    except SystemExit:
        pass


def test_cli_main_json_exit_code(monkeypatch, capsys):
    monkeypatch.setattr(cli, "scan", lambda checks: _sample())
    rc = cli.main(["--format", "json"])
    assert rc == 2  # a High+ finding present
    out = capsys.readouterr().out
    assert json.loads(out)["summary"]  # valid JSON printed


def test_cli_main_clean_exit_zero(monkeypatch):
    monkeypatch.setattr(cli, "scan", lambda checks: [])
    assert cli.main(["--format", "json"]) == 0


from privesc_audit.report import render_fix_script


def test_fix_script_includes_commands_and_header():
    items = [
        Finding(check="suid", title="SUID find", severity=Severity.HIGH, detail="x",
                remediation="r", fix_command="chmod -s /usr/bin/find"),
        Finding(check="sudo", title="manual sudo item", severity=Severity.HIGH, detail="x",
                remediation="r"),  # no fix_command -> manual
    ]
    script = render_fix_script(items)
    assert script.startswith("#!/usr/bin/env bash")
    assert "REVIEW EVERY LINE" in script
    assert "chmod -s /usr/bin/find" in script
    assert "1 finding(s) need manual review" in script


def test_fix_script_empty():
    assert "No auto-fixable findings" in render_fix_script([])
