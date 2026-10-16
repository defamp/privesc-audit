import json

import pytest

from privesc_audit import cli
from privesc_audit.baseline import diff, load_baseline, save_baseline
from privesc_audit.models import Finding, Severity
from privesc_audit.report import render_diff_markdown


def mkf(check, title, sev, evidence=None):
    return Finding(check=check, title=title, severity=sev, detail="d", remediation="r", evidence=evidence)


def test_save_and_load_roundtrip(tmp_path):
    p = tmp_path / "base.json"
    save_baseline([mkf("suid", "SUID find", Severity.HIGH, "/usr/bin/find")], str(p))
    items, meta = load_baseline(str(p))
    assert len(items) == 1 and items[0]["title"] == "SUID find"
    assert meta["tool_version"]  # metadata preserved
    assert json.loads(p.read_text())["schema"].startswith("privesc-audit/baseline")


def test_diff_added_resolved_changed(tmp_path):
    base = [
        mkf("suid", "A", Severity.HIGH, "/a"),
        mkf("groups", "B", Severity.LOW, "g:x"),
        mkf("sudo", "C", Severity.MEDIUM, "/c"),
    ]
    p = tmp_path / "b.json"
    save_baseline(base, str(p))
    items, meta = load_baseline(str(p))

    # A resolved, B unchanged, C severity raised, D brand new
    current = [
        mkf("groups", "B", Severity.LOW, "g:x"),
        mkf("sudo", "C", Severity.HIGH, "/c"),
        mkf("nfs", "D", Severity.HIGH, "/d"),
    ]
    d = diff(current, items, meta)
    assert [f.title for f in d.added] == ["D"]
    assert [i["title"] for i in d.resolved] == ["A"]
    assert len(d.changed) == 1 and d.changed[0][0].title == "C" and d.changed[0][1] == "Medium"
    assert d.unchanged == 1
    assert d.has_regression is True
    assert d.worst_new_severity == int(Severity.HIGH)


def test_diff_no_regression_when_only_resolved(tmp_path):
    p = tmp_path / "b.json"
    save_baseline([mkf("suid", "A", Severity.HIGH, "/a")], str(p))
    items, _ = load_baseline(str(p))
    d = diff([], items)
    assert d.added == [] and len(d.resolved) == 1
    assert d.has_regression is False
    assert d.worst_new_severity == -1


def test_load_bad_file_errors(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not valid json")
    with pytest.raises(SystemExit):
        load_baseline(str(p))
    with pytest.raises(SystemExit):
        load_baseline(str(tmp_path / "missing.json"))


def test_cli_save_then_diff_gate(tmp_path, monkeypatch, capsys):
    high = mkf("suid", "risky", Severity.HIGH, "/x")
    monkeypatch.setattr(cli, "scan", lambda checks: [high])
    base = tmp_path / "b.json"

    assert cli.main(["--save", str(base)]) == 0
    assert base.exists()
    capsys.readouterr()

    # unchanged state -> no regression -> exit 0
    assert cli.main(["--baseline", str(base)]) == 0
    assert "No changes" in capsys.readouterr().out

    # a new HIGH finding appears -> regression gate exits 2
    monkeypatch.setattr(cli, "scan", lambda checks: [high, mkf("nfs", "new", Severity.HIGH, "/y")])
    assert cli.main(["--baseline", str(base)]) == 2
    assert "NEW (1)" in capsys.readouterr().out


def test_markdown_diff_all_changes():
    old = [mkf("suid", "removed", Severity.HIGH).to_dict(),
           mkf("sudo", "raised", Severity.LOW).to_dict()]
    new = mkf("groups", "docker | <host>", Severity.HIGH, "line1\nline2")
    new.remediation = "review | members"
    new.mitre = ["T1548"]
    report = render_diff_markdown(diff(
        [new, mkf("sudo", "raised", Severity.HIGH)], old,
        {"created": "2026-10-16T00:00:00Z"},
    ))
    assert "## New (1)" in report
    assert "## Changed severity (1)" in report
    assert "## Resolved (1)" in report
    assert "Low → High" in report
    assert "docker \\| &lt;host&gt;" in report
    assert "line1<br>line2" in report
    assert "review \\| members" in report
    assert "T1548" in report
    assert "**Baseline:** 2026" in report
    assert "**VERDICT:** regression" in report
    assert "\033[" not in report


@pytest.mark.parametrize("current_severity, expected_code", [
    (None, 0), (Severity.LOW, 1), (Severity.HIGH, 2),
])
def test_cli_markdown_diff_file(tmp_path, monkeypatch, capsys, current_severity, expected_code):
    base = tmp_path / "base.json"
    output = tmp_path / "diff.md"
    save_baseline([], str(base))
    current = [] if current_severity is None else [mkf("groups", "new", current_severity)]
    monkeypatch.setattr(cli, "scan", lambda checks: current)
    assert cli.main(["--baseline", str(base), "--format", "markdown", "-o", str(output)]) == expected_code
    report = output.read_text()
    assert report.startswith("# privesc-audit baseline diff\n")
    assert "report written to" in capsys.readouterr().out
    if not current:
        assert "No changes since baseline" in report
        assert "**VERDICT:** no new exposure" in report


def test_cli_markdown_diff_downgrade_stdout(tmp_path, monkeypatch, capsys):
    base = tmp_path / "base.json"
    save_baseline([mkf("sudo", "rule", Severity.HIGH)], str(base))
    monkeypatch.setattr(cli, "scan", lambda checks: [mkf("sudo", "rule", Severity.LOW)])
    assert cli.main(["--baseline", str(base), "--format", "markdown"]) == 0
    report = capsys.readouterr().out
    assert "High → Low" in report
    assert "**VERDICT:** no new exposure" in report
