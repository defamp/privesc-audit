"""Baseline snapshots and diffing.

Save the current findings to a baseline file, then on a later run compare against
it to see only what *changed* — new misconfigurations, resolved ones, and severity
shifts. Handy as a hardening-regression gate in CI or cron: fail the job when a new
privilege-escalation path appears, stay quiet while the host only improves.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Tuple

from .models import Finding, Severity
from .report import summary

SCHEMA = "privesc-audit/baseline/v1"


def finding_key(check: str, title: str, evidence) -> str:
    """Stable identity for a finding across runs (independent of severity)."""
    return "|".join([check or "", title or "", evidence or ""])


def _key_of_finding(f: Finding) -> str:
    return finding_key(f.check, f.title, f.evidence)


def _key_of_item(d: dict) -> str:
    return finding_key(d.get("check", ""), d.get("title", ""), d.get("evidence"))


def save_baseline(findings: List[Finding], path: str) -> None:
    doc = {
        "schema": SCHEMA,
        "tool_version": _version(),
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": dict(summary(findings)),
        "findings": [f.to_dict() for f in findings],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)


def load_baseline(path: str) -> Tuple[List[dict], dict]:
    """Return (findings_items, metadata). Accepts the baseline doc or a bare list."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        raise SystemExit(f"error: baseline file not found: {path}")
    except (json.JSONDecodeError, OSError) as e:
        raise SystemExit(f"error: cannot read baseline '{path}': {e}")

    if isinstance(data, list):
        return data, {}
    if isinstance(data, dict) and "findings" in data:
        meta = {k: data.get(k) for k in ("created", "tool_version", "summary")}
        return data["findings"], meta
    raise SystemExit(f"error: '{path}' is not a privesc-audit baseline")


@dataclass
class Diff:
    added: List[Finding] = field(default_factory=list)          # present now, not before
    resolved: List[dict] = field(default_factory=list)          # in baseline, gone now
    changed: List[Tuple[Finding, str]] = field(default_factory=list)  # (now, old_severity_label)
    unchanged: int = 0
    baseline_meta: dict = field(default_factory=dict)
    current_count: int = 0

    @property
    def has_regression(self) -> bool:
        """True if anything got worse: a new finding or a severity increase."""
        if self.added:
            return True
        return any(_sev_value(f.severity.label) > _sev_value(old) for f, old in self.changed)

    @property
    def worst_new_severity(self) -> int:
        vals = [int(f.severity) for f in self.added]
        vals += [int(f.severity) for f, old in self.changed if _sev_value(f.severity.label) > _sev_value(old)]
        return max(vals) if vals else -1


def _sev_value(label: str) -> int:
    try:
        return int(Severity[label.upper()])
    except (KeyError, AttributeError):
        return -1


def diff(current: List[Finding], baseline_items: List[dict], baseline_meta: dict = None) -> Diff:
    cur_by_key: Dict[str, Finding] = {_key_of_finding(f): f for f in current}
    base_by_key: Dict[str, dict] = {_key_of_item(d): d for d in baseline_items}

    d = Diff(baseline_meta=baseline_meta or {}, current_count=len(current))
    for key, f in cur_by_key.items():
        base = base_by_key.get(key)
        if base is None:
            d.added.append(f)
        elif str(base.get("severity", "")).lower() != f.severity.label.lower():
            d.changed.append((f, str(base.get("severity", "?"))))
        else:
            d.unchanged += 1
    for key, item in base_by_key.items():
        if key not in cur_by_key:
            d.resolved.append(item)

    d.added.sort(key=lambda f: (-int(f.severity), f.check, f.title))
    d.resolved.sort(key=lambda i: (-_sev_value(str(i.get("severity", ""))), i.get("title", "")))
    return d


def _version() -> str:
    from . import __version__
    return __version__
