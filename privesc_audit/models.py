"""Data models for audit findings."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import List, Optional


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()


@dataclass
class Finding:
    """A single audit observation plus how to remediate it."""

    check: str                      # which check produced this (e.g. "suid")
    title: str                      # short human-readable title
    severity: Severity
    detail: str                     # what was observed and why it matters
    remediation: str                # how a defender should fix / harden it
    evidence: Optional[str] = None  # the concrete path/line observed (read-only)
    fix_command: Optional[str] = None  # a concrete hardening command, if one applies
    mitre: List[str] = field(default_factory=list)   # ATT&CK technique IDs
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.label
        return d
