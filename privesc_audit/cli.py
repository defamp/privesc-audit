"""Command-line entry point for privesc-audit."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .baseline import diff, load_baseline, save_baseline
from .models import Severity
from .report import (
    render_console,
    render_diff_console,
    render_diff_json,
    render_diff_markdown,
    render_fix_script,
    render_json,
    render_markdown,
)
from .scanner import scan

ALL_CHECKS = ["suid", "sudo", "capabilities", "writable", "nfs", "groups"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="privesc-audit",
        description="Read-only Linux privilege-escalation audit & hardening scanner "
                    "for authorized assessments. It never modifies the system.",
    )
    p.add_argument("-f", "--format", choices=["console", "json", "markdown", "fix-script"], default="console")
    p.add_argument("-c", "--checks", default="all",
                   help=f"comma-separated subset of: {','.join(ALL_CHECKS)} (default: all)")
    p.add_argument("-o", "--output", help="write report to a file instead of stdout")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors in console output")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--save", metavar="FILE",
                   help="save the current findings as a baseline snapshot (JSON) and exit")
    g.add_argument("--baseline", metavar="FILE",
                   help="compare the current scan to a saved baseline and report only what changed")
    p.add_argument("-V", "--version", action="version", version=f"privesc-audit {__version__}")
    return p


def _resolve_checks(arg: str):
    if arg.strip().lower() == "all":
        return set(ALL_CHECKS)
    chosen = {c.strip().lower() for c in arg.split(",") if c.strip()}
    invalid = chosen - set(ALL_CHECKS)
    if invalid:
        raise SystemExit(f"error: unknown check(s): {', '.join(sorted(invalid))}")
    return chosen


def _emit(text: str, output: str) -> None:
    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"report written to {output}")
    else:
        print(text)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    checks = _resolve_checks(args.checks)
    findings = scan(checks)
    use_color = sys.stdout.isatty() and not args.no_color

    # Baseline snapshot: save the current state and exit.
    if args.save:
        save_baseline(findings, args.save)
        print(f"baseline saved to {args.save} ({len(findings)} finding(s))")
        return 0

    # Baseline diff: report only what changed vs a saved snapshot (regression gate).
    if args.baseline:
        base_items, meta = load_baseline(args.baseline)
        d = diff(findings, base_items, meta)
        if args.format == "json":
            text = render_diff_json(d)
        elif args.format == "markdown":
            text = render_diff_markdown(d)
        else:
            text = render_diff_console(d, use_color=use_color)
        _emit(text, args.output)
        if d.worst_new_severity >= int(Severity.HIGH):
            return 2
        if d.has_regression:
            return 1
        return 0

    if args.format == "json":
        text = render_json(findings)
    elif args.format == "markdown":
        text = render_markdown(findings)
    elif args.format == "fix-script":
        text = render_fix_script(findings)
    else:
        text = render_console(findings, use_color=use_color)
    _emit(text, args.output)

    # Exit code for automation: 2 if any High+/Critical, 1 if only lower findings, 0 if none.
    if any(f.severity >= Severity.HIGH for f in findings):
        return 2
    if findings:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
