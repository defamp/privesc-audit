"""Individual, read-only audit checks. Each exposes pure ``analyze_*`` functions
that take already-collected system data and return a list of Findings, so they
are easy to unit-test and never touch the system themselves."""
