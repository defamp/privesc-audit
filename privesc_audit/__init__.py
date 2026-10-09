"""privesc-audit: read-only Linux privilege-escalation audit & hardening scanner.

Designed for authorized security assessments and blue-team hardening. It only
*reads* the local system to surface misconfigurations that could enable local
privilege escalation, and reports each one with remediation guidance. It never
modifies the system and never executes exploit code.
"""

__version__ = "0.1.0"
