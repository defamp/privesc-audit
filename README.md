# privesc-audit

**Read-only Linux privilege-escalation audit & hardening scanner.**

`privesc-audit` inspects the local machine for common **local privilege-escalation
misconfigurations** — risky SUID/SGID binaries, over-broad `sudo` rules, dangerous
file capabilities, writable sensitive files / `$PATH` directories / cron paths, and
membership of privilege-granting groups (`docker`, `lxd`, `disk`, …) — and reports
each one with **remediation guidance** and a MITRE ATT&CK mapping.

It is built for **authorized assessments and blue-team hardening**:

- 🔒 **Read-only.** It only *reads* the system. It never modifies anything and never runs exploit code.
- 🧰 **Zero dependencies.** Pure Python 3.8+ standard library — drops onto any host and runs.
- 🛠️ **Fix-oriented.** Every finding comes with how to remediate it, not how to abuse it.
- 🧭 **ATT&CK-mapped.** Findings reference techniques under T1548 (Abuse Elevation Control), T1574, T1053, and more.

> ⚠️ **Authorized use only.** Run this on systems you own or have explicit written
> permission to assess. It is an auditing/hardening aid, not an exploitation tool.

## Install

```bash
pip install -e .
# or just run it in place — it has no third-party dependencies:
python -m privesc_audit.cli
```

## Usage

```bash
privesc-audit                         # console report of the local host
privesc-audit --format json -o out.json
privesc-audit --format markdown
privesc-audit --checks suid,sudo      # run only selected checks
privesc-audit --format fix-script -o harden.sh   # reviewable hardening script
```

Exit codes (handy for CI / cron): `0` = nothing found, `1` = low/medium only,
`2` = at least one High/Critical finding.

### Baseline & diff

Snapshot the current state, then on a later run report only what **changed** —
new misconfigurations, resolved ones, and severity shifts. Use it as a
hardening-regression gate: the job stays green while the host only improves and
fails the moment a new privilege-escalation path appears.

```bash
privesc-audit --save baseline.json     # record the current findings
# ...time passes, config drifts...
privesc-audit --baseline baseline.json # show only what changed since then
privesc-audit --baseline baseline.json --format json   # machine-readable diff
privesc-audit --baseline baseline.json --format markdown -o diff.md
```

The Markdown diff report includes baseline metadata, finding counts, new findings,
severity changes, resolved findings, and the regression verdict. Each listed finding
includes evidence, remediation, and ATT&CK mappings when available. Save it with
`-o diff.md` to attach to an audit report or paste into a GitHub issue. Markdown
output uses the same regression exit codes as console and JSON output.

In diff mode the exit code is a regression gate: `0` = no new exposure (only
resolved/unchanged), `1` = a new low/medium finding or severity increase,
`2` = a new High/Critical finding.

## What it checks

| Check | Looks for | Remediation it suggests |
|---|---|---|
| `suid` | SUID/SGID binaries, flagging those known to escalate when privileged | remove the SUID bit / restrict the binary |
| `sudo` | over-broad or password-less `sudo -l` rules, shell-breakout binaries | scope the sudoers entry, drop `ALL`/`NOPASSWD` |
| `capabilities` | dangerous file capabilities (e.g. `cap_setuid`, `cap_dac_override`) | remove the capability, grant the narrowest one |
| `writable` | writable `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, writable `$PATH` dirs, cron & systemd units | restore safe owner/permissions |
| `nfs` | NFS exports with `no_root_squash` in `/etc/exports` | switch to `root_squash`, restrict hosts |
| `groups` | accounts in privilege-granting groups (`docker`, `lxd`/`lxc`, `disk`, `shadow`, `adm`, `kvm`/`libvirt`, …) | remove members that don't need the group; prefer scoped access (e.g. rootless Docker) |

The "known to escalate" list is derived from the public
[GTFOBins](https://gtfobins.github.io/) project — used here purely as *audit
metadata* (binary names + reference links) to decide which misconfigurations to
flag. No exploit commands are stored or emitted.

## Why pair this with detection?

Hardening removes the misconfiguration; detection catches the abuse if one slips
through. The techniques this tool audits for are the same ones covered by
detection rules in my [detection-engineering](https://github.com/defamp/detection-engineering)
work — audit the host, fix what you can, and detect the rest.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
