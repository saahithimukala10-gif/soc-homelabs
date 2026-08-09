# Lab 1 — Wazuh SIEM Deployment

Deploy a Wazuh all-in-one SIEM on an isolated virtual network, instrument a
Windows 11 endpoint, then use Atomic Red Team as ground truth to measure what
the default ruleset actually detects — not what it's assumed to detect.

## Environment

| Component | Detail |
| --- | --- |
| Host | Kali Linux, AMD Ryzen 7 260, 16 GB physical / 14 GB visible |
| Hypervisor | KVM/QEMU + libvirt |
| Lab network | `soclab`, bridge `virbr-soc`, `10.10.10.0/24`, isolated |
| SIEM VM | Ubuntu Server 24.04.4 LTS, 5 GB RAM, 80 GB disk, `10.10.10.10` |
| SIEM | Wazuh 4.14.7-rc1 all-in-one (indexer, server, dashboard) |
| Endpoint | Windows 11 Enterprise Eval 25H2, 4 GB RAM, 60 GB disk, `10.10.10.30` |
| Endpoint telemetry | Sysmon (SwiftOnSecurity config), audit policy, script block logging |

## Results: detection coverage measured with Atomic Red Team

| Technique | Tactic | Result | Gap type |
| --- | --- | --- | --- |
| [T1059.001 PowerShell (encoded command)](findings/t1059-001-powershell-encoded-command.md) | Execution | **Detected** | — |
| [T1053.005 Scheduled Task](findings/t1053-005-scheduled-task.md) | Persistence | **Not detected** | Rule |
| [T1003.001 LSASS Memory (comsvcs)](findings/t1003-001-lsass-memory.md) | Credential Access | **Prevented, then not detected** | Telemetry |

One clean detection, one rule gap, and one telemetry gap — full writeups with
screenshots in [findings/](findings/README.md). These three gaps seed the
custom-rule work in Lab 2.

## How it was built

1. [SIEM build](setup/01-siem-build.md) — isolated network, Wazuh install,
   configuration decisions, baseline noise.
2. [Endpoint & telemetry](setup/02-endpoint-telemetry.md) — Windows 11 victim,
   Sysmon, audit policy, agent enrollment, per-source verification.
3. [Findings](findings/README.md) — the three Atomic Red Team results above,
   in detail.
4. [Troubleshooting log](setup/troubleshooting.md) — secondary issues not
   central enough to keep inline.

## Next

Lab 2 measures out-of-box detection coverage across roughly ten ATT&CK
techniques, then closes the identified gaps with custom rules — validated
against both a positive corpus (the attack fires the rule) and a negative
corpus (a benign lookalike does not). The three gaps found here seed that
work: a scheduled-task rule keyed on EID 4698, a Sysmon ProcessAccess rule for
LSASS, and a script-block-content rule for obfuscated PowerShell.
