# Findings — Atomic Red Team Detection Validation

Back to [Lab 1 overview](../README.md). Setup: [SIEM build](../setup/01-siem-build.md) ·
[Endpoint telemetry](../setup/02-endpoint-telemetry.md).

Three ATT&CK techniques were executed against the instrumented endpoint as
ground truth, to measure what Wazuh's default ruleset detects out of the box.
Each was run from the `clean-baseline` snapshot and reverted afterward, so every
result reflects the technique under test rather than residue from a prior run.

Atomic Red Team, its execution framework, and the `powershell-yaml` dependency
were delivered to the isolated endpoint over the host HTTP file server, since
the victim has no internet route. This is the same constraint a real air-gapped
environment imposes.

**Deliberately stopped at three of four planned techniques.** One detection,
one rule gap, and one telemetry gap demonstrate the coverage method better than
four detections would. T1055 (process injection) needs downloaded payloads or
Office, none available offline, and is deferred to Lab 2 where a payload can be
staged deliberately.

## Results summary

| Technique | Tactic | Result | Data source | Gap type |
| --- | --- | --- | --- | --- |
| [T1059.001 PowerShell (encoded command)](t1059-001-powershell-encoded-command.md) | Execution | **Detected** | Sysmon EID 1 / 4688 command line | — |
| [T1053.005 Scheduled Task](t1053-005-scheduled-task.md) | Persistence | **Not detected** | schtasks.exe reaches indexer | Rule |
| [T1003.001 LSASS Memory (comsvcs)](t1003-001-lsass-memory.md) | Credential Access | **Prevented, then not detected** | Defender 1116/1117; Sysmon EID 1 only | Telemetry |

One clean detection, one rule gap, and one telemetry gap — three distinct
outcomes that together define where custom work is needed in Lab 2.

## Running the atomics: execution policy

**Symptom.** The post-revert setup script could not run — execution policy was
`Restricted`.

**Cause.** Each snapshot revert restores the baseline, where the default
`Restricted` policy is in force. The script that sets the policy cannot itself
run under that policy.

**Resolution.** Set `RemoteSigned` for the current user manually as the first
command after each revert, then run the script.

**Detection note.** This is the same friction an attacker meets, and the common
bypass — `powershell.exe -ExecutionPolicy Bypass` — is itself a well-known
suspicious command-line indicator and a candidate detection for Lab 2.

Other setup issues (missing ART dependencies on an offline host) are in
[troubleshooting.md](../setup/troubleshooting.md#atomic-red-team).

---

Next: [Lab 2 — coverage measurement and custom rules](../../lab2-atomic-redteam/).
