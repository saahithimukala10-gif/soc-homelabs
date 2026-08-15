# Lab 2 — Coverage Matrix (v1, in progress)

Back to [Lab 2](../README.md).

Out-of-box detection coverage across the ten-technique test plan, measured
before any custom rules are written. Each row is filled in only after the
technique has actually been run from a clean snapshot — no assumptions.

**Method:** query `data.win.system.providerName` first to confirm the channel
is collected, then `data.win.system.eventID` / `rule.mitre.id` in
`wazuh-alerts-*` to confirm a rule fired. An empty alert result with a
providerName hit is a **rule gap**; no providerName hit at all is a
**telemetry gap**.

| # | Technique | Tactic | Telemetry present? | OOB alert? | Gap type | Custom rule ID |
|---|---|---|---|---|---|---|
| 1 | T1059.001 PowerShell (encoded command) | Execution | Yes | Yes (92057) | — | — |
| 2 | T1053.005 Scheduled Task | Persistence | Yes | No | Rule | TBD (4698) |
| 3 | T1003.001 LSASS Memory | Credential Access | No (EID 10 filtered) | No | Telemetry | TBD |
| 4 | T1055 Process Injection | Defense Evasion | Not yet run | — | — | — |
| 5 | T1070.003 Clear Command History | Defense Evasion | Not yet run | — | — | — |
| 6 | T1547.001 Registry Run Keys | Persistence | Not yet run | — | — | — |
| 7 | T1087.001 Local Account Discovery | Discovery | Not yet run | — | — | — |
| 8 | T1548.002 Bypass UAC | Privilege Escalation | Not yet run | — | — | — |
| 9 | T1490 Inhibit System Recovery | Impact | Not yet run | — | — | — |
| 10 | T1113 Screen Capture | Collection | Not yet run | — | — | — |

Rows 1–3 carry over their Lab 1 results as the starting baseline. Rule IDs
for the seeded gaps will be assigned from 100001 once written, and recorded
here alongside the ART test number used to validate each one.

**Test-plan note:** row 5 was originally T1070.001 (Clear Windows Event Logs).
Atomic Red Team has no dedicated folder for that sub-technique — `atomics/T1070`
turned out to be FSUtil-based indicator removal (USN journal manipulation),
unrelated to event-log clearing. Swapped to T1070.003 (Clear Command History),
which does have ART coverage and stays in the same Defense Evasion /
indicator-removal family.

## Custom rules seeded from Lab 1

1. EID 4698 (scheduled task registered) — method-agnostic, closes the
   T1053.005 rule gap.
2. Sysmon ProcessAccess for `lsass.exe` (enable EID 10 first, then rule) —
   closes the T1003.001 telemetry gap. Flagship finding: telemetry must be
   verified, not assumed.
3. PowerShell 4104 script-block content — invocation-independent alternative
   to the string-dependent rule 92057.
4. `-ExecutionPolicy Bypass` command-line indicator, noted during Lab 1 setup.
