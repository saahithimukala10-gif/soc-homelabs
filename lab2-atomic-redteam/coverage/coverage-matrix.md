# Lab 2 — Coverage Matrix (v1, in progress)

Back to [Lab 2](../README.md).

Out-of-box detection coverage across the ten-technique test plan, measured
before any custom rules are written. Each row is filled in only after the
technique has actually been run — no assumptions.

**Methodology shortcut, this pass only:** techniques 4 onward were run in a
single session without a full VM revert between each one, to fit ten
techniques in one sitting. Each result is confirmed by querying for that
technique's specific artifact (a targetObject, a rule ID), not by absence of
other noise, so residue shouldn't invalidate a result — but this is looser
than the per-technique revert discipline used for techniques 1–3 and for the
paired TP/FP validation in Days 7–8, where a fresh revert per test matters
much more.

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
| 4 | T1055 Process Injection (test 13, UUID injection) | Defense Evasion | N/A — file quarantined before execution | Prevented (Defender) | — | — |
| 5 | T1112 Modify Registry (test 7, ExecutionPolicy Bypass) | Defense Evasion | No (Sysmon EID 13 filtered) | No | Telemetry | TBD |
| 6 | T1547.001 Registry Run Keys (test 1, Reg Key Run) | Persistence | Yes | Yes (92302) | — | — |
| 7 | T1087.001 Local Account Discovery (test 8) | Discovery | Yes | No (generic noise only) | Rule | TBD |
| 8 | T1548.002 Bypass UAC (test 1, Event Viewer) | Privilege Escalation | Yes | No | Rule | TBD |
| 9 | T1490 Inhibit System Recovery | Impact | Not yet run | — | — | — |
| 10 | T1113 Screen Capture | Collection | Not yet run | — | — | — |

Rows 1–3 carry over their Lab 1 results as the starting baseline. Rule IDs
for the seeded gaps will be assigned from 100001 once written, and recorded
here alongside the ART test number used to validate each one.

**Test-plan note:** row 5 went through two swaps. Originally T1070.001 (Clear
Windows Event Logs) — no dedicated ART folder for that sub-technique. Tried
T1070.003 (Clear Command History) next — every test in that folder targets
Linux/Mac bash history, none Windows-relevant. Landed on T1112 Modify Registry,
test 7 (Change PowerShell Execution Policy to Bypass): registry-based version
of the `-ExecutionPolicy Bypass` command-line indicator flagged in Lab 1, so it
still serves the original narrative goal.

**T1112 test 7 finding:** `Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope
LocalMachine` writes to
`HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell\ExecutionPolicy`
(confirmed via `Get-ItemProperty` after running). `wazuh-alerts-*` had 0 hits
for `eventID:13 AND targetObject:*ExecutionPolicy*`. Checked the local Sysmon
Operational log directly (same method as the T1003.001 telemetry-gap finding)
— zero events, even though EID 13 is actively logging other registry writes at
the same time (`Tamper-Winlogon`, `T1042` rules firing on Winlogon and OneDrive
protocol-handler changes). SwiftOnSecurity's Sysmon config filters EID 13 by an
allowlist of named `RuleName` categories, and `ExecutionPolicy` isn't among
them — Sysmon never wrote the event, so nothing could reach Wazuh. Second
telemetry gap found this way (after LSASS EID 10), reinforcing that
SwiftOnSecurity's registry coverage is a curated allowlist, not a broad net.

**T1055 note:** test 13 (UUID custom process injection) downloads a small,
purpose-built PoC binary (`uuid_injection.exe`) from ART's own repo — the
technique's other tests need Office (VBA) or a named credential-dumping tool
(mimikatz), neither viable offline or appropriate to stage. Defender flagged
the binary `Trojan:Win64/Malgent!MSR` and deleted it within seconds of it
landing on disk (confirmed: `Test-Path` returned `True` immediately after
download, `False` moments later) — the technique never got to execute.
Same story shape as T1003.001: signature AV caught it before Wazuh telemetry
was ever relevant. Recorded as "Prevented," not benchmarked against Wazuh,
since there's nothing for Wazuh to have seen.

**T1547.001 test 1 finding:** `REG ADD` on the `Run` key detected out of the box
— rule 92302, level 6, correctly mapped to `rule.mitre.id: T1547.001`. Useful
contrast with the T1112 telemetry gap directly above it: both are Sysmon EID 13
registry writes, but `Run` keys are squarely inside SwiftOnSecurity's allowlist
(rule group `sysmon_eid13_detections`) while the PowerShell `ExecutionPolicy`
value isn't. Confirms the allowlist is deliberately scoped to well-known
persistence locations, not a blanket exclusion of most registry paths.

**T1087.001 test 8 finding:** `net user`, `dir c:\Users\`, `cmdkey /list`, `net
localgroup` all ran and reached the indexer, but the only rule that fired was
92032 "Suspicious Windows cmd shell execution," level 3 — the identical rule
that fired for T1053.005 in Lab 1, with the identical static
`rule.mitre.id: T1087, T1059.003` tag, despite entirely different commands.
That's strong evidence 92032 pattern-matches on the cmd-spawned-from-cmd
process chain generically and carries a fixed mitre tag, rather than actually
analyzing command content for discovery behavior. Treated consistently with
the T1053.005 precedent: **rule gap**, not a genuine detection, even though the
mitre tag happens to say "T1087."

**T1548.002 test 1 finding:** the classic `eventvwr.exe`/`mscfile` fileless UAC
bypass. `wazuh-alerts-*` had 0 hits for both the registry write
(`targetObject:*mscfile*`) and the resulting process chain
(`parentImage:*eventvwr*`). Checked the local Sysmon log directly — full chain
present: EID 13 registry write (`RuleName: T1042`) to
`mscfile\shell\open\command`, then `reg.exe` → `cmd.exe /c eventvwr.msc` →
`cmd.exe`, with the **final `cmd.exe` at `IntegrityLevel: High`** — direct proof
the bypass actually elevated without a consent prompt. Confirmed this is a rule
gap and not a collection problem: the same agent had a genuine Sysmon-sourced
alert (rule 92302, T1547.001) fire minutes earlier, so the channel is flowing
fine — the default ruleset just has nothing watching for this pattern. Strong
candidate for a flagship Lab 2 finding alongside the LSASS gap: a full,
successful privilege-escalation chain, invisible end to end.

## Custom rules seeded from Lab 1

1. EID 4698 (scheduled task registered) — method-agnostic, closes the
   T1053.005 rule gap.
2. Sysmon ProcessAccess for `lsass.exe` (enable EID 10 first, then rule) —
   closes the T1003.001 telemetry gap. Flagship finding: telemetry must be
   verified, not assumed.
3. PowerShell 4104 script-block content — invocation-independent alternative
   to the string-dependent rule 92057.
4. `-ExecutionPolicy Bypass` command-line indicator, noted during Lab 1 setup.

## Custom rules seeded from Lab 2 so far

5. Sysmon RegistryEvent (EID 13) for the `ExecutionPolicy` value under
   `HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell` —
   enable targeted EID 13 logging for this key FIRST (same
   telemetry-before-rule sequencing as the LSASS fix), then write the rule.
   Registry-based counterpart to item 4 above — catches the technique whether
   an attacker uses the CLI flag or a direct registry write.
6. Local account/group enumeration rule — key on the specific commands
   (`net user`, `net localgroup`, `cmdkey /list`) rather than the generic
   cmd-spawned-cmd pattern rule 92032 relies on, so it's not drowned out by
   that rule's noise on unrelated cmd chains.
7. UAC-bypass registry-hijack rule — key on well-known auto-elevating binaries'
   associated registry paths (`mscfile\shell\open\command` for `eventvwr.exe`;
   similar hijack points exist for `fodhelper.exe`, `computerdefaults.exe`,
   `sdclt.exe`). More durable alternative/companion: alert on a process
   reaching `IntegrityLevel: High` whose direct parent chain includes one of
   those known auto-elevate binaries, since that catches new hijack variants
   without needing a rule per registry key.
