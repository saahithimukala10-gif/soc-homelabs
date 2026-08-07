# Lab 1 — Wazuh SIEM Deployment

## Objective

Deploy a Wazuh all-in-one SIEM on an isolated virtual network as the collection
and detection layer for subsequent detection-engineering work. The network is
isolated by construction, not by policy, so that attack simulation cannot reach
external hosts.

## Environment

| Component | Detail |
|---|---|
| Host | Kali Linux, AMD Ryzen 7 260, 16 GB physical / 14 GB visible |
| Hypervisor | KVM/QEMU + libvirt |
| Lab network | `soclab`, bridge `virbr-soc`, `10.10.10.0/24`, isolated |
| SIEM VM | Ubuntu Server 24.04.4 LTS, 5 GB RAM, 80 GB disk, `10.10.10.10` |
| SIEM | Wazuh 4.14.7-rc1 all-in-one (indexer, server, dashboard) |

## Network design

The `soclab` libvirt network omits the `<forward>` element entirely. Without it
libvirt creates an isolated bridge: guests reach each other and the host at
`10.10.10.1`, and there is no route outward. Isolation is therefore a property
of the network definition rather than a firewall rule that could be misapplied.

DHCP is also omitted. Every host is statically addressed so that agent
configuration, dashboard URLs, and detection rules can reference fixed
addresses.

Verification from inside the SIEM VM after configuration:

    $ ping -c 2 -W 3 8.8.8.8
    ping: connect: Network is unreachable

The kernel rejects the attempt immediately for want of a default route, rather
than timing out — there is no path out at any layer.

## Installation approach

The VM was built with two interfaces: one on `soclab` for its permanent address
and a second on the libvirt `default` NAT network for the duration of OS
installation, patching, and Wazuh package download. The NAT interface was
detached with `--persistent` once installation completed, editing the stored
domain XML so the interface does not return on reboot.

The installation assistant was downloaded and inspected before execution rather
than piped directly into a shell, so that the code being run as root had been
seen first.

## Configuration decisions

**Ubuntu 24.04 over 26.04.** Wazuh 4.14's supported-platform list ends at Ubuntu
24.04. 26.04 LTS was available but unsupported; an unsupported base OS is a
poor place to debug a component failure.

**JVM heap left at installer default.** The project plan called for capping the
indexer heap at 2 GB. Measurement contradicted the plan: the installer had
already auto-sized it to 1024m based on detected RAM, and `ps aux --sort=-%mem`
showed indexer RSS at 1.24 GB against a 4.8 GB VM with 232 MB of swap already
in use. Raising the heap would have increased memory pressure. The planned
tuning step was therefore not applied.

The gap between the 1 GB heap and 1.24 GB resident is JVM overhead outside the
heap — thread stacks, metaspace, and 512 MB of reserved Netty direct buffers.
Heap size and process footprint are not the same number.

**Vulnerability detection disabled.** See "Issues" below.

**Repository pinned.** The Wazuh apt repository was commented out after
installation. All subsequent coverage measurement compares out-of-box detection
against custom rules; an unannounced minor-version bump would silently change
the baseline mid-measurement and invalidate the comparison.

**30-day retention.** An ISM policy (`wazuh-30day-retention`) deletes
`wazuh-alerts-*` and `wazuh-archives-*` indices at 30 days. An `ism_template`
block applies it automatically to new daily indices; the index created before
the policy existed was attached explicitly. Without retention the indexer
accumulates indices until the disk fills, at which point ingestion stops
without any obvious failure indication.

## Baseline observation

Within roughly one hour of installation, with **zero agents enrolled**, the
manager had generated 367 alerts (1.3 MB) — 124 medium and 177 low severity.
These come from the manager monitoring its own host: SCA benchmark checks, file
integrity monitoring, and authentication events from the administrator's own
SSH and sudo activity.

This is a useful calibration point. None of these are attacks. Distinguishing
this class of baseline noise from signal is most of the analyst workload, and
the volume grows substantially once endpoints are enrolled.

## Issues encountered

### libvirt connected to the wrong instance

**Symptom.** `virsh net-list --all` returned an empty table as a normal user
while `virt-manager` displayed the `default` network. Later,
`virsh net-start soclab` failed with:

    error: error creating bridge interface virbr-soc: Operation not permitted

**Cause.** libvirt runs two independent instances. Unprivileged `virsh`
defaulted to the per-user `qemu:///session`, which has no networks and, lacking
`CAP_NET_ADMIN`, cannot create bridge interfaces. `virt-manager` defaults to the
system-wide `qemu:///system`. A stray network definition had also been written
to `~/.config/libvirt/qemu/networks/`.

**Impact.** The lab design requires a bridged isolated network with fixed
addressing. Session mode is structurally incapable of providing it.

**Resolution.** Undefined the session-mode copy, redefined under
`qemu:///system`, pinned `LIBVIRT_DEFAULT_URI`.

**Takeaway.** `virsh uri` is the first diagnostic when libvirt state appears
inconsistent between tools. Passing `-c qemu:///system` explicitly is more
reliable than depending on environment state.

### Environment fix written to the wrong shell profile

**Symptom.** The `LIBVIRT_DEFAULT_URI` fix worked in the session where it was
applied, then silently stopped working in every new terminal.

**Cause.** The export was appended to `~/.bashrc`. Kali's default shell is zsh,
which reads `~/.zshrc`.

**Takeaway.** A configuration fix that is not verified in a fresh session has
not been verified. `echo $SHELL` before editing a shell profile.

### Modular libvirt daemons absent

**Symptom.** `systemctl enable virtqemud.socket` returned `Unit
virtqemud.socket does not exist`, and `libvirtd.service` reported `inactive`
while `virsh` worked normally.

**Cause.** This build uses the monolithic `libvirtd` rather than the newer
per-function daemons, and it is socket-activated — systemd starts it on first
connection, so an `inactive` service is not evidence of a problem.

**Resolution.** Enabled `libvirtd.service` directly so it survives reboot, plus
`virtlogd.socket` for guest console logging.

### Fresh install consumed 21 GB with no agents

**Symptom.** `df -h` showed 21 GB used on a newly installed SIEM VM.

**Diagnosis.** `du -sh` narrowed it to `/var/ossec` (11 GB), then to
`/var/ossec/queue/vd` (8.0 GB) and `vd_updater` (1.1 GB) — CVE feeds for every
operating system Wazuh supports, refreshed hourly.

**Decision.** Vulnerability detection was disabled. It matches installed-package
inventories against CVE feeds, which is a different detection paradigm from the
behavioural work this project measures. More importantly it would have produced
continuous CVE alerts from the deliberately unpatched Windows victim, and that
volume would obscure the behavioural detections that Lab 2's coverage
measurement depends on.

**Resolution.** Set `<enabled>no</enabled>` in the `vulnerability-detection`
block, validated with `wazuh-analysisd -t` before restarting, then removed the
feed directories. Disk use fell from 21 GB to 12 GB; `apt clean` recovered a
further 1.7 GB.

**Takeaway.** Validate configuration with `wazuh-analysisd -t` before restarting
the manager. A malformed `ossec.conf` does not fail gracefully — the service
refuses to start.

### Indexer API not reachable on the VM's own address

**Symptom.** `curl https://10.10.10.10:9200` failed instantly with "Couldn't
connect to server".

**Cause.** `ss -tlnp` showed the indexer bound to `127.0.0.1:9200` and
`127.0.0.1:9300`. The all-in-one installer binds the indexer API to loopback
only; the manager, Filebeat, and dashboard all reach it locally. Only the
dashboard listens externally, on 443.

**Takeaway.** "Connection refused" immediately means nothing is listening on
that address; a timeout means something is filtering. `ss -tlnp` distinguishes
a binding problem from a network problem.

## Validation

| Check | Result |
|---|---|
| `soclab` active, no `<forward>` element | Pass |
| `virbr-soc` holds `10.10.10.1/24` | Pass |
| VM reachable at `10.10.10.10` over SSH | Pass |
| Dashboard reachable at `https://10.10.10.10` | Pass |
| `wazuh-indexer`, `wazuh-manager`, `wazuh-dashboard`, `filebeat` active | Pass |
| Alert index present and receiving documents | Pass (367 docs) |
| ISM policy attached, `enabled: true` | Pass |
| Outbound connectivity from VM | Fails as designed |

## Snapshots

| Name | State captured |
|---|---|
| `ubuntu-clean` | Ubuntu installed, static IP, SSH, pre-Wazuh |
| `wazuh-baseline` | Wazuh configured, VD disabled, retention set, NAT detached |

Both were taken from a clean shutdown rather than a running VM, so they capture
disk state only and are correspondingly small and quick to revert.



## Endpoint: Windows 11 victim

| Property | Value |
|---|---|
| OS | Windows 11 Enterprise Evaluation, 25H2 (build 26200.8973) |
| Address | `10.10.10.30/24`, no gateway |
| Resources | 4 GB RAM, 60 GB disk, 2 vCPU |
| Machine type | q35, UEFI (OVMF), emulated TPM 2.0 via swtpm |
| Local account | `analyst` (no Microsoft account) |
| Wazuh agent | 4.14.7-1, enrolled as `win11-victim`, agent ID 001 |

Windows 11 enforces UEFI and TPM 2.0 at install time, so the guest needed the
q35 chipset, OVMF firmware, and a `swtpm` emulated TPM rather than QEMU's
defaults. The system disk is on the virtio bus for throughput, which means
Windows setup cannot see it until the virtio storage driver is loaded manually
from a second CD (`viostor\w11\amd64`). Both ISOs are attached over SATA
precisely because the installer cannot boot from a bus it has no driver for.

The endpoint was patched to current over a temporary NAT interface, which was
then detached with `--persistent`. Verification from the endpoint afterwards:

    C:\> ping -n 2 8.8.8.8
    PING: transmit failed. General failure.

All subsequent software — Sysmon, its configuration, and the Wazuh agent — was
delivered from the Kali host over HTTP (`10.10.10.1:8000`), bound explicitly to
the lab bridge rather than all interfaces. This mirrors how an air-gapped
endpoint is actually serviced, and each transfer generates Sysmon EID 3 network
telemetry as a side effect.

## Telemetry configuration

Default Windows logging is insufficient for behavioural detection. The
configuration below was applied and each setting verified to produce events
before moving on.

### Baseline audit policy

The default policy on this build was measured before changing anything:

| Subcategory | Default state |
|---|---|
| Logon | Success and Failure |
| Special Logon | Success |
| User Account Management | Success |
| **Process Creation** | **No Auditing** |

Windows 11 25H2 ships with more auditing enabled than much of the available
guidance assumes. Logon and account-management auditing were already on; the
only gap was process creation.

### Applied configuration

    auditpol /set /subcategory:"Process Creation" /success:enable

Command-line capture in EID 4688, without which the event records that a process
started but not what it was asked to do:

    HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit
      ProcessCreationIncludeCmdLine_Enabled = 1 (DWORD)

PowerShell script block logging (EID 4104):

    HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
      EnableScriptBlockLogging = 1 (DWORD)

Sysmon was installed with the SwiftOnSecurity community configuration rather
than a hand-written one:

    .\Sysmon64.exe -accepteula -i sysmonconfig.xml

The command-line interface was used throughout in preference to the Group Policy
editor so that the configuration is reproducible and can be verified from a
transcript.

### Why script block logging matters

Command-line logging alone is defeated by encoding. Script block logging hooks
the PowerShell engine and records each block after deobfuscation, immediately
before execution. Demonstrated directly:

    PS> $b = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output 'scriptblock-demo'"))
    PS> powershell.exe -EncodedCommand $b

The command line visible to EID 4688 is an opaque base64 string. EID 4104
recorded:

    Creating Scriptblock text (1 of 1):
    Write-Output 'scriptblock-demo'

A detection keyed on the command line sees the blob; one keyed on 4104 sees the
code.

### Sysmon EID 1 versus Security EID 4688

Both record process creation. Sysmon additionally provides MD5, SHA256 and
IMPHASH of the image; the parent's full command line, where 4688 gives only the
parent's name; a `ProcessGuid` that is globally unique and therefore immune to
PID reuse; signature metadata including `OriginalFileName`, which survives
renaming of the binary; and a dedicated log channel that is not competing for
retention with Security log volume.

4688's advantages are that it is native, requires no third-party kernel driver,
and is available on endpoints where installing software is not an option.

## Agent configuration

The agent was installed and enrolled in one step:

    msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER="10.10.10.10" WAZUH_AGENT_NAME="win11-victim"

The default `ossec.conf` collects four sources:

    Application
    Security
    System
    active-response\active-responses.log

Sysmon and PowerShell write to their own event channels and are not collected
unless declared. Two `<localfile>` blocks were added:

    <localfile>
      <location>Microsoft-Windows-Sysmon/Operational</location>
      <log_format>eventchannel</log_format>
    </localfile>

    <localfile>
      <location>Microsoft-Windows-PowerShell/Operational</location>
      <log_format>eventchannel</log_format>
    </localfile>

## Verification: telemetry sources checked independently

Agent status is not evidence that data is arriving. Each source was verified
separately by generating a known event on the endpoint and locating it in the
indexer.

| Source | Reaches indexer | Alerts on default ruleset |
|---|---|---|
| Sysmon EID 1 (process create) | Yes | Yes |
| Security 4688 with command line | Yes | Yes |
| Security 4720 / 4722 / 4726 (account management) | Yes | Yes |
| PowerShell 4104 (script block) | Yes | Only on suspicious content |
| Security 4624 (successful logon) | Yes | **No** |

Three findings came out of this that shape the Lab 2 coverage work.

**The distinction between a telemetry gap and a rule gap.** `wazuh-alerts-*`
contains only events that matched a rule. An empty query result therefore has
two possible causes, and they call for opposite remedies — reconfiguring
collection, or writing a detection. Querying by `providerName` rather than
`eventID` separates them: if the provider returns hits, the channel is being
collected and the gap is in the ruleset.

**4104 arrives but rarely alerts.** Benign script blocks are ingested,
evaluated, and dropped. The only 4104 alerts present in a one-day window came
from the agent's own SCA policy checks, which invoke `secedit`. A manually
generated benign script block produced no alert. Detection of PowerShell
execution therefore depends on rule content, not on collection.

**4624 does not alert at all on the default ruleset.** Over a 24-day window no
successful-logon event produced an alert, while the same Security channel
delivered 72 EID 4688 events in a single hour. This is a defensible default —
4624 volume is very high on any real endpoint — but it means out-of-box coverage
for logon-based techniques is zero.

**Account management events do alert, contrary to the assumption this lab
started with.** Creating and deleting a local account produced eight alerts
including EID 4720 and 4722, carrying `samAccountName`, `targetUserName`, and
the initiating `subjectUserName`. This was expected to be a blind spot requiring
a custom rule; measurement showed otherwise on this version with account
management auditing already enabled by default. The assumption was carried into
the lab from secondary sources and did not survive testing.

## Issues encountered

### Two telemetry sources silently absent from the agent configuration

**Symptom.** The agent enrolled, showed Active, and delivered Security log
events. Sysmon and PowerShell events, verified as present on the endpoint,
produced nothing in the indexer.

**Cause.** The default Windows `ossec.conf` collects Application, Security, and
System only. Sysmon and PowerShell write to separate event channels that must be
declared explicitly.

**Impact.** Two of four intended sources were being generated on the endpoint
and discarded. Nothing in the agent status, the service state, or the agent log
indicated a problem.

**Takeaway.** Agent health and data arrival are independent. Every source needs
an end-to-end test — generate a known event, then find that specific event in
the indexer.

### Configuration inserted twice by a repeated command

**Symptom.** After editing `ossec.conf`, the two new `<localfile>` blocks each
appeared twice.

**Cause.** A regular-expression replacement against the closing `</ossec_config>`
tag was executed more than once.

**Impact.** Duplicate `<localfile>` entries would have caused each channel to be
read twice, doubling event volume and corrupting the coverage counts that Lab 2
depends on.

**Resolution.** Restored from the backup taken before the first edit, confirmed
the location count was back to four, then re-applied using a guarded version
that checks for the string before inserting.

**Takeaway.** Configuration edits should be idempotent. The backup taken before
the first change is what made this a one-minute fix.

### Windows guest tooling is three separate packages

**Symptom.** After installing `virtio-win-gt-x64.msi`, clipboard sharing did not
work in either direction. `Get-Service *spice*, *qemu*` returned nothing.

**Cause.** That installer provides paravirtualised drivers only. The QEMU guest
agent is a separate MSI in `guest-agent\` on the same ISO, and clipboard sharing
from host to guest requires `spice-vdagent`, which ships in `spice-guest-tools`
from spice-space.org and is not on the virtio ISO at all.

**Impact.** One-directional paste, which presents as a broken clipboard rather
than as a missing component.

**Takeaway.** Full guest integration under KVM/SPICE requires all three
packages. Install them before the temporary internet connection is removed.

### Evaluation licence reported as expired at first boot

**Symptom.** The desktop watermark read "Windows License is expired" immediately
after installation.

**Cause.** The evaluation period is measured from the ISO build date, not the
installation date. The image predated its own 90-day window.

**Resolution.** None required. The counter reset to 90 days after the first
activation check. No effect on event logging, Sysmon, or agent operation.

## Endpoint snapshot

| Name | State captured |
|---|---|
| `clean-baseline` | Windows 11 patched, Sysmon, audit policy, script block logging, agent enrolled, all four sources verified |

Taken from a clean shutdown. Every attack simulation reverts to this point
first, so that detections fire on the technique under test rather than on
residue from an earlier run.

---

## Next

Lab 2 measures out-of-box detection coverage across roughly ten ATT&CK
techniques, identifies the gaps, and closes them with custom rules validated
against both a positive and a negative corpus.