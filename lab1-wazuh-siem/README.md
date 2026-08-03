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

## Next

Lab 1 continues with the Windows 11 victim endpoint: Sysmon with the
SwiftOnSecurity configuration, advanced audit policy including command-line
process auditing, PowerShell script block logging, and Wazuh agent enrolment —
with each telemetry source verified as arriving in the indexer independently
before proceeding.