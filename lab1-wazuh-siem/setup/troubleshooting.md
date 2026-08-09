# Troubleshooting Log — Lab 1

Back to [Lab 1 overview](../README.md).

Secondary issues from the build, kept in symptom → cause → impact → resolution
→ takeaway form. The highest-signal issues stay inline in
[01-siem-build.md](01-siem-build.md) and [02-endpoint-telemetry.md](02-endpoint-telemetry.md);
these round out the record.

## SIEM build

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

## Endpoint & telemetry

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

## Atomic Red Team

### Atomic Red Team dependencies on an offline host

**Symptom.** The execution framework failed to import (`powershell-yaml` not
found), individual tests failed with missing helper modules, and several
techniques could not run at all.

**Cause.** The standard ART install pulls from the internet. On the isolated
victim, the framework, the `powershell-yaml` module, and the atomics had to be
fetched, zipped, and served from the host. The `AtomicTestHarnesses`-based tests
(the `ATH` prefix) need an additional module that was not present. Process-
injection tests (T1055) require downloaded payloads or Microsoft Office, neither
available offline.

**Resolution.** Delivered the framework and its dependency over the file server
and selected only self-contained tests using built-in Windows tooling
(`powershell.exe`, `schtasks.exe`, `comsvcs.dll`). T1055 was deferred to Lab 2,
where a payload can be staged deliberately.

**Takeaway.** An isolated lab forces the same discipline as an air-gapped
production environment — every tool is staged and accounted for. It also
constrains technique selection to native tooling, which is arguably more
realistic than downloading pre-built offensive binaries.
