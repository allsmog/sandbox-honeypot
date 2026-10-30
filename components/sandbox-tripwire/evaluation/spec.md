---
name: Event evaluation
summary: Matching host sensor events to decoys and the evaluate operation
kind: contract
---
# Event evaluation

This document defines the `evaluate` operation of the Sandbox Escape Tripwire: how
host sensor events hit decoys, how alerts are attributed and grouped, and how broken
or tampered monitoring is reported. Decoys, canonical locations, endpoints, and canary
digests are defined in `decoys/spec.md`; scenario conventions are in `component.md`.

## Operation `evaluate`

A **process identity** is an object with exactly `pid` (positive integer) and
`start_ticks` (nonnegative integer: the start time in clock ticks since boot, field 22
of `/proc/PID/stat`). Identities are equal only when both fields are, so a reused PID
never matches.

Request fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `operation` | string | `evaluate`. |
| `watch` | object | A `watch` object from a `plan` result. |
| `sandboxes` | array | Objects with exactly `sandbox_id` and `runtime_processes`: a nonempty array of the identities of that sandbox's runtime processes on the host (for example the gVisor sandbox and gofer, or the VMM). Sandbox IDs and identities are unique. |
| `suppressions` | array | Trusted maintenance: objects with exactly `decoy_id` (in `watch`), `executable` (path), and `uid` (integer). |
| `probe` | object or null | The self-test prober: exactly `executable`, `uid`, and `max_interval_seconds` (positive integer). |
| `corroboration` | object or null | Exactly `window_seconds` (positive integer) and `decoys`: objects with exactly `decoy_id` (in `watch`) and `sources` (two or more distinct sources). |
| `window` | object | Exactly `start` and `end` timestamps, `end` not before `start`. |
| `decoy_inodes` | array | Objects with exactly `decoy_id` (a planted path decoy in `watch`), `device`, and `inode` (nonnegative integers), recorded at materialization. Decoys and device-inode pairs are unique. |
| `events` | array | Host sensor observations. |

Everything except the elements of `events` is validated strictly and fails the
request. Each event is validated on its own; an invalid event is **rejected** and
recorded while the others are still evaluated, so one malformed record cannot hide a
real hit.

An event has exactly `event_id`, `time`, `source`, `sequence` (the sensor's
nonnegative per-source counter, or null), `action`, `target` (string), `target_inode`
(object with exactly `device` and `inode`, or null), and `actor`. `action` is one of
`stat`, `open`, `read`, `write`, `exec`, `delete`, `connect`, or `credential-use`.
`actor` has exactly `process` (identity or null), `ancestry` (identities, parent first,
possibly empty), `executable` (path or null), `uid` (integer or null), `comm` (string
or null), and `sandbox_id` (string or null).

Events sharing an `event_id` are all evaluated; the ID is listed in
`duplicate_event_ids`, and each of their alert IDs gains `#` and the event's index.
`actor.comm` is self-reported, so it is copied into alerts and MUST NOT influence any
decision. Sensors SHOULD record `ancestry` from the exec lineage, because a double
fork reparents a process and would erase its link to the runtime.

### Hits

An accepted event **hits** a decoy in `watch` when:

- `action` is `credential-use` and the SHA-256 digest of `target` equals the decoy's
  `canary_digest`;
- the decoy is a `kernel-interface`, `action` is `write`, and `target` is a path whose
  canonical form equals its `canonical_location` (scope `exact`) or lies beneath it
  with final segment `name` (scope `name-beneath`);
- the decoy is a planted path decoy, `action` is any other action except
  `credential-use`, and either `target` is a path whose canonical form (under
  `watch.path_aliases`) equals its `canonical_location`, or `target_inode` equals its
  `decoy_inodes` entry, which catches hard links; or
- the decoy is an endpoint, `action` is any action except `credential-use`, and
  `target` is an address endpoint whose canonical form equals its
  `canonical_location`.

An event hits at most one decoy; one that hits nothing is **ignored**. A non-
`credential-use` hit is a **probe hit** when `probe` is not null and the event's
`actor.executable` and `actor.uid` equal the probe's; otherwise it is **suppressed**
when both are non-null and a suppression names exactly that `decoy_id`, `executable`,
and `uid`. A `credential-use` hit is never either: a used canary proves exfiltration.
Every other hit is an alert.

### Attribution and verdict

Each alert is attributed by the first rule that applies:

1. `runtime`: `actor.process` equals a sandbox's runtime process. The runtime itself
   touched the decoy: a runtime file-access or overwrite flaw (2026 advisories include
   a Firecracker jailer host-file overwrite and a Cloud Hypervisor disk backing-file
   host leak), a compromised runtime, or a mis-declared exposure.
2. `ancestry`: the first identity in `actor.ancestry` equal to a runtime process names
   its sandbox. A new process descended from the runtime is the classic escape.
3. `kernel-helper`: the first identity in `actor.ancestry` has PID 2, so the kernel
   launched the process as a user-mode helper. Hijacked helpers (`release_agent`,
   `core_pattern`, `modprobe`) are how many escapes run code as host root. The sandbox
   is unknown.
4. `sensor`: `actor.sandbox_id` names a sandbox in `sandboxes`.
5. Otherwise `sandbox_id` and `attribution` are null.

Every alert has `severity` `critical`. The verdict is the first that applies:
`credential-exfiltrated` for `credential-use`; `escape-attempt` for a `reachable`
decoy with attribution `runtime` or `sensor` (the sandbox reached for the host);
`runtime-mediated` for attribution `runtime`; `escape-confirmed` for attribution
`ancestry`, `kernel-helper`, or `sensor`; otherwise `host-breach`. `techniques` is the
decoy technique then `T1078` for `credential-exfiltrated`, and otherwise `T1611` then
the decoy technique, listing `T1611` once when they coincide.

### Tamper evidence

- **Probes.** When `probe` is not null, every planted decoy is probed. For each, take
  the times of its probe hits within the window plus `window.start` and `window.end`,
  in instant order; every consecutive pair more than `max_interval_seconds` apart is a
  **watch gap**. Kernel interfaces are not probed, because writing them changes the
  host. Probes do not cover the external logs that record `credential-use`.
- **Sequences.** For each source, the distinct non-null `sequence` values of its
  accepted events, ascending: every consecutive pair `a`, `b` with `b > a + 1` is a
  **sequence gap**, revealing dropped or suppressed records.
- **Corroboration.** A kernel-level attacker can blind one sensor. For each
  non-`credential-use` hit on a decoy listed in `corroboration` whose `source` is in
  that decoy's `sources`, every other listed source MUST report a hit on the same decoy
  within `window_seconds` (inclusive); otherwise the hit is **uncorroborated**.

### Result

The result has exactly `operation`, `deployment_id` (from `watch`), `breached`
(alerts nonempty), `degraded` (any of `rejected`, `duplicate_event_ids`,
`watch_gaps`, `sequence_gaps`, or `uncorroborated` nonempty), `alerts` (ordered by
`time` instant, then `event_id`, then index), `incidents`, `suppressed` (objects with
exactly `event_id`, `decoy_id`, `executable`, and `uid`, in event order), `rejected`
(objects with exactly `index` and `field`, an RFC 6901 pointer within the event,
in index order), `duplicate_event_ids` (in order of first occurrence), `watch_gaps`
(objects with exactly `decoy_id`, `from`, and `to`, in decoy order then `from`),
`sequence_gaps` (objects with exactly `source`, `after`, and `before`, by source then
`after`), `uncorroborated` (objects with exactly `event_id`, `decoy_id`, and
`missing_sources` ascending, in event order), `probe_hits`, and `ignored` (counts).

Each alert has exactly `alert_id` (`event_id`, `/`, `decoy_id`, plus any duplicate
suffix), `event_id`, `decoy_id`, `kind`, `location`, `observed_target`, `severity`,
`verdict`, `techniques`, `sandbox_id`, `attribution`, `executable`, `uid`, `comm`,
`time`, and `source`. Incidents group alerts by `sandbox_id`, unattributed alerts
forming one incident with null `sandbox_id`; each has exactly `sandbox_id`,
`first_seen`, `last_seen`, and `alert_ids` in alert order, ordered by `first_seen`
instant, then `sandbox_id`, with the unattributed incident last among equals.

## Requirement: Decoy contact is a critical breakout

The tripwire SHALL turn every decoy contact that is not trusted maintenance or
self-testing into a critical alert, distinguish escaped processes, kernel-launched
helpers, runtime-mediated contact, and escape attempts, and SHALL NOT let a
self-reported name or a reused PID change any of them.

In these scenarios `W` is the `watch` from the gVisor cloud-VM plan, `sbx-1` has
runtime process `{4100, 500}`, times are on 2026-10-30, and actors not described are
all null with empty ancestry.

### Scenario: Escape, runtime contact, impostor, and exfiltration

- **GIVEN** `W`, `sbx-1`, and a suppression for `cloud-credentials`, executable `/usr/bin/restic`, uid 0
- **WHEN** `e1` at `12:00:00Z`: process `{4242, 900}` with ancestry `[{4100, 500}, {1, 1}]` running `/usr/bin/python3` connects to `/run/runsc-debug.sock`; `e2` at `12:01:00Z`: `/usr/bin/restic` as uid 0 reads `/home/deploy/.aws/credentials`; `e3` at `12:02:00Z`: process `{5000, 1000}` with comm `restic`, running `/tmp/.x/restic` as uid 0 with ancestry `[{4100, 777}, {1, 1}]`, reads the same file; `e4` at `12:03:00Z`: process `{4100, 500}` opens it; `e5` at `12:05:00Z`: source `cloudtrail` reports `credential-use` of `test-access-key-id`
- **THEN** the alerts are `e1/runtime-control` (`escape-confirmed`, `ancestry`, `sbx-1`, `["T1611"]`), `e3/cloud-credentials` (`host-breach`, because PID 4100 with other start ticks is a reused PID), `e4/cloud-credentials` (`runtime-mediated`, `runtime`, `sbx-1`), and `e5/cloud-credentials` (`credential-exfiltrated`, `["T1552.001", "T1078"]`)
- **AND** `suppressed` lists only `e2`, and the incidents are `sbx-1` with `e1` and `e4`, then the unattributed incident with `e3` and `e5`

### Scenario: Kernel-launched payload and tripwire write

- **GIVEN** `W` and `sbx-1`
- **WHEN** `k0`: a host process reads `/proc/sys/kernel/core_pattern`; `k1` at `12:00:00Z`: process `{6100, 950}` with ancestry `[{4100, 500}]` writes `/sys/fs/cgroup/rdma/release_agent`; `k2` at `12:00:05Z`: process `{7000, 1200}` running `/tmp/p` with ancestry `[{2, 3}]` reads `/home/deploy/.aws/credentials`
- **THEN** `k0` is ignored, `k1/cgroup-release-agent` is `escape-confirmed` with attribution `ancestry`, and `k2/cloud-credentials` is `escape-confirmed` with attribution `kernel-helper` and a null sandbox

### Scenario: Sandbox reaching for host SSH

- **GIVEN** `W` and `sbx-1`
- **WHEN** a flow sensor reports `g1` connecting to `172.17.0.1:22` with `actor.sandbox_id` `sbx-1`
- **THEN** `g1/gateway-ssh` is `escape-attempt` with attribution `sensor` and techniques `["T1611", "T1021.004"]`

### Scenario: Alias path and simultaneous alerts

- **GIVEN** `W` and `sbx-1`
- **WHEN** `a2` reads `/home/deploy/.aws/credentials`, and `a1`, with `actor.sandbox_id` `sbx-1`, connects to `/var/run/runsc-debug.sock`, both at `12:00:00Z`
- **THEN** `a1/runtime-control` (attribution `sensor`) precedes `a2/cloud-credentials`, and the `sbx-1` incident precedes the unattributed incident

### Scenario: Endpoint spelling and hard link

- **GIVEN** the `watch` from the Kubernetes node plan and a decoy inode for `ssh-private-key` of device 2049, inode 1234
- **WHEN** `n1` connects to `[::ffff:169.254.169.254]:80` and `n2` reads `/tmp/k` with target inode device 2049, inode 1234
- **THEN** the alerts are `n1/metadata-endpoint` and `n2/ssh-private-key`, both `host-breach`

## Requirement: Malformed, missing, or tampered telemetry is visible

The tripwire SHALL keep evaluating valid events when others are malformed or
duplicated, and SHALL report decoys whose monitoring stops working, dropped records,
and contacts that an independent sensor did not confirm.

### Scenario: One malformed event

- **GIVEN** `W`
- **WHEN** the first event's `time` is `2026-10-30 12:00` and a second, valid event connects to `/run/runsc-debug.sock`
- **THEN** the second still alerts, `rejected` is `[{"index": 0, "field": "/time"}]`, and `degraded` and `breached` are true

### Scenario: Duplicate event IDs

- **GIVEN** `W`
- **WHEN** two events at the same instant both have ID `x`; the first reads `/home/deploy/.aws/credentials` and the second connects to `/run/runsc-debug.sock`
- **THEN** the alert IDs are `x/cloud-credentials#0` and `x/runtime-control#1`, `duplicate_event_ids` is `["x"]`, and `degraded` is true

### Scenario: Broken decoy monitoring

- **GIVEN** `W`, window `12:00:00Z` to `13:00:00Z`, and probe `/usr/libexec/tripwire-probe` as uid 0 every 600 seconds
- **WHEN** the probe reads `/home/deploy/.aws/credentials` and connects to `127.0.0.1:2375` and `172.17.0.1:22` at `12:00`, `12:10`, `12:20`, `12:30`, `12:40`, and `12:50`, but connects to `/run/runsc-debug.sock` only at `12:00` and `12:05`
- **THEN** `watch_gaps` is only `runtime-control` from `2026-10-30T12:05:00Z` to `2026-10-30T13:00:00Z`, `probe_hits` is 20, `alerts` is empty, and `degraded` is true

### Scenario: Dropped records

- **WHEN** source `fanotify` reports accepted events with sequences 1, 2, and 5
- **THEN** `sequence_gaps` is `[{"source": "fanotify", "after": 2, "before": 5}]` and `degraded` is true

### Scenario: Blinded sensor

- **GIVEN** `W` and corroboration of `runtime-control` by sources `ebpf` and `fanotify` within 5 seconds
- **WHEN** only source `ebpf` reports event `b1` connecting to `/run/runsc-debug.sock`
- **THEN** `b1/runtime-control` still alerts, `uncorroborated` is `[{"event_id": "b1", "decoy_id": "runtime-control", "missing_sources": ["fanotify"]}]`, and `degraded` is true
