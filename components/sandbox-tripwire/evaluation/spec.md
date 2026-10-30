---
name: Event evaluation
summary: Matching host sensor events to decoys and the evaluate operation
kind: contract
---
# Event evaluation

This document defines the `evaluate` operation of the Sandbox Escape Tripwire: how
host sensor events hit decoys and how alerts are attributed, identified, and grouped.
Decoys and canonical locations are defined in `decoys/spec.md`; event authentication
and tamper evidence in `telemetry/spec.md`; scenario conventions in `component.md`.

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
| `sandboxes` | array | Objects with exactly `sandbox_id`, `runtime_processes` (nonempty identities of that sandbox's runtime on the host, such as the gVisor sandbox and gofer or the VMM), and `harness_processes` (identities of the agent harness on the host that drives the sandbox, possibly empty). Sandbox IDs and identities are unique. |
| `suppressions` | array | Trusted maintenance: objects with exactly `decoy_id` (in `watch`), `executable` (path), and `uid` (integer). |
| `probe`, `corroboration` | object or null | Self-test and cross-sensor checks (`telemetry/spec.md`). |
| `authentication`, `sensor_keys`, `max_clock_skew_seconds` | | Event authentication (`telemetry/spec.md`); `sensor_keys` is optional. |
| `harness_signatures` | array | Objects with exactly `harness_id` (identifier), `environment_names`, and `executables` (arrays of strings, together nonempty). |
| `window` | object | Exactly `start` and `end` timestamps, `end` not before `start`. |
| `decoy_inodes` | array | Objects with exactly `decoy_id` (a planted path decoy in `watch`), `device`, and `inode`, recorded at materialization; decoys and pairs are unique. |
| `events` | array | Host sensor observations. |

Everything except the elements of `events` is validated strictly and fails the
request. Each event is validated on its own; an invalid event is **rejected** and
recorded while the others are still evaluated, so one malformed record cannot hide a
real hit.

An event has exactly `event_id`, `time`, `received` (collector-stamped timestamp),
`source`, `sequence` (nonnegative per-source counter, or null), `action`, `target`
(string), `target_inode` (object with exactly `device` and `inode`, or null), `actor`,
and `mac` (string or null). `action` is one of `stat`, `open`, `read`, `write`, `exec`,
`delete`, `connect`, or `credential-use`. `actor` has exactly `process` (identity or
null), `ancestry` (identities, parent first, possibly empty), `executable` (path or
null), `uid` (integer or null), `comm` (string or null), `environment_names` (array of
strings or null), and `sandbox_id` (string or null).

`environment_names` carries the **names** of the process's environment variables,
never their values: sensors MUST NOT collect values. Events sharing an `event_id` are
all evaluated; the ID is listed in `duplicate_event_ids`, and each of their alert IDs
gains `#` and the event's index. `actor.comm` is self-reported, so it never influences
a decision. Sensors SHOULD record `ancestry` from the exec lineage, because a double
fork would otherwise erase a process's link to the runtime or harness.

### Hits

An accepted event **hits** a decoy in `watch` when:

- `action` is `credential-use` and the SHA-256 digest of `target` equals the decoy's
  `canary_digest`;
- the decoy is a `kernel-interface`, `action` is `write`, and `target` is a path whose
  canonical form equals its `canonical_location` (scope `exact`) or lies beneath it
  with final segment `name` (scope `name-beneath`);
- the decoy is a planted path decoy, `action` is any other action except
  `credential-use`, and either `target` is a path whose canonical form equals its
  `canonical_location`, or `target_inode` equals its `decoy_inodes` entry (catching
  hard links); or
- the decoy is an endpoint, `action` is not `credential-use`, and `target` is an
  address endpoint whose canonical form equals its `canonical_location`.

An event hits at most one decoy; one that hits nothing is **ignored**. A non-
`credential-use` hit is a **probe hit** when `probe` is not null and the event's
`actor.executable` and `actor.uid` equal the probe's; otherwise it is **suppressed** when both are non-null
and a suppression names exactly that `decoy_id`, `executable`, and `uid`. A
`credential-use` hit is never either. Every other hit is an alert.

### Attribution and verdict

Each alert is attributed by the first rule that applies:

1. `runtime`: `actor.process` equals a sandbox's runtime process. The runtime itself
   touched the decoy: a runtime file-access or overwrite flaw (2026 advisories include
   a Firecracker jailer host-file overwrite and a Cloud Hypervisor disk backing-file
   host leak), a compromised runtime, or a mis-declared exposure.
2. `harness`: `actor.process` equals a sandbox's harness process.
3. Lineage: the first identity in `actor.ancestry` that equals a runtime or harness
   process names its sandbox, with attribution `ancestry` for a runtime process (a new
   process descended from the runtime, the classic escape) and `harness` for a harness
   process (code the harness ran outside the sandbox). The nearest ancestor wins, so a
   process inside the runtime is never blamed on the harness that launched it.
4. `kernel-helper`: the first identity in `actor.ancestry` has PID 2, so the kernel
   launched the process as a user-mode helper. Hijacked helpers (`release_agent`,
   `core_pattern`, `modprobe`) are how many escapes run code as host root. The sandbox
   is unknown.
5. `sensor`: `actor.sandbox_id` names a sandbox in `sandboxes`.
6. Otherwise `sandbox_id` and `attribution` are null.

A **harness escape** needs no exploit: an artifact can persuade the agent harness to
re-run it without the sandbox, for example by reporting a fabricated sandbox
violation. Paths the harness legitimately reads on the host count as exposure when
planning.

Every alert has `severity` `critical`. The verdict is the first that applies:
`credential-exfiltrated` for `credential-use`; `harness-escape` for attribution
`harness`; `escape-attempt` for a `reachable` decoy with attribution `runtime` or
`sensor`; `runtime-mediated` for attribution `runtime`; `escape-confirmed` for
attribution `ancestry`, `kernel-helper`, or `sensor`; otherwise `host-breach`.
`techniques` is the decoy technique then `T1078` for `credential-exfiltrated`, and
otherwise `T1611` then the decoy technique, listing `T1611` once when they coincide.

### Harness identification

Knowing which agent harness drove an escape matters for response. Identification is
passive: it reads only what host sensors recorded, and never runs code on the actor's
side. When `harness_signatures` is empty, each alert's `harness` is null. Otherwise a
signature's **matches** are `env:` plus each of its `environment_names` found in
`actor.environment_names`, and `exe:` plus each of its `executables` equal to the final
segment of `actor.executable`. If exactly one signature has the most matches and that
number is positive, `harness` is `{"harness_id": ID, "matched": MATCHES, "abstained":
false}` with matches sorted; otherwise it is `{"harness_id": null, "matched": [],
"abstained": true}`. Identification is context for responders and never changes a
verdict.

### Result

The result has exactly `operation`, `deployment_id` (from `watch`), `warnings`,
`breached` (alerts nonempty), `degraded` (any of `rejected`, `duplicate_event_ids`,
`watch_gaps`, `sequence_gaps`, `uncorroborated`, or `clock_skew` nonempty), `alerts`
(ordered by `time` instant, then `event_id`, then index), `incidents`, `suppressed`
(objects with exactly `event_id`, `decoy_id`, `executable`, and `uid`, in event order),
`rejected` (objects with exactly `index` and `field`, an RFC 6901 pointer within the
event, in index order), `duplicate_event_ids` (in order of first occurrence),
`watch_gaps` (objects with exactly `decoy_id`, `from`, and `to`, in decoy order then
`from`), `sequence_gaps` (objects with exactly `source`, `after`, and `before`, by
source then `after`), `uncorroborated` (objects with exactly `event_id`, `decoy_id`,
and ascending `missing_sources`, in event order), `clock_skew` (event IDs in event
order), `probe_hits`, and `ignored` (counts).

Each alert has exactly `alert_id` (`event_id`, `/`, `decoy_id`, plus any duplicate
suffix), `event_id`, `decoy_id`, `kind`, `location`, `observed_target`, `severity`,
`verdict`, `techniques`, `sandbox_id`, `attribution`, `harness`, `executable`, `uid`,
`comm`, `time`, and `source`. Incidents group alerts by `sandbox_id`, unattributed
alerts forming one incident with null `sandbox_id`; each has exactly `sandbox_id`,
`first_seen`, `last_seen`, and `alert_ids` in alert order, ordered by `first_seen`
instant, then `sandbox_id`, with the unattributed incident last among equals.

## Requirement: Decoy contact is a critical breakout

The tripwire SHALL turn every decoy contact that is not trusted maintenance or
self-testing into a critical alert; distinguish escaped processes, harness escapes,
kernel-launched helpers, runtime-mediated contact, and escape attempts; and SHALL NOT
let a self-reported name or a reused PID change any of them.

In these scenarios `W` is the `watch` from the gVisor cloud-VM plan in
`decoys/spec.md`; `sbx-1` has runtime process `{4100, 500}` and harness process
`{3000, 400}`; times are on 2026-10-30; and actors not described are all null with
empty ancestry.

### Scenario: Escape, runtime contact, impostor, and exfiltration

- **GIVEN** `W`, `sbx-1`, and a suppression for `cloud-credentials`, executable `/usr/bin/restic`, uid 0
- **WHEN** `e1` at `12:00:00Z`: process `{4242, 900}` with ancestry `[{4100, 500}, {3000, 400}, {1, 1}]` running `/usr/bin/python3` connects to `/run/runsc-debug.sock`; `e2` at `12:01:00Z`: `/usr/bin/restic` as uid 0 reads `/home/deploy/.aws/credentials`; `e3` at `12:02:00Z`: process `{5000, 1000}` with comm `restic`, running `/tmp/.x/restic` as uid 0 with ancestry `[{4100, 777}, {1, 1}]`, reads the same file; `e4` at `12:03:00Z`: process `{4100, 500}` opens it; `e5` at `12:05:00Z`: source `cloudtrail` reports `credential-use` of `test-access-key-id`
- **THEN** the alerts are `e1/runtime-control` (`escape-confirmed`, `ancestry`, `sbx-1`, `["T1611"]`), `e3/cloud-credentials` (`host-breach`, because PID 4100 with other start ticks is a reused PID), `e4/cloud-credentials` (`runtime-mediated`, `runtime`, `sbx-1`), and `e5/cloud-credentials` (`credential-exfiltrated`, `["T1552.001", "T1078"]`)
- **AND** `suppressed` lists only `e2`, and the incidents are `sbx-1` with `e1` and `e4`, then the unattributed incident with `e3` and `e5`

### Scenario: Harness escape, identified passively

- **GIVEN** `W`, `sbx-1`, and harness signatures `claude-code` (environment name `CLAUDECODE`, executable `claude`) and `aider` (environment name `AIDER_MODEL`, executable `aider`)
- **WHEN** `h1` at `12:00:00Z`: process `{3100, 450}` with ancestry `[{3000, 400}, {1, 1}]`, running `/usr/bin/python3` with environment names `["CLAUDECODE", "HOME", "PATH"]`, reads `/home/deploy/.aws/credentials`; `h2` at `12:01:00Z`: process `{4300, 980}` with ancestry `[{4100, 500}, {3000, 400}, {1, 1}]` and environment names `["PATH"]` connects to `/run/runsc-debug.sock`
- **THEN** `h1/cloud-credentials` is `harness-escape` with attribution `harness`, sandbox `sbx-1`, and harness `{"harness_id": "claude-code", "matched": ["env:CLAUDECODE"], "abstained": false}`
- **AND** `h2/runtime-control` is `escape-confirmed` with attribution `ancestry`, because the runtime is the nearest ancestor, and its harness identification abstains

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
