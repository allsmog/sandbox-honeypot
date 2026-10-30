---
name: Event evaluation
summary: The evaluate request, event shape, hits, and result
kind: contract
---
# Event evaluation

This document defines the `evaluate` request, the shape of host sensor events, which
events hit which decoys, and the result. Attribution, verdicts, and harness
identification are in `attribution/spec.md`; authentication, batching, and tamper
evidence in `telemetry/spec.md`; scenario conventions in `component.md`.

## Request

A **process identity** is an object with exactly `pid` (positive integer: the PID in
the initial PID namespace) and `start_ticks` (nonnegative integer: the start time in
`USER_HZ` clock ticks since boot, as in field 22 of `/proc/PID/stat`). Identities are
equal only when both fields are, so a reused PID never matches.

| Field | Type | Meaning |
| --- | --- | --- |
| `operation` | string | `evaluate`. |
| `watch` | object | A `watch` object from a `plan` result. |
| `sandboxes` | array | Objects with exactly `sandbox_id`, `runtime_processes` (nonempty identities of that sandbox's runtime on the host, such as the gVisor sandbox and gofer or the VMM), and `harness_processes` (identities of the agent harness that drives it, possibly empty). Sandbox IDs and identities are unique. |
| `suppressions` | array | Trusted maintenance: objects with exactly `decoy_id` (in `watch.decoys`), `executable` (path), `executable_digest` (64 lowercase hex: SHA-256 of the executable file), `uid` (integer), and `value_digest` (64 lowercase hex for a kernel interface, null otherwise). |
| `expected_helpers` | array of strings | Paths of executables the kernel legitimately launches as user-mode helpers, such as `/sbin/modprobe`. |
| `harness_signatures` | array | See `attribution/spec.md`. |
| `probe`, `corroboration`, `expected_sources`, `authentication`, `sensor_keys`, `max_clock_skew_seconds`, `carry` | | See `telemetry/spec.md`; `sensor_keys` is optional. |
| `window` | object | Exactly `start` and `end` timestamps, `end` not before `start`; both bounds are inclusive. |
| `decoy_inodes` | array | Objects with exactly `decoy_id` (a placed planted path decoy), `device` (the `st_dev` value `stat(2)` returns), and `inode` (`st_ino`), recorded at materialization; decoys and pairs are unique. |
| `events` | array | Host sensor observations. |

Everything except the elements of `events` is validated strictly and fails the
request.

## Events

An event has exactly these fields. The first nine are **core**; the rest are
**detail**.

| Field | Type | Meaning |
| --- | --- | --- |
| `event_id` | string | Sensor-assigned identifier. |
| `deployment_id` | string | MUST equal `watch.deployment_id`. |
| `time` | timestamp | When the sensor observed the action; MUST lie in the window. |
| `received` | timestamp | Stamped on arrival by the collector, never by the sensor. |
| `source` | string | The sensor. |
| `sensor_instance` | string | Identifies one run of the sensor, such as a boot ID plus start time. |
| `action` | string | One of the actions below. |
| `target` | string | What was acted on (see Hits). |
| `mac` | string or null | See `telemetry/spec.md`. |
| `sequence` | integer or null | The sensor's per-instance counter. |
| `target_inode` | object or null | Exactly `device` and `inode`, encoded as in `decoy_inodes`. |
| `target_fs` | object or null | Exactly `type` (filesystem type, such as `proc` or `cgroup`) and `path` (path within that filesystem, without a leading `/`). |
| `written_digest` | string or null | SHA-256 (64 lowercase hex) of the bytes written, for writes. |
| `actor` | object | Exactly `process` (identity or null), `ancestry` (identities, parent first, from the exec lineage, possibly empty), `executable` (path or null), `executable_digest` (64 lowercase hex or null), `uid` (integer or null), `comm` (string or null), `environment_names` (array of at most 256 strings or null), and `sandbox_id` (string or null). |

Actions are `stat`, `open` (read-only), `open-write`, `read`, `write`, `truncate`,
`exec`, `delete`, `rename`, `link`, `attr` (a change of mode, owner, extended
attribute, or timestamps), `connect`, `credential-use`, and `heartbeat` (a sensor
liveness record, which never hits).

Sensors MUST report a path `target` as the kernel-resolved absolute path of the object
in the initial mount namespace (as `d_path` gives), never the path argument the process
supplied, and MUST encode text as UTF-8, replacing each invalid byte with U+FFFD.
`environment_names` holds variable **names** only: sensors MUST NOT collect values.

An event with an invalid core field is **rejected** and recorded at the first invalid
field. An event with a valid core but an invalid detail field is evaluated with that
field treated as null (`actor` fields individually; `ancestry` as empty) and recorded
in `repaired`, so a crafted file name or environment cannot turn an attacker's own hit
into a rejection. Events sharing an `event_id` are all evaluated; the ID is listed in
`duplicate_event_ids`, and each of their alert IDs gains `#` and the event's index.

## Hits

For matching, the canonical form of an endpoint target also rewrites `0.0.0.0` to
`127.0.0.1` and `[::]` to `[::1]`, the loopback addresses Linux connects them to. An
accepted event **hits** a decoy when:

- `action` is `credential-use` and the SHA-256 of `target` equals a decoy's
  `canary_digest` or a `watch.retired` digest (the alert then uses the retired entry's
  `decoy_id` and `technique`);
- the decoy is a `kernel-interface`, `action` is `open-write`, `write`, or `truncate`,
  and either `target` is a path whose canonical form equals its `canonical_location`
  (scope `exact`) or lies beneath it with final segment `name` (scope `name-beneath`),
  or `target_fs.type` equals its `fs_type` and `target_fs.path` equals its `fs_path`
  (or, for scope `name-beneath`, has final segment `name`);
- the decoy is `helper-exec`, `action` is `exec`, some identity in `actor.ancestry`
  has PID 2 (so the kernel launched the lineage as a user-mode helper), and
  `actor.executable` is not in `expected_helpers`;
- the decoy is a planted path decoy, `action` is any action except `credential-use`
  and `heartbeat`, and either `target` is a path whose canonical form equals its
  `canonical_location` or one of its `companion_paths`, or `target_inode` equals its
  `decoy_inodes` entry (catching hard links); or
- the decoy is an endpoint, `action` is any action except `credential-use` and
  `heartbeat`, and `target` is an address endpoint whose canonical form equals its
  `canonical_location`.

When several decoys match, the first in `watch.decoys` order wins, then retired
entries in order, with a path match preferred over an inode match. An accepted
non-`heartbeat` event that hits nothing is **ignored**. A rejected event whose `target`,
with repeated `/` collapsed and `.` and `..` segments resolved, equals a planted
decoy's canonical location or companion path is also listed in `rejected_hits`, since
a malformed event on a decoy needs investigation.

A hit is a **probe hit** when `probe` is not null, the decoy is planted, the action is
`stat`, `open`, `read`, or `connect`, and the actor's `executable`,
`executable_digest`, and `uid` equal the probe's. Otherwise it is **suppressed** when a
suppression names its `decoy_id` and the actor's non-null `executable`,
`executable_digest`, and `uid`, and, for a kernel interface, the event's
`written_digest` equals the suppression's `value_digest`; a maintenance tool writing an
unexpected value still alerts. `credential-use` and `helper-exec` hits are never probe
hits or suppressed. Every other hit is an alert.

## Result

The result has exactly these fields:

| Field | Meaning |
| --- | --- |
| `operation`, `deployment_id` | `evaluate`, and `watch.deployment_id`. |
| `warnings` | In this order, each when applicable: `keys-in-request`, `unauthenticated`. |
| `breached` | True when `alerts` is nonempty. |
| `degraded` | True when any of `rejected`, `repaired`, `rejected_hits`, `duplicate_event_ids`, or the tamper lists in `telemetry/spec.md` is nonempty. |
| `alerts` | Ordered by `time` instant, then `event_id` (by Unicode code point), then index. |
| `incidents` | Alerts grouped by sandbox. |
| `suppressed` | Objects with exactly `event_id` and `decoy_id`, in event order. |
| `rejected`, `repaired` | Objects with exactly `index` and `field` (an RFC 6901 pointer within the event), in index then field order. |
| `rejected_hits` | Indexes in ascending order. |
| `duplicate_event_ids` | In order of first occurrence. |
| tamper lists | `watch_gaps`, `sequence_gaps`, `sequence_duplicates`, `sensor_restarts`, `silence_gaps`, `uncorroborated`, and `clock_skew` (`telemetry/spec.md`). |
| `carry` | State for the next batch (`telemetry/spec.md`). |
| `probe_hits`, `ignored` | Counts. |

Each alert has exactly `alert_id` (`event_id`, `/`, `decoy_id`, plus any duplicate
suffix), `event_id`, `decoy_id`, `kind`, `location`, `observed_target`, `severity`,
`verdict`, `techniques`, `sandbox_id`, `attribution`, `harness`, `executable`, `uid`,
`comm`, `time`, and `source`. Incidents group alerts by `sandbox_id`, unattributed
alerts forming one incident with null `sandbox_id`; each has exactly `sandbox_id`,
`first_seen`, `last_seen`, and `alert_ids` in alert order, ordered by `first_seen`
instant, then `sandbox_id` by code point, with the unattributed incident last among
equals. Timestamps are echoed exactly as received.
