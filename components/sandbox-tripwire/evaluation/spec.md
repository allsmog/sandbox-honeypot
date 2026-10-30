---
name: Event evaluation
summary: The evaluate request, event shape, hits, and result
kind: contract
---
# Event evaluation

This document defines the `evaluate` request, the shape of host sensor events, which
events hit which decoys, and the result. Attribution, verdicts, and harness
identification are in `attribution/spec.md`; sources, authentication, batching, and
tamper evidence in `telemetry/spec.md`; scenario conventions in `component.md`.

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
| `expected_helpers` | array | Executables the kernel legitimately launches as user-mode helpers: objects with exactly `path` and `digest` (SHA-256 of that file, which for a script is the script, not its interpreter). |
| `ignore_stat` | array of strings | Planted path decoys in `watch.decoys` for which `stat` is not a hit, where people routinely list the directory. |
| `harness_signatures` | array | See `attribution/spec.md`. |
| `sources`, `probe`, `corroboration`, `authentication`, `sensor_keys`, `max_clock_skew_seconds`, `carry` | | See `telemetry/spec.md`; `sensor_keys` is optional. |
| `window` | object | Exactly `start` and `end` timestamps, `end` after `start`. It contains the events **received** from `start` (inclusive) to `end` (exclusive). |
| `decoy_inodes` | array | Objects with exactly `decoy_id` (a placed planted path decoy), `path` (its canonical location or one of its `companion_paths`), `device` (the `st_dev` value `stat(2)` returns), and `inode` (`st_ino`), recorded whenever decoys are materialized. Paths and device-inode pairs are unique. |
| `events` | array | Host sensor observations. |

Everything except the elements of `events` is validated strictly and fails the
request.

## Events

An event has exactly these fields. The first ten are **core**; the rest are
**detail**. Identifiers are at most 256 characters, paths and targets at most 4096
UTF-8 bytes, `ancestry` at most 64 entries, and `environment_names` at most 256 names
of at most 256 bytes each; sensors truncate longer values to these limits.

| Field | Type | Meaning |
| --- | --- | --- |
| `event_id` | string | Sensor-assigned identifier. |
| `deployment_id` | string | MUST equal `watch.deployment_id`. |
| `time` | timestamp | When the action was observed. |
| `received` | timestamp | Stamped on arrival by the collector, never by the sensor; MUST lie in the window. |
| `source` | string | A source declared in `sources`. |
| `sensor_instance` | string | Identifies one run of the signer, such as a boot ID plus start time. |
| `sequence` | integer | The signer's counter for this instance, incremented for every event it ships. |
| `action` | string | One of the actions below. |
| `target` | string | What was acted on (see Hits). |
| `mac` | string or null | See `telemetry/spec.md`. |
| `target_inode` | object or null | Exactly `device` and `inode`, encoded as in `decoy_inodes`. |
| `target_fs` | object or null | Exactly `type` (filesystem type, such as `proc` or `cgroup`) and `path` (path within that filesystem, without a leading `/`). |
| `target_digest` | string or null | For `exec`, the SHA-256 of the executed file. |
| `written_digest` | string or null | For `write`, the SHA-256 of the bytes passed to that one `write(2)` call. |
| `actor` | object | Exactly `process` (identity or null), `ancestry` (identities of the creation chain recorded when each process was created, parent first, including kernel threads and unaffected by later reparenting), `helper_depth` (0 when the kernel started this process as a user-mode helper, `n` when its `n`th ancestor was, otherwise null), `executable` (path or null), `executable_digest` (64 lowercase hex or null), `uid` (effective user ID or null), `comm` (string or null), `environment_names` (array of strings or null), and `sandbox_id` (string or null). |

Actions are `stat` (also `access`, `readlink`, and extended-attribute reads), `open`
(read-only), `open-write`, `read`, `write`, `truncate`, `exec`, `delete`, `rename`,
`link`, `attr` (changes of mode, owner, extended attributes, or timestamps),
`connect`, `credential-use`, and `heartbeat` (a liveness record, which never hits).
fanotify cannot observe `stat`, failed opens, or socket `connect`; sensors SHOULD use
eBPF or LSM hooks, which observe every action.

Sensors MUST report a path `target` as the kernel-resolved absolute path of the object
in the initial mount namespace (as `d_path` gives); when the object has no such path,
as in a private mount namespace, they report the path within the actor's namespace and
MUST supply `target_inode`. Text is UTF-8 with each invalid byte replaced by U+FFFD.
`environment_names` holds variable **names** only: sensors MUST NOT collect values.

An event with an invalid core field is **rejected** and recorded at the first invalid
field. An event with a valid core but an invalid detail field is evaluated with that
field treated as null (`actor` fields individually; `ancestry` as empty) and recorded
in `repaired`, so a crafted file name or environment cannot turn an attacker's own hit
into a rejection. Events sharing an `event_id` are all evaluated; the ID is listed in
`duplicate_event_ids`, and each of their alert IDs gains `#` and the event's index.

## Hits

For matching, a path target is canonicalized under `watch.path_aliases`, and an
endpoint target is canonicalized with `0.0.0.0` rewritten to `127.0.0.1` and `[::]` to
`[::1]`, the loopback addresses Linux connects them to. An accepted event **hits**:

- any decoy or `watch.retired` entry whose `canary_digest` equals the SHA-256 of
  `target`, when `action` is `credential-use`;
- a `kernel-interface` decoy, when `action` is `open-write`, `write`, or `truncate`
  and either the canonical target equals its `canonical_location` (scope `exact`) or
  lies beneath it with final segment `name` (scope `name-beneath`), or `target_fs.type`
  equals its `fs_type` and `target_fs.path` equals its `fs_path` (scope `exact`) or has
  final segment `name` (scope `name-beneath`);
- `helper-exec`, when `action` is `exec`, `actor.helper_depth` is 0, and no expected
  helper has `path` equal to the canonical target and `digest` equal to
  `target_digest`;
- a planted path decoy, when `action` is any action except `credential-use` and
  `heartbeat` (and `stat` for decoys in `ignore_stat`), and either `target_inode`
  equals a `decoy_inodes` entry of that decoy (catching hard links and bind mounts) or
  the canonical target equals its `canonical_location` or one of its
  `companion_paths`; or
- an endpoint decoy, when `action` is `connect` and the canonical target equals its
  `canonical_location`.

An event hits at most one decoy: inode matches take precedence over path matches,
then the first matching decoy in `watch.decoys` order, then retired entries in order.
An accepted non-`heartbeat` event that hits nothing is **ignored**. The same matching,
applied to whatever fields of a rejected event parse, lists it in `rejected_hits`
(`index` and `decoy_id`), because a malformed or forged event on a decoy needs
investigation. When a placed planted path decoy or one of its companions has no
`decoy_inodes` entry, the result warns `missing-inode-binding`.

A hit is a **probe hit** when `probe` is not null, the decoy is planted, the action is
`stat`, `open`, `read`, or `connect`, and the actor's `executable`,
`executable_digest`, and `uid` equal the probe's. Otherwise it is **suppressed** when a
suppression names its `decoy_id` and the actor's non-null `executable`,
`executable_digest`, and `uid`, and, for a `write` to a kernel interface, the event's
`written_digest` equals the suppression's `value_digest`, so a maintenance tool
writing an unexpected value still alerts. `credential-use` and `helper-exec` hits are
never probe hits or suppressed. Every other hit is an alert.

## Result

| Field | Meaning |
| --- | --- |
| `operation`, `deployment_id` | `evaluate`, and `watch.deployment_id`. |
| `warnings` | In this order, each when applicable: `keys-in-request`, `unauthenticated`, `missing-inode-binding`. |
| `breached` | True when `alerts` is nonempty. |
| `degraded` | True when any of `rejected`, `repaired`, `rejected_hits`, `duplicate_event_ids`, or the tamper lists in `telemetry/spec.md` is nonempty. |
| `alerts` | Ordered by `time` instant, then `event_id`, then index. |
| `incidents` | Alerts grouped by sandbox. |
| `suppressed` | Objects with exactly `event_id` and `decoy_id`, in event order. |
| `rejected`, `repaired` | Objects with exactly `index` and `field` (an RFC 6901 pointer within the event), ordered by index then field. |
| `rejected_hits` | Objects with exactly `index` and `decoy_id`, in index order. |
| `duplicate_event_ids` | In order of first occurrence. |
| tamper lists | Defined in `telemetry/spec.md`. |
| `carry` | State for the next batch (`telemetry/spec.md`). |
| `probe_hits`, `ignored` | Counts. |

Each alert has exactly `alert_id` (`event_id`, `/`, `decoy_id`, plus any duplicate
suffix), `event_id`, `decoy_id`, `kind`, `location` (null for a retired entry),
`observed_target` (the event's `target`, but null for `credential-use`, so a credential
never reaches alert storage), `severity`, `verdict`, `techniques`, `sandbox_id`,
`attribution`, `harness`, `executable`, `uid`, `comm`, `time`, and `source`. Incidents
group alerts by `sandbox_id`, unattributed alerts forming one incident with null
`sandbox_id`; each has exactly `sandbox_id`, `first_seen`, `last_seen`, and `alert_ids`
in alert order, ordered by `first_seen` instant, then `sandbox_id`, with the
unattributed incident last among equals. Timestamps are echoed exactly as received.
