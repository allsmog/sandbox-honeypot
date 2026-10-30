---
name: Event evaluation
summary: Matching host sensor events to decoys and the evaluate operation
kind: contract
---
# Event evaluation

This document defines the `evaluate` operation of the Sandbox Escape Tripwire: how
host sensor events hit decoys, how alerts are attributed and grouped, and how broken
monitoring is reported. Decoys, canonical locations, endpoints, and canary digests are
defined in `decoys/spec.md`.

## Operation `evaluate`

A **process identity** is an object with exactly `pid` (positive integer) and
`start_ticks` (nonnegative integer: the process start time in clock ticks since boot,
as in field 22 of `/proc/PID/stat`). Two identities are equal only when both fields
are equal, so a reused PID never matches.

Request fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `operation` | string | `evaluate`. |
| `watch` | object | A `watch` object from a `plan` result. |
| `sandboxes` | array | Objects with exactly `sandbox_id` and `runtime_processes`: a nonempty array of the process identities of that sandbox's runtime on the host (for example the gVisor sandbox and gofer processes, or the Firecracker VMM). Sandbox IDs and process identities are unique across sandboxes. |
| `suppressions` | array | Known maintenance access: objects with exactly `decoy_id` (a decoy in `watch`), `executable` (path), and `uid` (integer). |
| `probe` | object or null | The self-test prober: exactly `executable` (path), `uid` (integer), and `max_interval_seconds` (positive integer). |
| `window` | object | Exactly `start` and `end` timestamps, with `end` not before `start`. |
| `decoy_inodes` | array | Objects with exactly `decoy_id` (a path decoy in `watch`), `device`, and `inode` (nonnegative integers), recorded when decoys are materialized. Decoys and device-inode pairs are unique. |
| `events` | array | Host sensor observations. |

Everything except the elements of `events` is validated strictly and fails the
request. Each event is validated on its own; an invalid event is **rejected** and
recorded, and the remaining events are still evaluated, so one malformed sensor
record cannot hide a real hit.

An event has exactly `event_id`, `time` (timestamp), `source`, `action`, `target`
(string), `target_inode` (object with exactly `device` and `inode`, or null), and
`actor`. `action` is one of `open`, `read`, `write`, `exec`, `delete`, `connect`, or
`credential-use`. `actor` has exactly `process` (process identity or null),
`ancestry` (array of process identities, parent first, possibly empty), `executable`
(path or null), `uid` (integer or null), `comm` (string or null), and `sandbox_id`
(string or null).

Event IDs SHOULD be unique. Events sharing an `event_id` are all evaluated; that ID is
listed in `duplicate_event_ids`, and each of their alert IDs gains the suffix `#` and
the event's index in `events`.

`actor.comm` is the self-reported process name. Because any process can set its own
name, it is copied into alerts for context and MUST NOT influence any decision.

Sensors SHOULD record `ancestry` from the exec lineage rather than the current parent,
because a double fork reparents a process to PID 1 or a subreaper and would otherwise
erase its link to the runtime.

### Hits

An accepted event **hits** a placed decoy when:

- `action` is `credential-use` and the SHA-256 digest of `target` equals the decoy's
  `canary_digest`; or
- `action` is `open`, `read`, `write`, `exec`, `delete`, or `connect`, and the decoy is
  a path decoy and either `target` is a path whose canonical form (under
  `watch.path_aliases`) equals the decoy's `canonical_location` or `target_inode`
  equals the decoy's `decoy_inodes` entry, which catches hard links; or the decoy is an
  endpoint decoy and `target` is an address endpoint whose canonical form equals the
  decoy's `canonical_location`.

An event hits at most one decoy. An accepted event that hits nothing is **ignored**.
A target that is neither a valid path nor a valid endpoint simply hits nothing.

A hit that is not `credential-use` is a **probe hit** when `probe` is not null and the
event's `actor.executable` and `actor.uid` equal the probe's. Otherwise it is
**suppressed** when `actor.executable` and `actor.uid` are both non-null and a
suppression names exactly that `decoy_id`, `executable`, and `uid`. A
`credential-use` hit is never a probe hit or suppressed: a used canary proves
exfiltration regardless of who touched the file. Every other hit is an alert.

### Attribution and verdict

Each alert is attributed by the first rule that applies:

1. `runtime`: `actor.process` equals a runtime process of a sandbox. The runtime itself
   touched the decoy, usually on the guest's behalf: either the declared exposure is
   wrong or the runtime is compromised.
2. `ancestry`: the first identity in `actor.ancestry` that equals a runtime process
   names its sandbox. A new process descended from the runtime is the classic escape.
3. `sensor`: `actor.sandbox_id` names a sandbox in `sandboxes`.
4. Otherwise `sandbox_id` and `attribution` are null.

Every alert has `severity` `critical`; attribution adds context but never lowers it.

| Condition (first match) | `verdict` | `techniques` |
| --- | --- | --- |
| `credential-use` | `credential-exfiltrated` | decoy technique, then `T1078` |
| attribution `runtime` | `runtime-mediated` | `T1611`, then decoy technique |
| attribution `ancestry` or `sensor` | `escape-confirmed` | `T1611`, then decoy technique |
| otherwise | `host-breach` | `T1611`, then decoy technique |

When the decoy technique is itself `T1611`, `techniques` lists it once.

### Self-test probes

A heartbeat only proves a sensor process is alive. A probe proves the whole path from
decoy to `evaluate` works. When `probe` is not null, every placed decoy is probed: for
each decoy, take the times of its probe hits within the window, plus `window.start`
and `window.end`, in instant order. Every consecutive pair more than
`max_interval_seconds` apart is a **watch gap** for that decoy. Probe hits outside the
window never close a gap. Probes cover file, socket, and endpoint monitoring, not the
external logs that record `credential-use`.

### Result

The result has exactly these fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `operation` | string | `evaluate`. |
| `deployment_id` | string | From `watch`. |
| `breached` | boolean | True when `alerts` is nonempty. |
| `degraded` | boolean | True when `rejected`, `duplicate_event_ids`, or `watch_gaps` is nonempty. |
| `alerts` | array | Ordered by `time` instant, then `event_id`, then event index. |
| `incidents` | array | Alerts grouped by sandbox. |
| `suppressed` | array | Objects with exactly `event_id`, `decoy_id`, `executable`, and `uid`, in event order. |
| `rejected` | array | Objects with exactly `index` (position in `events`) and `field` (RFC 6901 pointer within that event, `""` for the whole event), in index order. |
| `duplicate_event_ids` | array of strings | Each repeated event ID once, in order of first occurrence. |
| `watch_gaps` | array | Objects with exactly `decoy_id`, `from`, and `to`, in decoy order then `from` instant. |
| `probe_hits` | integer | Count of probe hits. |
| `ignored` | integer | Count of ignored events. |

Each alert has exactly `alert_id` (`event_id`, `/`, `decoy_id`, plus any duplicate
suffix), `event_id`, `decoy_id`, `kind`, `location` (the decoy's), `observed_target`
(the event's `target`), `severity`, `verdict`, `techniques`, `sandbox_id`,
`attribution`, `executable`, `uid`, `comm`, `time`, and `source`.

Alerts are grouped into one incident per distinct `sandbox_id`, with all unattributed
alerts forming one incident whose `sandbox_id` is null. Each incident has exactly
`sandbox_id`, `first_seen`, `last_seen` (the member `time` values denoting the
earliest and latest instants), and `alert_ids` in alert order. Incidents are ordered
by `first_seen` instant, then `sandbox_id` ascending, with the unattributed incident
last among equal instants.
