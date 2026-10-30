---
name: Event evaluation
summary: Matching host sensor events to decoys and the evaluate operation
kind: contract
---
# Event evaluation

This document defines the `evaluate` operation of the Sandbox Escape Tripwire: how
host sensor events hit decoys, how alerts are attributed and grouped, and how sensor
health is reported. Decoys, canonical locations, and canary digests are defined in
`decoys/spec.md`.

## Operation `evaluate`

Request fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `operation` | string | `evaluate`. |
| `watch` | object | A `watch` object from a `plan` result. |
| `sandboxes` | array | Objects with exactly `sandbox_id` and `host_pids`: the host process IDs of that sandbox's runtime (for example the gVisor sandbox and gofer processes or the Firecracker VMM). IDs and PIDs are unique across sandboxes. |
| `suppressions` | array | Known maintenance access: objects with exactly `decoy_id`, `executable`, and `uid`. |
| `window` | object | Exactly `start` and `end` timestamps, with `end` not before `start`. |
| `sensors` | array | Objects with exactly `source` and `max_silence_seconds` (positive integer); sources are unique. |
| `events` | array | Host sensor observations. |

Everything except the elements of `events` is validated strictly and fails the
request. Each event is validated on its own; an invalid event is **rejected** and
recorded, and the remaining events are still evaluated, so one malformed sensor
record cannot hide a real hit.

An event has exactly `event_id`, `time` (timestamp), `source`, `action`, `target`
(string), and `actor`. `action` is one of `open`, `read`, `write`, `exec`, `delete`,
`connect`, `credential-use`, or `heartbeat`. `actor` has exactly `pid` (integer or
null), `ancestry` (array of integer PIDs, parent first, possibly empty),
`executable` (path or null), `uid` (integer or null), `process` (string or null), and
`sandbox_id` (string or null). An event whose `event_id` repeats an earlier accepted
event is rejected at `/event_id`.

`actor.process` is the self-reported process name. Because any process can set its
own name, it is copied into alerts for context and MUST NOT influence any decision.

### Hits

An accepted event **hits** a placed decoy when:

- `action` is `credential-use` and the SHA-256 digest of `target` equals the decoy's
  `canary_digest`; or
- `action` is `open`, `read`, `write`, `exec`, `delete`, or `connect`, and either the
  decoy is a path decoy and `target` is a path whose canonical form (under
  `watch.path_aliases`) equals the decoy's `canonical_location`, or the decoy is an
  endpoint decoy and `target` equals its `location`.

Canonical locations and identifiers are unique, so an event hits at most one decoy.
`heartbeat` events never hit. An accepted, non-heartbeat event that hits nothing is
**ignored**.

A hit is **suppressed** when its action is not `credential-use`, the event's
`actor.executable` and `actor.uid` are both non-null, and a suppression names exactly
that `decoy_id`, `executable`, and `uid`. A `credential-use` hit is never suppressed:
a used canary proves exfiltration regardless of who touched the file. Every other hit
is an alert.

### Attribution and verdict

An alert is attributed to a sandbox by process ancestry first: walk `actor.pid` then
`actor.ancestry` in order, and the first PID found in a sandbox's `host_pids` names
that sandbox (`attribution` is `ancestry`). Otherwise, when `actor.sandbox_id` names a
sandbox in `sandboxes`, that sandbox is used (`attribution` is `sensor`). Otherwise
`sandbox_id` and `attribution` are null.

Every alert has `severity` `critical`; attribution adds context but never lowers it.

| Condition | `verdict` | `techniques` |
| --- | --- | --- |
| `credential-use` | `credential-exfiltrated` | decoy technique, then `T1078` |
| attributed to a sandbox | `escape-confirmed` | `T1611`, then decoy technique |
| otherwise | `host-breach` | `T1611`, then decoy technique |

When the decoy technique is itself `T1611`, `techniques` lists it once.

### Sensor health

For each declared sensor, take the times of accepted events (of any action) from that
`source` that lie within the window, plus `window.start` and `window.end`, in instant
order. Every consecutive pair more than `max_silence_seconds` apart is a gap. Events
outside the window are still evaluated for hits but never close a gap.

### Result

The result has exactly these fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `operation` | string | `evaluate`. |
| `deployment_id` | string | From `watch`. |
| `breached` | boolean | True when `alerts` is nonempty. |
| `degraded` | boolean | True when `rejected` or `sensor_gaps` is nonempty. |
| `alerts` | array | Ordered by `time` instant, then `event_id`. |
| `incidents` | array | Alerts grouped by sandbox. |
| `suppressed` | array | Objects with exactly `event_id`, `decoy_id`, `executable`, and `uid`, in event order. |
| `rejected` | array | Objects with exactly `index` (position in `events`) and `field` (RFC 6901 pointer within that event, `""` for the whole event), in index order. |
| `sensor_gaps` | array | Objects with exactly `source`, `from`, and `to`, ordered by `source` then `from` instant. |
| `ignored` | integer | Count of ignored events. |

Each alert has exactly `alert_id` (`event_id`, `/`, `decoy_id`), `event_id`,
`decoy_id`, `kind`, `location` (the decoy's), `observed_target` (the event's
`target`), `severity`, `verdict`, `techniques`, `sandbox_id`, `attribution`,
`executable`, `uid`, `process`, `time`, and `source`.

Alerts are grouped into one incident per distinct `sandbox_id`, with all unattributed
alerts forming one incident whose `sandbox_id` is null. Each incident has exactly
`sandbox_id`, `first_seen`, `last_seen` (the member `time` values denoting the
earliest and latest instants), and `alert_ids` in alert order. Incidents are ordered
by `first_seen` instant, then `sandbox_id` ascending, with the unattributed incident
last among equal instants.

