---
name: Telemetry integrity
summary: Sources, authenticated events, batching, and evidence of tampered monitoring
kind: contract
---
# Telemetry integrity

This document defines which sensor events `evaluate` trusts, how consecutive batches
connect, and how broken, dropped, delayed, or tampered monitoring is reported. Event
shape and hits are in `evaluation/spec.md`; scenario conventions are in
`component.md`.

## Sources

`sources` declares every source: objects with exactly `source`, `signer` (`sensor` when
the sensor signs its own events, `collector` when the off-host collector signs on its
behalf, as for cloud audit trails, SSH logs, and token webhooks, which cannot sign),
`max_silence_seconds` (positive integer or null), and `max_delay_seconds` (positive
integer), with unique sources. An event from an undeclared source is rejected at
`/source`. Each signer numbers the events it ships per instance, so every event has a
sequence and filtering happens before signing. A sensor also consumes one sequence
number for each record it loses before shipping, as in a full kernel ring buffer, so
loss appears as a sequence gap.

## Authenticated events

- `authentication` is `required` or `off`. When `required`, `mac` MUST be the
  lowercase hexadecimal HMAC-SHA256 over the RFC 8785 (JCS) canonical JSON of the event
  as received, unknown fields included and before any repair, without `mac` and
  `received`, keyed with the 32 bytes decoded from its source's
  hexadecimal key; an event whose `mac` is missing or wrong is rejected at `/mac`. When
  `off`, `mac` is ignored and the result warns `unauthenticated`.
- Sensor keys are a JSON object mapping each declared source to 64 lowercase
  hexadecimal characters, read from `SANDBOX_HONEYPOT_SENSOR_KEYS` when the request has
  no `sensor_keys` field. When `authentication` is `required`, exactly one of the two
  MUST be present and give a key for every declared source, otherwise the request is
  invalid at `/sensor_keys`; a request `sensor_keys` adds the warning
  `keys-in-request`. When `off`, neither is read and a request `sensor_keys` is
  ignored without a warning. Keys MUST be unique per host and
  source, so a key stolen on one host cannot speak for another.
- A key is bound to one source and the signed event names its deployment and
  sequence, so an event cannot claim another source, move between deployments, or be
  replayed without appearing as a sequence duplicate. A sensor-signed event cannot be
  forged or altered by the collector, which can only drop or delay it, as sequence
  gaps, late fills, silence, and clock skew reveal. A collector-signed source is
  trusted to the same degree as its collector.
- `received` is stamped by the collector and not signed. An accepted event is listed
  in `clock_skew` when `received` is more than its source's `max_delay_seconds` after
  `time`, or `time` is more than `max_clock_skew_seconds` (positive integer) after
  `received`.

## Batches and carry

A request MUST fit in one command-line argument, so operators evaluate consecutive
windows as batches; every event belongs to exactly one batch by its `received` time,
so an event that arrives late is still evaluated. `carry` is null for the first batch
and otherwise the `carry` of the result for the immediately preceding window. It has
exactly `window_end` (that window's `end`) and:

- `sequences`: objects with exactly `source`, `sensor_instance`, `highest`,
  `missing` (at most 64 objects with exactly `from` and `to`, the newest kept), and
  `last_received`, one per instance, dropped once `last_received` is more than 86400
  seconds before `window.end`;
- `last_seen`: objects with exactly `source` and `received`;
- `last_probe`: objects with exactly `decoy_id` and `received`;
- `recent_hits` and `pending`: objects with exactly `event_id`, `decoy_id`, `source`,
  `time`, and `received`, plus `missing_sources` for `pending` (Corroboration).

The result's `carry` holds the updated values, sorted by source and instance, by
source, in decoy order, and by time then event ID respectively.

## Sequences and restarts

For each source and instance, process its accepted events in ascending `sequence`
order (ties by index), starting from the carried `highest` and `missing` ranges.
Every instance numbers its events from 1, so an instance with nothing carried starts
from `highest` 0, and records dropped right after a restart form a gap after 0:

- a sequence above `highest` becomes the new `highest`; if it skips numbers, those
  form a **sequence gap** (`source`, `sensor_instance`, `after`, `before`), revealing
  dropped records, and are added to `missing`;
- a sequence inside a `missing` range is a **late fill** (its `event_id`), revealing a
  delayed record, and is removed from `missing`;
- any other sequence at or below `highest`, including a repeat within the batch, is a
  **sequence duplicate** (`source`, `sensor_instance`, `sequence`), revealing replay.
  The event is still evaluated.

An instance first seen while another instance of the same source is known, from
`carry` or earlier in the batch, is a **sensor restart** (`source`,
`sensor_instance`), since a killed sensor restarts its counter.

## Silence

For each source with a non-null `max_silence_seconds`, take its carried `last_seen`
time (or `window.start`), the `received` times of its accepted events, and
`window.end`, in instant order: every consecutive pair more than
`max_silence_seconds` apart is a **silence gap** (`source`, `from`, `to`). Sensors
SHOULD emit `heartbeat` events, so a quiet sensor is distinguishable from a dead one.

## Self-test probes

`probe` is null or an object with exactly `executable` (path), `executable_digest`
(64 lowercase hex), `uid` (integer), and `max_interval_seconds` (positive integer).
When it is not null, every planted decoy is probed: take its carried `last_probe` time
(or `window.start`), the `received` times of its probe hits, and `window.end`, in
instant order; every consecutive pair more than `max_interval_seconds` apart is a
**watch gap** (`decoy_id`, `from`, `to`). Watched decoys are not probed, because
writing a kernel interface changes the host; silence gaps cover their sensors and the
external logs that record `credential-use`.

## Corroboration

A kernel-level attacker can blind one sensor. `corroboration` is null or an object with
exactly `window_seconds` (positive integer) and `decoys`: objects with exactly
`decoy_id` (a planted or kernel-interface decoy in `watch.decoys`, each at most once)
and `sources` (two or more distinct declared sources). Two hits **corroborate** each
other when they are on the same decoy from different listed sources and their `time`
values are at most `window_seconds` apart. Each accepted non-`credential-use` hit,
whatever its outcome, on a listed decoy from a listed source needs a corroborating hit
from every other listed source, among this batch's hits and the carried `recent_hits`.
Let `H` be `window_seconds` plus the largest `max_delay_seconds` of the decoy's listed
sources, since a slower source's report arrives later. A hit missing one stays in
`pending` while it was received at most `H` before `window.end`, and is judged again in
each later batch; otherwise it is **uncorroborated** (`event_id`, `decoy_id`, and
ascending `missing_sources`), as is a pending hit in a batch whose `corroboration` is
null or no longer lists its decoy. `recent_hits` carries the hits on listed decoys
received at most `H` before `window.end`.

## Tamper lists and ordering

The result's tamper lists are `sequence_gaps` (objects with exactly `source`,
`sensor_instance`, `after`, and `before`), `late_fills` (event IDs),
`sequence_duplicates` (objects with exactly `source`, `sensor_instance`, and
`sequence`), `sensor_restarts` (objects with exactly `source` and `sensor_instance`),
`silence_gaps` (objects with exactly `source`, `from`, and `to`), `watch_gaps` (objects
with exactly `decoy_id`, `from`, and `to`), `uncorroborated` (objects with exactly
`event_id`, `decoy_id`, and `missing_sources`), and `clock_skew` (event IDs).

Sequence gaps are ordered by source, instance, then `after`; late fills and
`clock_skew` event IDs in event order; sequence duplicates by source, instance, then
`sequence`; sensor restarts by first occurrence; silence gaps by source then `from`;
watch gaps in decoy order then `from`; uncorroborated hits carried ones first, then in
event order.

## Requirement: Malformed, missing, or tampered telemetry is visible

The tripwire SHALL keep evaluating valid events when others are malformed, forged,
late, or duplicated, and SHALL report decoys whose monitoring stops working, sensors
that fall silent or restart, dropped, replayed, or delayed records, and contacts an
independent sensor did not confirm.

In these scenarios `W` is the `watch` from the gVisor cloud-VM plan in
`decoys/spec.md`.

### Scenario: Forged and authentic events

- **GIVEN** `W`, authentication `required`, request sensor keys `{"ebpf": K}` where `K` is `0f` repeated 32 times, and maximum clock skew 30 seconds
- **WHEN** event `m1` is `{"event_id": "m1", "deployment_id": "prod-agents", "time": "2026-10-30T12:00:00Z", "source": "ebpf", "sensor_instance": "boot-1", "sequence": 7, "action": "connect", "target": "/run/runsc-debug.sock", "target_inode": null, "target_fs": null, "target_digest": null, "written_digest": null, "actor": {"process": null, "ancestry": [], "helper_depth": null, "executable": null, "executable_digest": null, "uid": null, "comm": null, "environment_names": null, "sandbox_id": null}}` with `mac` `99f9d0d11b0a32fe2a390c6b2f6418459161cd833ded595ad7f26ec45aedab12` and `received` `2026-10-30T12:00:02Z`, and `m2` is identical except for `event_id` `m2`, `sequence` 8, and `target` `/home/deploy/.aws/credentials`, carrying the same `mac`
- **THEN** `m1/runtime-control` alerts, `m2` is rejected at `/mac` and `rejected_hits` is `[{"index": 1, "decoy_id": "cloud-credentials"}]`, and `warnings` is `["keys-in-request", "missing-inode-binding"]`

### Scenario: Late external log

- **GIVEN** `W` and source `cloudtrail` signed by the collector with maximum delay 900 seconds
- **WHEN** a batch for `12:05:00Z` to `12:10:00Z` receives `c1` at `12:09:00Z`, a `credential-use` with target `P` observed at `12:04:00Z`
- **THEN** `c1/cloud-credentials` is `credential-exfiltrated` and `clock_skew` is empty

### Scenario: Backdated event

- **GIVEN** `W` and source `ebpf` with maximum delay 60 seconds
- **WHEN** an accepted event `d1` has `time` `12:00:00Z` and `received` `12:05:00Z`
- **THEN** `clock_skew` is `["d1"]` and `degraded` is true

### Scenario: Malformed and repaired events

- **GIVEN** `W`
- **WHEN** the first event connects to `/run/runsc-debug.sock` with `time` `2026-10-30 12:00`, and a second, otherwise valid event connects to it with `actor.process` `{"pid": 0, "start_ticks": 0}`
- **THEN** the second still alerts, `rejected` is `[{"index": 0, "field": "/time"}]`, `rejected_hits` is `[{"index": 0, "decoy_id": "runtime-control"}]`, `repaired` is `[{"index": 1, "field": "/actor/process"}]`, and `degraded` and `breached` are true

### Scenario: Duplicate event IDs

- **GIVEN** `W`
- **WHEN** two events at the same instant both have ID `x`; the first reads `/home/deploy/.aws/credentials` and the second connects to `/run/runsc-debug.sock`
- **THEN** the alert IDs are `x/cloud-credentials#0` and `x/runtime-control#1`, `duplicate_event_ids` is `["x"]`, and `degraded` is true

### Scenario: Broken decoy monitoring

- **GIVEN** `W`, window `12:00:00Z` to `13:00:00Z`, and probe `/usr/libexec/fs-audit` with digest `R` as uid 0 every 600 seconds
- **WHEN** the probe reads `/home/deploy/.aws/credentials` and `/home/deploy/.ssh/id_ed25519` and connects to `127.0.0.1:2375` and `172.17.0.1:22` at `12:00`, `12:10`, `12:20`, `12:30`, `12:40`, and `12:50`, but connects to `/run/runsc-debug.sock` only at `12:00` and `12:05`
- **THEN** `watch_gaps` is only `runtime-control` from `2026-10-30T12:05:00Z` to `2026-10-30T13:00:00Z`, `probe_hits` is 26, `alerts` is empty, `degraded` is true, and `carry.last_probe` gives `runtime-control` `2026-10-30T12:05:00Z`

### Scenario: Dropped, late, and replayed records across batches

- **GIVEN** `W`, and a first batch whose `ebpf` heartbeats from instance `boot-1` have sequences 1 and 2
- **WHEN** the second batch, for 2026-10-31 and given that `carry`, has `boot-1` heartbeats with sequences 5 and 2 and a `boot-2` heartbeat with sequence 1, and a third batch, for 2026-11-01 and given the second's `carry`, has a `boot-1` heartbeat `h3` with sequence 3, each event received at noon of its batch's day
- **THEN** the second batch reports sequence gap `boot-1` after 2 before 5, sequence duplicate `boot-1` 2, and sensor restart `boot-2`, and the third batch lists `h3` as a late fill

### Scenario: Silent sensor

- **GIVEN** `W`, window `12:00:00Z` to `13:00:00Z`, and source `ebpf` with maximum silence 600 seconds
- **WHEN** the only `ebpf` events are heartbeats received at `12:00` and `12:10`
- **THEN** `silence_gaps` is only `ebpf` from `2026-10-30T12:10:00Z` to `2026-10-30T13:00:00Z`

### Scenario: Blinded sensor and batch boundaries

- **GIVEN** `W`, declared sources `ebpf` and `lsm` in both batches, and corroboration of `runtime-control` by those sources within 5 seconds
- **WHEN** only `ebpf` reports `b1` at `12:00:00Z` and `b2` at `23:59:58Z`, both connecting to `/run/runsc-debug.sock`, and the next batch, for window `2026-10-31T00:00:00Z` to `2026-11-01T00:00:00Z` and given that `carry`, receives an `lsm` hit `b3` on the same socket at `2026-10-31T00:00:01Z`
- **THEN** the first batch lists only `b1` as uncorroborated and carries `b2` as pending, and the next batch reports nothing uncorroborated, because `b2` and `b3` corroborate each other
