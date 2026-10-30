---
name: Telemetry integrity
summary: Authenticated events, batching, and evidence of broken or tampered monitoring
kind: contract
---
# Telemetry integrity

This document defines which sensor events `evaluate` trusts, how consecutive batches
connect, and how broken, dropped, or tampered monitoring is reported. Event shape and
hits are in `evaluation/spec.md`; scenario conventions are in `component.md`.

## Authenticated events

A forged or altered event could hide a breakout or frame a sandbox, so each sensor
signs its events with its own key.

- `authentication` is `required` or `off`. When `required`, an event whose core fields
  are valid MUST also carry `mac`: the lowercase hexadecimal HMAC-SHA256 over the
  RFC 8785 (JCS) canonical JSON of the event without `mac` and `received`, keyed with
  the 32 bytes decoded from its `source`'s hexadecimal key. An event whose `source` has
  no key, or whose `mac` is missing or wrong, is rejected at `/mac`. When `off`, `mac`
  is ignored and the result warns `unauthenticated`.
- Sensor keys are a JSON object mapping each source to 64 lowercase hexadecimal
  characters, read from `SANDBOX_HONEYPOT_SENSOR_KEYS` when the request has no
  `sensor_keys` field. When `authentication` is `required`, exactly one of the two
  MUST be present (otherwise the request is invalid at `/sensor_keys`); a request
  `sensor_keys` adds the warning `keys-in-request`.
- A key is bound to one source, and the signed event names its deployment, so an
  event cannot claim another sensor's identity or be replayed into another deployment;
  events outside the window are rejected, so old events cannot be replayed into a later
  batch. External logs that cannot sign (cloud audit trails, SSH logs, token webhooks)
  are signed by the collector that ingests them, under that source's key.
- The collector can drop or delay events, which sequence gaps and silence reveal, but
  cannot forge or alter them. It stamps `received`, which is not signed: an accepted
  event whose `time` and `received` differ by more than `max_clock_skew_seconds`
  (positive integer) is listed in `clock_skew`, revealing backdated or held events.

## Batches and carry

A request MUST fit in one command-line argument, so operators evaluate consecutive
windows as batches. `carry` is null for the first batch and otherwise the `carry` of
the result for the immediately preceding window. It has exactly `sequences` (objects
with exactly `source`, `sensor_instance`, and `sequence`), `last_seen` (objects with
exactly `source` and `time`), `last_probe` (objects with exactly `decoy_id` and
`time`), and `pending` (objects with exactly `event_id`, `decoy_id`, `source`, and
`time`). The result's `carry` holds, respectively: the highest sequence seen per source
and instance, the latest accepted event time per expected source, the latest probe hit
per probed decoy, and unresolved corroboration (below), each including carried values
not superseded, sorted by source and instance, by source, in decoy order, and by time
then event ID.

## Sequences and restarts

For each source and instance, take the carried sequence (if any) followed by the
distinct non-null `sequence` values of its accepted events in ascending order: every
consecutive pair `a`, `b` with `b > a + 1` is a **sequence gap** (`source`,
`sensor_instance`, `after`, `before`), revealing dropped records. A value carried by
more than one accepted event, or not above the carried value, is a **sequence
duplicate** (`source`, `sensor_instance`, `sequence`), revealing replay. An instance
of a source that `carry` knew under other instances is a **sensor restart** (`source`,
`sensor_instance`), since a killed sensor restarts its counter.

## Silence

`expected_sources` holds objects with exactly `source` and `max_silence_seconds`
(positive integer), with unique sources. For each, take its carried `last_seen` time
(or `window.start`), the times of its accepted events in the window, and
`window.end`, in instant order: every consecutive pair more than
`max_silence_seconds` apart is a **silence gap** (`source`, `from`, `to`). Sensors
SHOULD emit `heartbeat` events, so a quiet sensor is distinguishable from a dead one.

## Self-test probes

`probe` is null or an object with exactly `executable` (path), `executable_digest`
(64 lowercase hex), `uid` (integer), and `max_interval_seconds` (positive integer).
When it is not null, every planted decoy is probed: take its carried `last_probe`
time (or `window.start`), its probe hit times in the window, and `window.end`, in
instant order; every consecutive pair more than `max_interval_seconds` apart is a
**watch gap** (`decoy_id`, `from`, `to`). Watched decoys are not probed, because
writing a kernel interface changes the host, and probes do not cover the external logs
that record `credential-use`; silence gaps cover those sensors instead.

## Corroboration

A kernel-level attacker can blind one sensor. `corroboration` is null or an object with
exactly `window_seconds` (positive integer) and `decoys`: objects with exactly
`decoy_id` (a planted or kernel-interface decoy in `watch.decoys`, each at most once)
and `sources` (two or more distinct sources). For each accepted non-`credential-use`
hit, whatever its outcome, on a listed decoy whose `source` is in that decoy's
`sources`, every other listed source MUST report an accepted hit on the same decoy
within `window_seconds` (inclusive). A hit missing one is **uncorroborated**
(`event_id`, `decoy_id`, and ascending `missing_sources`), unless it lies within
`window_seconds` of `window.end`, in which case it is carried as `pending` and judged
in the next batch against that batch's hits.

Tamper lists are ordered: sequence gaps by source, instance, then `after`; sequence
duplicates by source, instance, then `sequence`; sensor restarts by first occurrence;
silence gaps by source then `from`; watch gaps in decoy order then `from`;
uncorroborated hits carried ones first, then in event order; `clock_skew` event IDs in
event order.

## Requirement: Malformed, missing, or tampered telemetry is visible

The tripwire SHALL keep evaluating valid events when others are malformed, forged, or
duplicated, and SHALL report decoys whose monitoring stops working, sensors that fall
silent or restart, dropped, replayed, or delayed records, and contacts an independent
sensor did not confirm.

In these scenarios `W` is the `watch` from the gVisor cloud-VM plan in
`decoys/spec.md`.

### Scenario: Forged and authentic events

- **GIVEN** `W`, authentication `required`, request sensor keys `{"ebpf": K}` where `K` is `0f` repeated 32 times, and maximum clock skew 30 seconds
- **WHEN** event `m1` is `{"event_id": "m1", "deployment_id": "prod-agents", "time": "2026-10-30T12:00:00Z", "source": "ebpf", "sensor_instance": "boot-1", "sequence": 7, "action": "connect", "target": "/run/runsc-debug.sock", "target_inode": null, "target_fs": null, "written_digest": null, "actor": {"process": null, "ancestry": [], "executable": null, "executable_digest": null, "uid": null, "comm": null, "environment_names": null, "sandbox_id": null}}` with `mac` `8ee36c13224903df99190492f4a28d5a92318d15f5c49e747ed14691cb332645` and `received` `2026-10-30T12:00:02Z`, and `m2` is identical except for `event_id` `m2`, `sequence` 8, and `target` `/home/deploy/.aws/credentials`, carrying the same `mac`
- **THEN** `m1/runtime-control` alerts, `m2` is rejected at `/mac` and listed in `rejected_hits`, `warnings` is `["keys-in-request"]`, and `clock_skew` is empty

### Scenario: Backdated event

- **GIVEN** `W` and maximum clock skew 30 seconds
- **WHEN** an accepted event `d1` has `time` `12:00:00Z` and `received` `12:05:00Z`
- **THEN** `clock_skew` is `["d1"]` and `degraded` is true

### Scenario: Malformed and repaired events

- **GIVEN** `W`
- **WHEN** the first event connects to `/run/runsc-debug.sock` with `time` `2026-10-30 12:00`, and a second, otherwise valid event connects to it with `actor.process` `{"pid": 0, "start_ticks": 0}`
- **THEN** the second still alerts, `rejected` is `[{"index": 0, "field": "/time"}]`, `rejected_hits` is `[0]`, `repaired` is `[{"index": 1, "field": "/actor/process"}]`, and `degraded` and `breached` are true

### Scenario: Duplicate event IDs

- **GIVEN** `W`
- **WHEN** two events at the same instant both have ID `x`; the first reads `/home/deploy/.aws/credentials` and the second connects to `/run/runsc-debug.sock`
- **THEN** the alert IDs are `x/cloud-credentials#0` and `x/runtime-control#1`, `duplicate_event_ids` is `["x"]`, and `degraded` is true

### Scenario: Broken decoy monitoring

- **GIVEN** `W`, window `12:00:00Z` to `13:00:00Z`, and probe `/usr/libexec/fs-audit` with digest `R` as uid 0 every 600 seconds
- **WHEN** the probe reads `/home/deploy/.aws/credentials` and `/home/deploy/.ssh/id_ed25519` and connects to `127.0.0.1:2375` and `172.17.0.1:22` at `12:00`, `12:10`, `12:20`, `12:30`, `12:40`, and `12:50`, but connects to `/run/runsc-debug.sock` only at `12:00` and `12:05`
- **THEN** `watch_gaps` is only `runtime-control` from `2026-10-30T12:05:00Z` to `2026-10-30T13:00:00Z`, `probe_hits` is 26, `alerts` is empty, `degraded` is true, and `carry.last_probe` gives `runtime-control` `2026-10-30T12:05:00Z`

### Scenario: Dropped records and a restarted sensor across batches

- **GIVEN** `W`, and a first batch whose `fanotify` heartbeats from instance `boot-1` carry sequences 1 and 2
- **WHEN** the next batch, given that batch's `carry`, has `fanotify` heartbeats from `boot-1` with sequence 5 and from `boot-2` with sequence 1
- **THEN** `sequence_gaps` is `[{"source": "fanotify", "sensor_instance": "boot-1", "after": 2, "before": 5}]`, `sensor_restarts` is `[{"source": "fanotify", "sensor_instance": "boot-2"}]`, and `degraded` is true

### Scenario: Silent sensor

- **GIVEN** `W`, window `12:00:00Z` to `13:00:00Z`, and expected source `ebpf` with maximum silence 600 seconds
- **WHEN** the only `ebpf` events are heartbeats at `12:00` and `12:10`
- **THEN** `silence_gaps` is only `ebpf` from `2026-10-30T12:10:00Z` to `2026-10-30T13:00:00Z`

### Scenario: Blinded sensor

- **GIVEN** `W` and corroboration of `runtime-control` by sources `ebpf` and `fanotify` within 5 seconds
- **WHEN** only `ebpf` reports `b1` at `12:00:00Z` and `b2` at `23:59:58Z`, both connecting to `/run/runsc-debug.sock`
- **THEN** both alert, `uncorroborated` is `[{"event_id": "b1", "decoy_id": "runtime-control", "missing_sources": ["fanotify"]}]`, and `carry.pending` holds `b2`, which the next batch judges
