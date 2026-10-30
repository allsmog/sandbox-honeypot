---
name: Telemetry integrity
summary: Authenticated sensor events and evidence of broken or tampered monitoring
kind: contract
---
# Telemetry integrity

This document defines how `evaluate` decides which sensor events to trust and how it
reports monitoring that is broken, dropped, or tampered with. Event shape, hits, and
the result are defined in `evaluation/spec.md`; scenario conventions are in
`component.md`.

## Authenticated events

A forged or altered event could hide a breakout or frame a sandbox, so each sensor
signs its events with its own key, and facts the sensor cannot vouch for are stamped
by the collector.

- `authentication` (request field) is `required` or `off`. When `required`, every
  event MUST carry `mac`: the lowercase hexadecimal HMAC-SHA256, keyed with its
  `source`'s key, over the event's **canonical form**: the event without `mac` and `received`,
  serialized as UTF-8 JSON with object keys sorted, no insignificant whitespace,
  non-ASCII characters unescaped, and integers in base 10. An event whose `source` has
  no key, or whose `mac` is missing or wrong, is rejected at `/mac`.
- Sensor keys are a JSON object mapping each source to 64 lowercase hexadecimal
  characters. `evaluate` reads them from the environment variable
  `SANDBOX_HONEYPOT_SENSOR_KEYS` when the request has no `sensor_keys` field; exactly
  one of the two MUST be present when `authentication` is `required` (otherwise the
  request is invalid at `/sensor_keys`). A request `sensor_keys` adds the warning
  `keys-in-request` to the result. When `authentication` is `off`, `mac` is ignored
  and the result carries the warning `unauthenticated`.
- Because each key is bound to one source, an event cannot claim another sensor's
  identity. A sensor's key lives with the sensor on the protected host: an attacker who
  gains host root can steal it, which is why events are shipped off the host as they
  occur (`component.md`, Threat model).
- The collector that receives events off the host stamps `received`, the timestamp of
  arrival; the sensor never supplies it. An accepted event whose `time` is more than
  `max_clock_skew_seconds` (request field, positive integer) before or after its
  `received` is listed in `clock_skew` with its `event_id`, since a delayed or
  backdated event is a tamper signal.

## Self-test probes

When `probe` is not null, every planted decoy is probed. For each, take the times of
its probe hits within the window plus `window.start` and `window.end`, in instant
order; every consecutive pair more than `max_interval_seconds` apart is a **watch
gap**. Kernel interfaces are not probed, because writing them changes the host. Probes
do not cover the external logs that record `credential-use`.

## Sequence gaps

For each source, take the distinct non-null `sequence` values of its accepted events in
ascending order: every consecutive pair `a`, `b` with `b > a + 1` is a **sequence
gap**, revealing dropped or suppressed records.

## Corroboration

A kernel-level attacker can blind one sensor. For each non-`credential-use` hit on a
decoy listed in `corroboration` whose `source` is in that decoy's `sources`, every
other listed source MUST report a hit on the same decoy within `window_seconds`
(inclusive); otherwise the hit is **uncorroborated**.

## Requirement: Malformed, missing, or tampered telemetry is visible

The tripwire SHALL keep evaluating valid events when others are malformed, forged, or
duplicated, and SHALL report decoys whose monitoring stops working, dropped or delayed
records, and contacts an independent sensor did not confirm.

In these scenarios `W` is the `watch` from the gVisor cloud-VM plan in
`decoys/spec.md` and times are on 2026-10-30.

### Scenario: Forged and authentic events

- **GIVEN** `W`, authentication `required`, request sensor keys `{"ebpf": K}` where `K` is `0f` repeated 32 times, and maximum clock skew 30 seconds
- **WHEN** event `m1` is `{"event_id": "m1", "time": "2026-10-30T12:00:00Z", "source": "ebpf", "sequence": 7, "action": "connect", "target": "/run/runsc-debug.sock", "target_inode": null, "actor": {"process": null, "ancestry": [], "executable": null, "uid": null, "comm": null, "environment_names": null, "sandbox_id": null}}` with `mac` `3c4186f710e65eefd286fbeaaaea53a17187e082e9e10d09ccd5a69ddac1f7ac` and `received` `2026-10-30T12:00:02Z`, and event `m2` is identical except for `event_id` `m2` and `target` `/home/deploy/.aws/credentials`, still carrying the same `mac`
- **THEN** `m1/runtime-control` alerts, `m2` is rejected at `/mac`, `warnings` is `["keys-in-request"]`, and `clock_skew` is empty

### Scenario: Backdated event

- **GIVEN** `W` and maximum clock skew 30 seconds
- **WHEN** an accepted event `d1` has `time` `12:00:00Z` and `received` `12:05:00Z`
- **THEN** `clock_skew` is `["d1"]` and `degraded` is true

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
