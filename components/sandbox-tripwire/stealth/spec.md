---
name: Silent detection
summary: Requirements that keep decoy contact invisible to the attacker
kind: contract
---
# Silent detection

An attacker who learns that they touched a decoy can stop, erase traces, avoid the
remaining decoys, or sabotage monitoring, and deception-aware AI attackers actively
search for exactly these tells. A decoy contact MUST therefore change nothing the
attacker can observe. These requirements bind whoever materializes decoys, runs
sensors, and responds to alerts (the operator in version 0.1.0). The engine itself
already has no host side effects.

## Decoys behave like the assets they imitate

- A credential-file decoy is an ordinary regular file whose owner, mode, size, and
  contents are realistic for its location and for the host's own context (account,
  cluster, user, and host names). Reading it succeeds like reading any file.
- Its timestamps are consistent with a long-lived host asset and are never changed by
  monitoring: sensors and probes MUST NOT update its access, modification, or change
  times (for example, probes open decoys with `O_NOATIME`), so the file shows no
  access pattern.
- A socket or endpoint decoy accepts connections and answers its imitated protocol
  the way a real service that rejects the caller would, never with a banner, error,
  or delay unique to the decoy.
- A used decoy credential gets exactly the response a real credential without
  permissions gets: `AccessDenied` for the deny-all AWS key,
  `Permission denied (publickey)` for SSH, and `401` or `403` from Kubernetes.
  Identity details a caller can query, such as the IAM user name and path returned by
  `sts get-caller-identity`, look like a real service account.
- No decoy name, path, identity, or content contains a word or marker that reveals
  deception (such as canary, honey, decoy, trap, or tripwire), and no deployment
  reuses the public test values in this specification. `plan` rejects the most
  revealing words in operator-supplied text (`decoys/spec.md`).

## Observation is passive

- Sensors observe without interposing: notification-only mechanisms (fanotify
  notification marks, audit rules, eBPF tracepoints), never permission events,
  blocking hooks, or access denials on decoys. A contact completes with the same
  result and no added latency an attacker could measure.
- Detection takes no inline action on the protected host: at the time of contact
  there is no process kill, network cut, login message, broadcast, file change, or
  locally visible log entry. Events leave the host through an always-on telemetry
  channel whose traffic does not change when a decoy is touched.
- Responses such as containment, credential revocation, and host isolation are
  decided off the host. A response SHOULD resemble routine operations (for example a
  host drain or maintenance) rather than an immediate reaction to the touched decoy.
- Probes run on jittered schedules from processes that look like routine host
  maintenance, so neither their timing nor their identity marks which files are
  decoys.

## Decoy knowledge stays off the host

- `plan` and `evaluate` run on a system outside the protected host. `material` exists
  on the protected host only while decoys are materialized. `watch` holds no
  credential secrets but is confidential, because it lists which assets are decoys.
- Sensor configuration that names decoy locations is readable only by root on the
  protected host, and SHOULD use rules broad enough (a directory or a class of files)
  that it does not enumerate decoys.
- No two hosts share a decoy layout or decoy credentials: each host has its own
  `deployment_id`, so agents that pool what they learn across hosts cannot use one
  host's decoys to recognize another's.
- Every interaction an attacker can make with a decoy is a hit, including a metadata
  read (`stat`), so a decoy cannot be inspected safely before it is touched. Listing
  the containing directory is not a hit.
