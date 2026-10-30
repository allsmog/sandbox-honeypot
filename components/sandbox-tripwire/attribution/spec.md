---
name: Attribution
summary: Attributing alerts to sandboxes, verdicts, and passive harness identification
kind: contract
---
# Attribution

This document defines how each alert from `evaluate` is attributed, which verdict it
gets, and how the driving agent harness is identified. Hits and the result shape are
in `evaluation/spec.md`; scenario conventions are in `component.md`.

## Attribution

Each alert is attributed by the first rule that applies:

1. `runtime`: `actor.process` equals a sandbox's runtime process. The runtime itself
   touched the decoy. For a VMM this is a guest-to-host escape through the VMM (2026
   advisories include a Firecracker jailer host-file overwrite and a Cloud Hypervisor
   disk backing-file host leak); otherwise a compromised runtime or a mis-declared
   exposure.
2. `harness`: `actor.process` equals a sandbox's harness process.
3. Lineage: the first identity in `actor.ancestry` equal to a runtime or harness
   process names its sandbox, with attribution `ancestry` for a runtime process (a new
   process descended from the runtime, the classic escape) and `harness` for a harness
   process (code the harness ran outside the sandbox). The nearest ancestor wins, so a
   process inside the runtime is never blamed on the harness that launched it.
4. `kernel-helper`: `actor.helper_depth` is not null, so the kernel started this
   process or an ancestor as a user-mode helper. Hijacked helpers (`release_agent`,
   `core_pattern`, `modprobe`) are how many escapes run code as host root, and their
   payloads often fork. The sandbox is unknown.
5. `sensor`: `actor.sandbox_id` names a sandbox in `sandboxes`.
6. Otherwise `sandbox_id` and `attribution` are null.

A **harness escape** needs no exploit: an artifact can persuade the agent harness to
re-run it without the sandbox, for example by reporting a fabricated sandbox
violation. Paths the harness legitimately reads on the host belong in exposure when
planning.

## Verdict

Every alert has `severity` `critical`. The verdict is the first that applies:

1. `credential-exfiltrated` for `credential-use`;
2. `harness-escape` for attribution `harness`;
3. `escape-attempt` for an endpoint decoy with attribution `runtime` or `sensor`: the
   sandbox reached for a host endpoint, whether or not egress let the connection
   through;
4. `runtime-mediated` for attribution `runtime`;
5. `escape-confirmed` for attribution `ancestry`, `kernel-helper`, or `sensor`;
6. otherwise `host-breach`.

`techniques` is the decoy technique then `T1078` for `credential-exfiltrated`, and
otherwise `T1611` then the decoy technique, listing `T1611` once when they coincide.

## Harness identification

Knowing which agent harness drove an escape matters for response. Identification is
passive: it reads only what host sensors recorded and never runs code on the actor's
side. `harness_signatures` holds objects with exactly `harness_id` (identifier),
`environment_names`, and `executables` (arrays of strings, together nonempty), with
unique IDs. When it is empty, each alert's `harness` is null.

Otherwise a signature's **matches** are `env:` plus each of its `environment_names`
found in `actor.environment_names`, and `exe:` plus each of its `executables` equal to
the final segment of `actor.executable`. If exactly one signature has the most matches
and that number is positive, `harness` is `{"harness_id": ID, "matched": MATCHES,
"abstained": false}`, with matches sorted by code point; otherwise it is
`{"harness_id": null, "matched": [], "abstained": true}`. Identification is context for
responders and never changes a verdict.

## Requirement: Decoy contact is a critical, attributed breakout

The tripwire SHALL turn every decoy contact that is not trusted maintenance or
self-testing into a critical alert; distinguish escaped processes, harness escapes,
kernel-launched helpers, runtime-mediated contact, and escape attempts; and SHALL NOT
let a self-reported name or a reused PID change any of them.

In these scenarios `W` is the `watch` from the gVisor cloud-VM plan in
`decoys/spec.md`; `sbx-1` has runtime process `{4100, 500}` and harness process
`{3000, 400}`; and `R` is a fixed executable digest.

### Scenario: Escape, runtime contact, impostor, and exfiltration

- **GIVEN** `W`, `sbx-1`, and a suppression for `cloud-credentials`, executable `/usr/bin/restic` with digest `R`, uid 0
- **WHEN** `e1` at `12:00:00Z`: process `{4242, 900}` with ancestry `[{4100, 500}, {3000, 400}, {1, 1}]` running `/usr/bin/python3` connects to `/run/runsc-debug.sock`; `e2` at `12:01:00Z`: `/usr/bin/restic` with digest `R` as uid 0 reads `/home/deploy/.aws/credentials`; `e3` at `12:02:00Z`: process `{5000, 1000}` with comm `restic`, running `/tmp/.x/restic` as uid 0 with ancestry `[{4100, 777}, {1, 1}]`, reads the same file; `e4` at `12:03:00Z`: process `{4100, 500}` opens it; `e5` at `12:05:00Z`: source `cloudtrail` reports a `credential-use` with target `P`
- **THEN** the alerts are `e1/runtime-control` (`escape-confirmed`, `ancestry`, `sbx-1`, `["T1611"]`), `e3/cloud-credentials` (`host-breach`, because PID 4100 with other start ticks is a reused PID), `e4/cloud-credentials` (`runtime-mediated`, `runtime`, `sbx-1`), and `e5/cloud-credentials` (`credential-exfiltrated`, `["T1552.001", "T1078"]`)
- **AND** `suppressed` lists only `e2`, and the incidents are `sbx-1` with `e1` and `e4`, then the unattributed incident with `e3` and `e5`

### Scenario: Harness escape, identified passively

- **GIVEN** `W`, `sbx-1`, and harness signatures `claude-code` (environment name `CLAUDECODE`, executable `claude`) and `aider` (environment name `AIDER_MODEL`, executable `aider`)
- **WHEN** `h1` at `12:00:00Z`: process `{3100, 450}` with ancestry `[{3000, 400}, {1, 1}]`, running `/usr/bin/python3` with environment names `["CLAUDECODE", "HOME", "PATH"]`, reads `/home/deploy/.aws/credentials`; `h2` at `12:01:00Z`: process `{4300, 980}` with ancestry `[{4100, 500}, {3000, 400}, {1, 1}]` and environment names `["PATH"]` connects to `/run/runsc-debug.sock`
- **THEN** `h1/cloud-credentials` is `harness-escape` with attribution `harness`, sandbox `sbx-1`, and harness `{"harness_id": "claude-code", "matched": ["env:CLAUDECODE"], "abstained": false}`
- **AND** `h2/runtime-control` is `escape-confirmed` with attribution `ancestry`, because the runtime is the nearest ancestor, and its harness identification abstains

### Scenario: Escape through kernel helpers

- **GIVEN** `W`, `sbx-1`, and expected helper `/usr/bin/kmod` with digest `R`
- **WHEN** `k0`: a host process reads `/proc/sys/kernel/core_pattern`; `k1` at `12:00:00Z`: process `{6100, 950}` with ancestry `[{4100, 500}]` writes `/tmp/cgrp/release_agent` with target filesystem `{"type": "cgroup", "path": "release_agent"}`; `k2` at `12:00:05Z`: process `{7000, 1200}` with helper depth 0 execs `/tmp/p`; `k3` at `12:00:06Z`: its child `{7001, 1210}` with helper depth 1 reads `/home/deploy/.aws/credentials`; `k4`: a process with helper depth 0 execs `/usr/bin/kmod` with target digest `R`
- **THEN** `k0` and `k4` are ignored; `k1/cgroup-release-agent` is `escape-confirmed` with attribution `ancestry` and sandbox `sbx-1`, although the write bypassed `/sys/fs/cgroup`; and `k2/helper-exec` and `k3/cloud-credentials` are `escape-confirmed` with attribution `kernel-helper` and a null sandbox

### Scenario: Sandbox reaching for host SSH

- **GIVEN** `W` and `sbx-1`
- **WHEN** a flow sensor reports `g1` connecting to `172.17.0.1:22` with `actor.sandbox_id` `sbx-1`
- **THEN** `g1/gateway-ssh` is `escape-attempt` with attribution `sensor` and techniques `["T1611", "T1021.004"]`

### Scenario: Alias path and simultaneous alerts

- **GIVEN** `W` and `sbx-1`
- **WHEN** `a2` reads `/home/deploy/.aws/credentials`, and `a1`, with `actor.sandbox_id` `sbx-1`, connects to `/var/run/runsc-debug.sock`, both at `12:00:00Z`
- **THEN** `a1/runtime-control` (attribution `sensor`) precedes `a2/cloud-credentials`, and the `sbx-1` incident precedes the unattributed incident

### Scenario: Endpoint spellings, companion, and hard link

- **GIVEN** the `watch` from the Kubernetes node plan in `decoys/spec.md` and a decoy inode for `ssh-private-key` at `/root/.ssh/id_ed25519` of device 2049, inode 1234
- **WHEN** `n1` connects to `[::ffff:169.254.169.254]:80`, `n2` reads `/tmp/k` with target inode device 2049, inode 1234, `n3` connects to `0.0.0.0:2375`, and `n4` performs `stat` on `/root/.ssh/id_ed25519.pub`
- **THEN** the alerts are `n1/metadata-endpoint`, `n2/ssh-private-key`, `n3/docker-api`, and `n4/ssh-private-key`, all `host-breach`
