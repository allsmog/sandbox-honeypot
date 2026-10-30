---
name: Decoy planning
summary: Decoy catalog, locations, and the plan operation
kind: contract
---
# Decoy planning

This document defines which host decoys and tripwires exist, where they go, and the
`plan` operation of the Sandbox Escape Tripwire. Credentials, context, companions,
and cover files are in `credentials/spec.md`; shared rules and scenario conventions
are in `component.md`.

## Decoy catalog

Each decoy has a stable `decoy_id`, a `kind`, candidate locations, and a primary MITRE
ATT&CK `technique`. **Planted** kinds are bait the operator creates:
`credential-file`, `socket`, and `endpoint`. **Watched** kinds are real host behavior
treated as a tripwire: `kernel-interface` (an interface escape techniques write to)
and `kernel-helper` (a process the kernel launches). Catalog order is the order of
decoys in every result. Every catalog `decoy_id` is reserved even when not included.

| `decoy_id` | `kind` | Candidate locations | `technique` | Included when |
| --- | --- | --- | --- | --- |
| `cloud-credentials` | `credential-file` | `/root/.aws/credentials`, `/home/{user}/.aws/credentials` | `T1552.001` | always |
| `ssh-private-key` | `credential-file` | `/root/.ssh/id_ed25519`, `/home/{user}/.ssh/id_ed25519` | `T1552.004` | always |
| `container-socket` | `socket` | `/var/run/docker.sock` | `T1552.007` | listed in `include` |
| `metadata-endpoint` | `endpoint` | `169.254.169.254:80` | `T1552.005` | listed in `include` |
| `runtime-control` | `socket` | per runtime, below | `T1611` | always |
| `kubeconfig` | `credential-file` | `/root/.kube/config`, `/home/{user}/.kube/config` | `T1552.001` | `host_profile` is `kubernetes-node` |
| `docker-api` | `endpoint` | `127.0.0.1:2375` | `T1552.007` | listed in `include` |
| `gateway-ssh` | `endpoint` | `{gateway}:22` | `T1021.004` | `sandbox_gateway` is not null |
| `core-pattern` | `kernel-interface` | `/proc/sys/kernel/core_pattern` | `T1611` | always |
| `modprobe-path` | `kernel-interface` | `/proc/sys/kernel/modprobe` | `T1611` | always |
| `uevent-helper` | `kernel-interface` | `/sys/kernel/uevent_helper` | `T1611` | always |
| `hotplug-helper` | `kernel-interface` | `/proc/sys/kernel/hotplug` | `T1611` | always |
| `poweroff-cmd` | `kernel-interface` | `/proc/sys/kernel/poweroff_cmd` | `T1611` | always |
| `binfmt-register` | `kernel-interface` | `/proc/sys/fs/binfmt_misc/register` | `T1611` | always |
| `cgroup-release-agent` | `kernel-interface` | `/sys/fs/cgroup` | `T1611` | always |
| `helper-exec` | `kernel-helper` | none | `T1611` | always |

`{user}` is `context.dormant_user`, and candidates containing it are omitted when that
is null. `{gateway}` is `sandbox_gateway`, bracketed when it is IPv6. The
credential-file formats are `aws-access-key` for `cloud-credentials`, `ssh-ed25519`
for `ssh-private-key`, and `kubeconfig-token` for `kubeconfig`; every other catalog
decoy has a null format. The **opt-in** decoys `metadata-endpoint`,
`container-socket`, and `docker-api` are included only when listed in `include`,
because cloud SDKs, monitoring agents, and habitual `docker` commands contact those
addresses by default on many hosts; include them only where nothing legitimate does.

`runtime-control` candidates sit directly in `/run`, outside any directory a runtime
manages, and SHOULD be relocated to site-specific names because these are public:
`gvisor` `/run/runsc-metrics.sock`, `/run/runsc-debug.sock`; `capsem`
`/run/capsem-admin.sock`, `/run/capsem-control.sock`; `firecracker`
`/run/firecracker-api.sock`, `/run/firecracker-jailer.sock`; `cloud-hypervisor`
`/run/cloud-hypervisor-api.sock`, `/run/ch-remote.sock`; `libkrun`
`/run/libkrun-admin.sock`, `/run/krun-control.sock`; `kata` `/run/kata-admin.sock`,
`/run/kata-monitor.sock`; `generic` `/run/sandbox-admin.sock`,
`/run/sandbox-control.sock`.

**Per-host layout.** A candidate is **eligible** when neither it nor its decoy's
companions or cover files would be skipped as `exposed` or `occupied` (below). A decoy
uses the eligible candidate at index `b mod n`, where `n` is the number of eligible
candidates in catalog order and `b` is the first byte of HMAC-SHA256 keyed with the
seed over the UTF-8 bytes of `deployment_id`, a line feed, the ASCII string `layout`, a
line feed, and `decoy_id`. A candidate is also ineligible when its footprint collides
with that of a relocated or custom decoy or of a decoy placed earlier. With no eligible candidate, the first candidate is checked and
skipped. Operators SHOULD give each host its own `deployment_id`, so layouts vary;
with few candidates, relocation is the main source of diversity.

**Boundary decoy.** `gateway-ssh` listens on the sandbox network's host gateway, the
address escaping agents have used to reach host SSH. No legitimate workload connects
to it, so it is planted even where egress allows it (`reachable` true); every other
decoy has `reachable` false. Where a real SSH server already serves that endpoint, the
decoy is not skipped as occupied: it is placed with `listener` false, and only
connections to the real server are watched, so operators MUST block sandbox traffic
to the host's other addresses on that port. Every other socket and endpoint decoy
has `listener` true; credential files and watched decoys have `listener` false.

**Kernel interfaces** are matched by path and by filesystem, because published escapes
mount a fresh `proc` or `cgroup` filesystem elsewhere and write it there. Each has a
filesystem type and a path within that filesystem: `core-pattern` `proc`
`sys/kernel/core_pattern`; `modprobe-path` `proc` `sys/kernel/modprobe`;
`uevent-helper` `sysfs` `kernel/uevent_helper`; `hotplug-helper` `proc`
`sys/kernel/hotplug` (the same kernel setting as `uevent_helper`); `poweroff-cmd`
`proc` `sys/kernel/poweroff_cmd`; `binfmt-register` `binfmt_misc` `register`. `cgroup-release-agent` has filesystem `cgroup` (version 1), scope
`name-beneath`, and name `release_agent`: it matches any `release_agent` on such a
filesystem or beneath its location. Every other decoy has scope `exact` and null name.

**Kernel helper.** `helper-exec` has no location: it is hit when a process launched by
the kernel as a user-mode helper runs an executable the operator did not expect
(`evaluation/spec.md`). It catches exploits that overwrite helper paths in kernel
memory and never write a file.

## Tailoring

- `exclude` lists catalog IDs to leave out. Every entry MUST be a catalog ID; an ID
  that is not included has no effect.
- `include` lists opt-in catalog IDs; any other entry is invalid.
- `relocate` moves included planted catalog decoys other than `gateway-ssh`, whose
  location follows `sandbox_gateway`: objects with exactly `decoy_id`
  and `location` (of the decoy's location type). It replaces the layout choice.
- `custom_decoys` appends decoys after the catalog, in request order: objects with
  exactly `decoy_id` (lowercase ASCII letters and digits in hyphen-separated groups,
  at most 64 characters, not a catalog ID), `kind` (a planted kind), `location`,
  `technique` (`T` and four digits, optionally `.` and three digits), and
  `credential_format` (a format in `credentials/spec.md` for a `credential-file`,
  otherwise null), with one location, scope `exact`, and `reachable` false.

Credential-file and socket locations are paths; endpoint locations are address
endpoints, never the unspecified address `0.0.0.0` or `[::]`. Each of `include`,
`exclude`, `relocate`, `epochs`, and `provided_credentials` names a decoy at most once.
A decoy's **footprint** is its location, its companions, and its cover files. Two
items collide when their canonical paths are equal or one lies beneath the other, or
their canonical endpoints are equal; two footprints collide when any of their items
do. Relocated and custom decoys count whether or not they are placed.

## Paths, aliases, and endpoints

A path is absolute POSIX: it starts with `/`, contains no empty, `.`, or `..`
segment, and has no trailing `/` unless it is exactly `/`. "Beneath" always means on a
segment boundary, and every other path lies beneath `/`. The effective alias list is the built-in alias `/var/run` → `/run`
followed by the request's `path_aliases` (objects with exactly `alias` and `target`).
It is valid only when every `alias` is distinct, no `target` equals or lies beneath any
`alias`, and no `alias` equals or lies beneath any `target`, so one rewrite always
reaches a fixed point. The **canonical** form of a path replaces
its longest alias prefix with that alias's target. Sensors report resolved paths, so
every symlinked ancestor of a footprint path (such as `/home` → `/var/home`) MUST be
aliased.

An address endpoint is `ADDRESS:PORT`: an IPv4 dotted quad or a bracketed IPv6
address, and a port from 1 to 65535. Its canonical form writes IPv4 in decimal without
leading zeros, IPv6 in RFC 5952 form, an IPv4-mapped IPv6 address as plain IPv4, and
the port without leading zeros. Host names are not endpoints. An exposure endpoint is
`SCOPE:PORTS`: `SCOPE` is an address, a CIDR block (IPv4 `a.b.c.d/n`, or IPv6
`[address]/n`, an IPv4-mapped block being its IPv4 block), or `*`, every
non-loopback address of both families; `PORTS` is a port or `*`. A decoy endpoint is exposed when its
canonical address lies in the scope and its port is in the ports. IPv4 addresses lie
only in IPv4 scopes. A sandbox's loopback is normally its own, so `*` and CIDR scopes
never cover loopback addresses unless the block lies within loopback (`127.0.0.0/8`,
`[::1]/128`); only such an exposure endpoint, or one naming a loopback address,
covers them, which sandboxes sharing the host network, libkrun's TSI, and slirp,
passt, or pasta with host-loopback forwarding need. Egress rules naming
hosts MUST be resolved to addresses by the operator.

## Operation `plan`

Request fields: `operation` (`plan`); `deployment_id`; `runtime` (`gvisor`, `capsem`,
`firecracker`, `cloud-hypervisor`, `libkrun`, `kata`, or `generic`); `host_profile`
(`linux-host` or `kubernetes-node`); `metadata_service` (boolean: whether the host has
a real instance metadata service at `169.254.169.254`); `include` (opt-in catalog
IDs); optional `seed`; `context`;
`sandbox_gateway` (the host-side address at which sandbox traffic to its gateway
arrives, never an unspecified address in any spelling, which is invalid at
`/sandbox_gateway`, or null; it is null for user-space stacks such as slirp4netns,
pasta, or gvproxy, which deliver gateway traffic to host loopback, where host tools
use SSH legitimately, so sandboxes on those stacks have no gateway decoy, a residual
gap); `exposure`; `occupied`; `path_aliases`;
`exclude`; `relocate`; `custom_decoys`; `epochs`; `provided_credentials`;
`retired_canaries`; and `cover_files`.

`exposure` has exactly `paths` and `endpoints`. `paths` lists **host-side** paths any
sandbox can reach: the host sources of bind mounts, shared folders (virtio-fs or 9p),
overlay layers, and image or disk backing files, never paths as seen inside the guest,
plus paths an agent harness reads on the host. Exposure and occupied paths MUST be
resolved or aliased like footprint paths. `endpoints` lists exposure endpoints
allowed by sandbox egress policy. `occupied` lists paths (covering everything beneath
them) and address endpoints in real use; an occupied endpoint with address `0.0.0.0`
or `[::]` covers every address on its port. `occupied` MUST list existing files a
footprint item would replace, runtime-managed directories, and the default credential
directories of any account whose tools use them (such as `/root/.aws` when root runs
AWS tooling), because a decoy there would hijack real tooling; directories that merely
contain decoys, such as the dormant account's home, are not occupied.

Watched decoys are skipped only when excluded. Every other included decoy is checked
in this order and skipped with the first matching reason:

1. `excluded`: its `decoy_id` is in `exclude`.
2. `real-service`: it is `metadata-endpoint` and `metadata_service` is true.
3. `exposed`: it is not `reachable`, and a canonical path of its footprint equals or
   lies beneath the canonical form of an exposure path, or its canonical endpoint is
   exposed.
4. `occupied`: a canonical path of its footprint equals or lies beneath the canonical
   form of an occupied path, or its canonical endpoint is covered by an occupied
   endpoint (except `gateway-ssh`, described above).
5. `collision`: its footprint collides with that of another relocated or custom decoy
   or of a decoy placed earlier.
6. `unprovisioned`: it is an `aws-access-key` decoy without a provided credential.

Every other decoy is placed. A skipped decoy's `location` is the candidate that was
checked: its layout choice, the first candidate when none was eligible, or null for
`helper-exec`. The request is invalid when the footprints of two relocated or custom
decoys collide, or two items of one of their footprints do; such a collision within a
layout candidate's footprint makes it ineligible and skips it as `collision` (see `component.md` for the reported
field). The result has exactly `operation`, `warnings` (in this order when
applicable: `seed-in-request`, and `public-socket-name` when `runtime-control` is
placed at any runtime's catalog candidate, compared canonically), `watch`, `material`, `companions`, and `skipped`
(objects with exactly `decoy_id`, `location`, and `reason`, in decoy order);
`material` and `companions` are defined in `credentials/spec.md`.

`watch` is the confidential, secret-free input to `evaluate`. It has exactly
`deployment_id`, `runtime`, `host_profile`, `path_aliases` (the effective list,
built-in first), `decoys`, and `retired` (`credentials/spec.md`). Each placed decoy
appears in `decoys` with exactly `decoy_id`, `kind`, `location` (after relocation;
null for `helper-exec`), `canonical_location` (null for `helper-exec`),
`companion_paths` (canonical paths of its companions), `listener`, `scope`, `name`, `fs_type`,
`fs_path` (null except for kernel interfaces; `fs_path` also null for
`cgroup-release-agent`), `reachable`, `technique`, `credential_format`, `epoch` (null
unless the credential is derived), and `canary_digest`.

## Requirement: Host decoys stay outside the sandbox boundary

The tripwire SHALL never plant a decoy that a sandbox can legitimately reach, other
than a boundary decoy, and SHALL never plant one over a real host asset, service, or
runtime-managed state.

### Scenario: gVisor on a cloud VM

- **WHEN** `plan` runs with request seed `SEED` for deployment `prod-agents`, runtime `gvisor`, host profile `linux-host`, metadata service `true`, gateway `172.17.0.1`, exposure paths `["/root/.ssh"]`, occupied `["/run/docker.sock"]`, and a provided credential for `cloud-credentials` with digest `P`
- **THEN** `watch.decoys` holds, in order, `cloud-credentials` at `/home/deploy/.aws/credentials` (canary digest `P`), `ssh-private-key` at `/home/deploy/.ssh/id_ed25519` (the only eligible candidate), `runtime-control` at `/run/runsc-debug.sock`, `docker-api`, `gateway-ssh` at `172.17.0.1:22` (reachable), the seven kernel interfaces, and `helper-exec`
- **AND** the `ssh-private-key` fingerprint is `SHA256:PXe4dd9+L8MO6NhKTT4snE3F6+FFwnoRJAVi5xXAPKc`, and `skipped` lists `container-socket` as `occupied` through the built-in alias and `metadata-endpoint` as `real-service`

### Scenario: Host-side share and open egress

- **WHEN** `plan` runs with request seed `SEED` for deployment `agents-2`, runtime `capsem`, host profile `linux-host`, metadata service `false`, exposure paths `["/root", "/home"]` (host homes shared into the guest), exposure endpoints `["169.254.0.0/16:*"]`, and occupied `["/var/run"]`
- **THEN** `cloud-credentials` (location `/root/.aws/credentials`), `ssh-private-key`, and `metadata-endpoint` are skipped as `exposed`, `container-socket` and `runtime-control` (location `/run/capsem-admin.sock`) as `occupied`, and `watch.decoys` holds `docker-api`, the seven kernel interfaces, and `helper-exec`

### Scenario: Kubernetes node with tailored decoys

- **WHEN** `plan` runs with request seed `SEED` for deployment `k8s-node-1`, runtime `kata`, host profile `kubernetes-node`, metadata service `false`, exclusion `["container-socket"]`, relocation of `runtime-control` to `/opt/kata/admin.sock`, custom decoy `ops-kubeconfig` of kind `credential-file` at `/home/ops/.kube/config` with technique `T1552.001` and format `kubeconfig-token`, and epoch 1 for `ops-kubeconfig`
- **THEN** `watch.decoys` lists `ssh-private-key` (at `/root/.ssh/id_ed25519`), `metadata-endpoint`, `runtime-control` (at `/opt/kata/admin.sock`), `kubeconfig` (at `/home/deploy/.kube/config`), `docker-api`, the seven kernel interfaces, `helper-exec`, and `ops-kubeconfig` (epoch 1), and `skipped` lists `cloud-credentials` as `unprovisioned` then `container-socket` as `excluded`
- **AND** the `ssh-private-key` fingerprint is `SHA256:7aoE+l0t+JNkUolH8Nm5Q9BV8ho7xPc9SqVM5nYyJQ0`, the `kubeconfig` token is `dsu5zv.c64q9jgo1id0wgj3`, the `ops-kubeconfig` token is `1helzq.owosf7a9dcehe9jo`, and `watch.retired` holds `ops-kubeconfig` epoch 0 with digest `db4c26aa97ab843ff292fe0828a1b818d86e01f1a9cd7976698db748ec4466c6`
