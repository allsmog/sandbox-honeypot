---
name: Decoy planning
summary: Decoy catalog, locations, credential material, and the plan operation
kind: contract
---
# Decoy planning

This document defines which host decoys and tripwires exist, how their locations and
credentials are derived, and the `plan` operation of the Sandbox Escape Tripwire. The
shared request rules, secrets handling, threat model, scenario conventions, and failure
contract are in `component.md`.

## Decoy catalog

Each decoy has a stable `decoy_id`, a `kind`, one or more candidate `location`s, a
primary MITRE ATT&CK `technique`, and, for credential files, a `credential_format`.
Kinds are `credential-file`, `socket`, and `endpoint` (planted bait), and
`kernel-interface`: a real host interface that escape techniques write to, watched as
a tripwire rather than planted. Catalog order is the order of decoys in the result.
Every catalog `decoy_id` is reserved even when not included.

| `decoy_id` | `kind` | Candidate locations | `technique` | Format | Included when |
| --- | --- | --- | --- | --- | --- |
| `cloud-credentials` | `credential-file` | `/root/.aws/credentials`, `/home/{user}/.aws/credentials` | `T1552.001` | `aws-access-key` | always |
| `ssh-private-key` | `credential-file` | `/root/.ssh/id_ed25519`, `/home/{user}/.ssh/id_ed25519` | `T1552.004` | `ssh-ed25519` | always |
| `container-socket` | `socket` | `/var/run/docker.sock` | `T1552.007` | null | always |
| `metadata-endpoint` | `endpoint` | `169.254.169.254:80` | `T1552.005` | null | always |
| `runtime-control` | `socket` | per runtime, below | `T1611` | null | always |
| `kubeconfig` | `credential-file` | `/etc/kubernetes/admin.conf`, `/root/.kube/config`, `/home/{user}/.kube/config` | `T1552.001` | `kubeconfig-token` | `host_profile` is `kubernetes-node` |
| `docker-api` | `endpoint` | `127.0.0.1:2375` | `T1552.007` | null | always |
| `gateway-ssh` | `endpoint` | `{gateway}:22` | `T1021.004` | null | `sandbox_gateway` is not null |
| `core-pattern` | `kernel-interface` | `/proc/sys/kernel/core_pattern` | `T1611` | null | always |
| `modprobe-path` | `kernel-interface` | `/proc/sys/kernel/modprobe` | `T1611` | null | always |
| `uevent-helper` | `kernel-interface` | `/sys/kernel/uevent_helper` | `T1611` | null | always |
| `binfmt-register` | `kernel-interface` | `/proc/sys/fs/binfmt_misc/register` | `T1611` | null | always |
| `cgroup-release-agent` | `kernel-interface` | any `release_agent` beneath `/sys/fs/cgroup` | `T1611` | null | always |

`{user}` is `context.service_user`; `{gateway}` is `sandbox_gateway`. The default
`runtime-control` location sits directly in `/run`, outside any directory a runtime
manages: `gvisor` `/run/runsc-debug.sock`, `capsem` `/run/capsem-admin.sock`,
`firecracker` `/run/firecracker-api.sock`, `cloud-hypervisor`
`/run/cloud-hypervisor-api.sock`, `libkrun` `/run/libkrun-admin.sock`, `kata`
`/run/kata-admin.sock`, and `generic` `/run/sandbox-admin.sock`.

**Per-host layout.** A decoy with several candidates uses the one at index
`b mod n`, where `n` is the candidate count and `b` is the first byte of HMAC-SHA256
keyed with the seed over the UTF-8 bytes of `deployment_id`, a line feed, `layout`, a
line feed, and `decoy_id`. Operators SHOULD give each host its own `deployment_id`, so
layouts differ between hosts and an attacker cannot learn one host's decoys from
another.

`gateway-ssh` is a **boundary decoy**: an SSH listener on the sandbox network's host
gateway, the address escaping agents have used to reach host SSH. No legitimate
workload connects to it, so it is planted even where egress allows it (`reachable`
is true), and contact from a sandbox reports an escape attempt. Every other decoy has
`reachable` false.

A `kernel-interface` decoy is hit only by a write. `cgroup-release-agent` has
`scope` `name-beneath` with `name` `release_agent`: it matches any path beneath its
location whose final segment is that name. Every other decoy has `scope` `exact` and a
null `name`.

## Tailoring

- `exclude` lists catalog IDs to leave out. Every entry MUST be a catalog ID; an ID
  that is not included is accepted and has no effect.
- `relocate` moves included catalog decoys other than kernel interfaces: objects with
  exactly `decoy_id` and `location` (of the decoy's location type). It replaces the
  per-host layout choice.
- `custom_decoys` appends decoys after the catalog, in request order: objects with
  exactly `decoy_id` (lowercase ASCII letters and digits in hyphen-separated groups,
  at most 64 characters, not a catalog ID), `kind`, `location`, `technique` (`T` and
  four digits, optionally `.` and three digits), and `credential_format` (a format
  below for a `credential-file`, otherwise null). Custom decoys have one location,
  scope `exact`, and `reachable` false.

Credential-file, socket, and kernel-interface locations are paths; endpoint locations
are address endpoints. No two included decoys may share a canonical location. Each of
`exclude`, `relocate`, `epochs`, and `provided_credentials` names a decoy at most once.

## Paths, aliases, and endpoints

A path is absolute POSIX: it starts with `/`, contains no empty, `.`, or `..`
segment, and has no trailing `/` unless it is exactly `/`. "Beneath" always means on a
segment boundary. The effective alias list is the built-in alias `/var/run` → `/run`
followed by the request's `path_aliases` (objects with exactly `alias` and `target`).
It is valid only when every `alias` is distinct and no `target` equals or lies beneath
any `alias`. The **canonical** form of a path replaces its longest alias prefix with
that alias's target.

An address endpoint is `ADDRESS:PORT`: an IPv4 dotted quad or a bracketed IPv6
address, and a port from 1 to 65535. Its canonical form writes IPv4 in decimal without
leading zeros, IPv6 in RFC 5952 form, an IPv4-mapped IPv6 address as plain IPv4, and
the port without leading zeros. Host names are not endpoints.

An exposure endpoint is `SCOPE:PORTS`. `SCOPE` is an address, a CIDR block (IPv4
`a.b.c.d/n`, or IPv6 `[address]/n`), or `*`; `PORTS` is a port or `*`. A decoy
endpoint is exposed when its canonical address lies in the scope and its port is in
the ports. Egress rules that name hosts MUST be resolved to addresses by the operator.

## Credentials, context, and companions

Each credential format has a **source** and an **identifier**, the value a monitored
log records when someone uses the credential. A decoy's `canary_digest` is the
lowercase hexadecimal SHA-256 of its identifier's UTF-8 bytes.

| Format | Source | Material fields | Identifier | Detection requires |
| --- | --- | --- | --- | --- |
| `aws-access-key` | provided | none; the operator holds the key | the access key ID | a real IAM access key whose policy denies everything, in an account whose audit trail (including denied calls) feeds `evaluate`. A key ID that exists in no account is never logged. |
| `ssh-ed25519` | derived | `private_key_seed`: lowercase hex of `derive("ed25519")`, the RFC 8032 private key; `public_key`: `ssh-ed25519 `, the standard base64 of the SSH public key blob (length-prefixed `ssh-ed25519`, then the length-prefixed 32-byte public key), a space, `{user}@{organization}`; `fingerprint` | `fingerprint`: `SHA256:` and the unpadded standard base64 of SHA-256 over that blob | OpenSSH servers at `LogLevel VERBOSE` on hosts an intruder would try, or an SSH honeypot. |
| `kubeconfig-token` | derived | `token`: map each of the first 22 bytes of `derive("token")` to `0123456789abcdefghijklmnopqrstuvwxyz` by value modulo 36; the first 6 characters, `.`, and the remaining 16. Also `cluster` (`context.cluster_name`), `server` (`https://` and `context.api_server`), and `user` (`{user}`). | `token` | a token authentication webhook or authenticating proxy that reports presented tokens; API server audit logs never contain tokens. |

A provided credential enters `plan` only as a digest, through `provided_credentials`
(objects with exactly `decoy_id`, naming an `aws-access-key` decoy, and
`identifier_digest`, 64 lowercase hexadecimal characters). A derived credential uses
`derive(label)`: HMAC-SHA256 keyed with the UTF-8 seed over the UTF-8 bytes of
`deployment_id`, a line feed, the decoy's epoch in base 10, a line feed, `decoy_id`, a
line feed, and `label`. A decoy's epoch defaults to 0; `epochs` (objects with exactly
`decoy_id`, naming an included derived-credential decoy, and a nonnegative `epoch`)
overrides it, rotating that decoy alone.

`context` grounds decoys in the host's own naming, because context-free decoys are
recognizable. It has exactly `organization` (a lowercase DNS label), `service_user` (a
POSIX user name: a lowercase letter or `_`, then up to 31 lowercase letters, digits,
`_`, or `-`), `aws_region` (nonempty), `cluster_name`, and `api_server` (nonempty
strings without whitespace, required on `kubernetes-node` and otherwise null).

A **companion** is a sibling file a real asset would have; without it a decoy looks
staged. `ssh-ed25519` has companion `LOCATION.pub` containing `public_key` and a line
feed. `aws-access-key` has companion `config` in the same directory containing
`[default]`, a line feed, `region = `, `aws_region`, and a line feed.

A **cover file** is operator-written dressing that makes a decoy the obvious next step,
such as a runbook or a shell-history line that mentions it: `cover_files` holds objects
with exactly `decoy_id` (a planted decoy), `path`, and `content`. Companions and cover
files are not watched. A request is invalid when a `context` value, a custom decoy
location, or a cover file path or content contains, ignoring case, `canary`,
`honeypot`, `honeytoken`, `decoy`, or `tripwire`, because such words reveal the
deception.

Socket, endpoint, and kernel-interface decoys have no material and a null
`canary_digest`; they are detected by contact alone.

## Operation `plan`

Request fields: `operation` (`plan`); `deployment_id`; `runtime` (`gvisor`, `capsem`,
`firecracker`, `cloud-hypervisor`, `libkrun`, `kata`, or `generic`); `host_profile`
(`linux-host` or `kubernetes-node`); `host_environment` (`bare-metal` or `cloud-vm`);
optional `seed` (see `component.md`); `context`; `sandbox_gateway` (address or null);
`exposure`; `occupied`; `path_aliases`; `exclude`; `relocate`; `custom_decoys`;
`epochs`; `provided_credentials`; and `cover_files`.

`exposure` has exactly `paths` and `endpoints`. `paths` lists **host-side** paths any
sandbox can reach: the host sources of bind mounts, shared folders (virtio-fs or 9p),
overlay layers, and image or disk backing files, never paths as seen inside the guest.
`endpoints` lists exposure endpoints allowed by sandbox egress policy. `occupied` lists
paths (covering everything beneath them) and address endpoints used by real host
assets; directories a runtime manages SHOULD be listed.

Kernel-interface decoys are skipped only when excluded. Every other included decoy is
checked in this order and skipped with the first matching reason:

1. `excluded`: its `decoy_id` is in `exclude`.
2. `real-service`: it is `metadata-endpoint` on a `cloud-vm`, where that address is
   the real instance metadata service.
3. `exposed`: it is not `reachable`, and its canonical path, or that of one of its
   companions or cover files, equals or lies beneath the canonical form of an exposure
   path, or its canonical endpoint is exposed. A cover story the sandbox can read
   would point a sandboxed attacker at the host.
4. `occupied`: its canonical location or a companion's or cover file's canonical path
   equals or lies
   beneath the canonical form of an occupied path, or its canonical endpoint equals an
   occupied endpoint.
5. `unprovisioned`: it is an `aws-access-key` decoy without a provided credential.

Every other decoy is placed. The result has exactly `operation`, `warnings`
(`seed-in-request` when applicable, otherwise empty), `watch`, `material` (one object
per placed derived-credential decoy, in decoy order: `decoy_id`, `credential_format`,
`epoch`, and that format's fields), `companions` (objects with exactly `decoy_id`,
`path`, and `content`, in decoy order; each decoy's companions precede its cover files), and `skipped` (objects with exactly
`decoy_id`, `location`, and `reason`, in decoy order).

`watch` is the confidential, secret-free input to `evaluate`. It has exactly
`deployment_id`, `runtime`, `host_profile`, `host_environment`, `path_aliases` (the
effective list, built-in first), and `decoys`: one object per placed decoy with
exactly `decoy_id`, `kind`, `location`, `canonical_location`, `scope`, `name`,
`reachable`, `technique`, `credential_format`, `epoch` (null unless the credential is
derived), and `canary_digest`.

## Requirement: Host decoys stay outside the sandbox boundary

The tripwire SHALL never plant a decoy that a sandbox can legitimately reach, other
than a boundary decoy, and SHALL never plant one over a real host asset, service, or
runtime-managed state.

### Scenario: gVisor on a cloud VM

- **WHEN** `plan` runs with request seed `SEED` for deployment `prod-agents`, runtime `gvisor`, host profile `linux-host`, environment `cloud-vm`, gateway `172.17.0.1`, exposure paths `["/root/.ssh"]`, occupied `["/run/docker.sock"]`, and a provided credential for `cloud-credentials` with digest `P`
- **THEN** `material` is empty and `watch.decoys` holds `cloud-credentials` at `/home/deploy/.aws/credentials` (canary digest `P`), `runtime-control` at `/run/runsc-debug.sock`, `docker-api`, `gateway-ssh` at `172.17.0.1:22` (reachable), and the five kernel interfaces
- **AND** `companions` is only `/home/deploy/.aws/config` with content `[default]\nregion = us-east-1\n`, and `skipped` lists `ssh-private-key` as `exposed`, `container-socket` as `occupied` through the built-in alias, and `metadata-endpoint` as `real-service`

### Scenario: Host-side share and open egress

- **WHEN** `plan` runs with request seed `SEED` for deployment `agents-2`, runtime `capsem`, host profile `linux-host`, environment `bare-metal`, exposure paths `["/root"]` (the host source of the guest's `/workspace` share), exposure endpoints `["169.254.0.0/16:*"]`, and occupied `["/var/run"]`
- **THEN** `cloud-credentials` (at `/root/.aws/credentials`), `ssh-private-key`, and `metadata-endpoint` are skipped as `exposed`, `container-socket` and `runtime-control` as `occupied`, and `watch.decoys` holds only `docker-api` and the five kernel interfaces

### Scenario: Kubernetes node with tailored decoys

- **WHEN** `plan` runs with request seed `SEED` for deployment `k8s-node-1`, runtime `kata`, host profile `kubernetes-node`, environment `bare-metal`, exclusion `["container-socket"]`, relocation of `runtime-control` to `/opt/kata/admin.sock`, custom decoy `ops-kubeconfig` of kind `credential-file` at `/home/ops/.kube/config` with technique `T1552.001` and format `kubeconfig-token`, and epoch 1 for `ops-kubeconfig`
- **THEN** `watch.decoys` lists `ssh-private-key` (at `/root/.ssh/id_ed25519`), `metadata-endpoint`, `runtime-control` (at `/opt/kata/admin.sock`), `kubeconfig` (at `/etc/kubernetes/admin.conf`), `docker-api`, the five kernel interfaces, and `ops-kubeconfig` (epoch 1), and `skipped` lists `cloud-credentials` as `unprovisioned` then `container-socket` as `excluded`
- **AND** the `ssh-private-key` fingerprint is `SHA256:7aoE+l0t+JNkUolH8Nm5Q9BV8ho7xPc9SqVM5nYyJQ0` with companion `/root/.ssh/id_ed25519.pub`, the `kubeconfig` token is `dsu5zv.c64q9jgo1id0wgj3` with server `https://10.0.0.1:6443`, and the `ops-kubeconfig` token is `1helzq.owosf7a9dcehe9jo` (`57s1n9.u205saks22kzy6dz` at epoch 0)

### Scenario: Cover story

- **WHEN** the gVisor cloud-VM plan also has a cover file for `cloud-credentials` at `/home/deploy/docs/RUNBOOK.md` with content `Release cache credentials: ~/.aws/credentials\n`
- **THEN** `companions` lists `/home/deploy/.aws/config` and then the runbook with that content
- **AND** with exposure path `/home/deploy/docs` added, `cloud-credentials` is skipped as `exposed`, because the sandbox could read its cover story
