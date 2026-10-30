---
name: Decoy planning
summary: Decoy catalog, locations, credential material, and the plan operation
kind: contract
---
# Decoy planning

This document defines which host decoys exist, how their locations and credentials
are derived, and the `plan` operation of the Sandbox Escape Tripwire. The shared
request rules, secrets handling, threat model, and failure contract are in
`component.md`.

## Decoy catalog

Each decoy has a stable `decoy_id`, a `kind` (`credential-file`, `socket`, or
`endpoint`), a host `location`, a primary MITRE ATT&CK `technique`, and, for
credential files, a `credential_format`. Catalog order is the order of placed and
skipped decoys in the result. Every catalog `decoy_id` is reserved, even when the
selected host profile does not include it.

| `decoy_id` | `kind` | `location` | `technique` | `credential_format` | Included when |
| --- | --- | --- | --- | --- | --- |
| `cloud-credentials` | `credential-file` | `/root/.aws/credentials` | `T1552.001` | `aws-access-key` | always |
| `ssh-private-key` | `credential-file` | `/root/.ssh/id_ed25519` | `T1552.004` | `ssh-ed25519` | always |
| `container-socket` | `socket` | `/var/run/docker.sock` | `T1552.007` | null | always |
| `metadata-endpoint` | `endpoint` | `169.254.169.254:80` | `T1552.005` | null | always |
| `runtime-control` | `socket` | per runtime, below | `T1611` | null | always |
| `kubeconfig` | `credential-file` | `/etc/kubernetes/admin.conf` | `T1552.001` | `kubeconfig-token` | `host_profile` is `kubernetes-node` |

The default `runtime-control` location sits directly in `/run`, outside any directory
a runtime manages, so the decoy cannot collide with real runtime state:

| `runtime` | `location` |
| --- | --- |
| `gvisor` | `/run/runsc-debug.sock` |
| `capsem` | `/run/capsem-admin.sock` |
| `firecracker` | `/run/firecracker-api.sock` |
| `kata` | `/run/kata-admin.sock` |
| `generic` | `/run/sandbox-admin.sock` |

Operators MAY tailor the catalog:

- `exclude` lists catalog IDs to leave out. Every entry MUST be a catalog ID; an ID
  the host profile does not include is accepted and has no effect.
- `relocate` moves catalog decoys: objects with exactly `decoy_id` (a catalog decoy
  included for the host profile) and `location` (of the decoy's location type).
- `custom_decoys` appends decoys after the catalog, in request order. A custom decoy
  has exactly `decoy_id` (lowercase ASCII letters and digits in hyphen-separated
  groups, at most 64 characters, not a catalog ID), `kind`, `location`, `technique`
  (`T` and four digits, optionally `.` and three digits), and `credential_format`,
  which is a format below for a `credential-file` and null otherwise.

A `credential-file` or `socket` location is a path; an `endpoint` location is an
address endpoint. No two included decoys may share a canonical location. Each of
`exclude`, `relocate`, `epochs`, and `provided_credentials` names a decoy at most once.

## Paths and path aliases

A path is absolute POSIX: it starts with `/`, contains no empty, `.`, or `..`
segment, and has no trailing `/` unless it is exactly `/`. "Beneath" always means on a
segment boundary: `/run/a` is beneath `/run`, `/running` is not.

A path alias maps an `alias` path to a `target` path, such as a symlinked directory or
a bind mount. The effective alias list is the built-in alias `/var/run` → `/run`
followed by the request's `path_aliases`. An alias set is valid only when every `alias`
is distinct and no `target` equals or lies beneath any `alias`, so one rewrite is
final. The **canonical** form of a path replaces its longest alias prefix with that
alias's target; a path with no alias prefix is already canonical.

## Endpoints

An address endpoint is `ADDRESS:PORT`. `ADDRESS` is an IPv4 dotted quad or an IPv6
address in brackets; `PORT` is a base-10 integer from 1 to 65535. The canonical form
writes IPv4 in decimal without leading zeros, writes IPv6 in RFC 5952 form, rewrites an
IPv4-mapped IPv6 address (`[::ffff:a.b.c.d]`) as plain IPv4, and writes the port
without leading zeros. Host names are not endpoints.

An exposure endpoint is `SCOPE:PORTS`. `SCOPE` is an address, a CIDR block (IPv4
`a.b.c.d/n`, or IPv6 `[address]/n`), or `*` for every address. `PORTS` is a port or
`*` for every port. A decoy endpoint is exposed when its canonical address lies in
the scope and its port is in the ports. Use `*:*` for unrestricted egress. Egress
rules that name hosts MUST be resolved to addresses by the operator.

## Credential material and canaries

Each credential format has a **source** and an **identifier**: the value a monitored
log records when someone uses the credential. A decoy's `canary_digest` is the
lowercase hexadecimal SHA-256 of its identifier's UTF-8 bytes.

| `credential_format` | Source | Material fields | Identifier | Detection requires |
| --- | --- | --- | --- | --- |
| `aws-access-key` | provided | none; the operator holds the key | the access key ID | a real IAM access key whose policy denies everything, in an account whose audit trail (including denied calls) feeds `evaluate`. A key ID that exists in no account is never logged anywhere. |
| `ssh-ed25519` | derived | `private_key_seed`: lowercase hex of `derive("ed25519")`, the RFC 8032 Ed25519 private key; `public_key`: `ssh-ed25519 ` and the standard base64 of the SSH public key blob (length-prefixed `ssh-ed25519`, then the length-prefixed 32-byte public key); `fingerprint` | `fingerprint`: `SHA256:` and the unpadded standard base64 of SHA-256 over that blob | OpenSSH servers at `LogLevel VERBOSE`, which logs the fingerprint of every offered key, on hosts an intruder would try, or an SSH honeypot. |
| `kubeconfig-token` | derived | `token`: map each of the first 22 bytes of `derive("token")` to `0123456789abcdefghijklmnopqrstuvwxyz` by value modulo 36; the first 6 characters, `.`, and the remaining 16 | `token` | a token authentication webhook or authenticating proxy that reports presented tokens. API server audit logs never contain tokens. |

A **provided** credential is created and monitored by the operator; `plan` receives
only its identifier digest through `provided_credentials` (objects with exactly
`decoy_id`, naming an `aws-access-key` decoy, and `identifier_digest`, 64 lowercase
hexadecimal characters). A **derived** credential uses
`derive(label)`: HMAC-SHA256 keyed with the UTF-8 seed over the UTF-8 bytes of
`deployment_id`, a line feed, the decoy's epoch in base 10, a line feed, `decoy_id`, a
line feed, and `label`.

A decoy's **epoch** defaults to 0. `epochs` (objects with exactly `decoy_id`, naming
an included derived-credential decoy, and `epoch`, a nonnegative integer) overrides it. Raising one
decoy's epoch rotates that decoy's derived credential without changing any other.

Socket and endpoint decoys have no material and a null `canary_digest`; they are
detected by contact alone.

## Operation `plan`

Request fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `operation` | string | `plan`. |
| `deployment_id` | string | The protected deployment. |
| `runtime` | string | `gvisor`, `capsem`, `firecracker`, `kata`, or `generic`. |
| `host_profile` | string | `linux-host` or `kubernetes-node`. |
| `host_environment` | string | `bare-metal` or `cloud-vm`. |
| `seed` | string | Optional; see Secrets in `component.md`. |
| `exposure` | object | Exactly `paths` and `endpoints`, defined below. |
| `occupied` | array of strings | Paths or address endpoints used by real host assets. |
| `path_aliases` | array | Objects with exactly `alias` and `target`. |
| `exclude`, `relocate`, `custom_decoys` | arrays | Catalog tailoring, defined above. |
| `epochs`, `provided_credentials` | arrays | Credential settings, defined above. |

`exposure.paths` lists **host-side** paths that any sandbox can reach: the host
sources of bind mounts, shared folders (virtio-fs or 9p), overlay layers, and image or
disk backing files. They are never paths as seen inside the guest: when a guest sees
`/workspace` backed by host `/srv/agents/ws`, the exposure path is `/srv/agents/ws`.
`exposure.endpoints` lists exposure endpoints allowed by sandbox egress policy.

`occupied` path entries cover everything beneath them. Directories a runtime manages,
such as a runtime's state root, SHOULD be listed. Occupied endpoints match exactly
after canonicalization.

Each included decoy is checked in this order and skipped with the first matching
reason:

1. `excluded`: its `decoy_id` is in `exclude`.
2. `real-service`: it is `metadata-endpoint` and `host_environment` is `cloud-vm`,
   where that address is the real instance metadata service.
3. `exposed`: its canonical path equals or lies beneath the canonical form of an
   exposure path, or its canonical endpoint is exposed.
4. `occupied`: its canonical path equals or lies beneath the canonical form of an
   occupied path, or its canonical endpoint equals an occupied endpoint.
5. `unprovisioned`: it is an `aws-access-key` decoy without a provided credential.

Every other decoy is placed. The result has exactly these fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `operation` | string | `plan`. |
| `warnings` | array of strings | `seed-in-request` when applicable; otherwise empty. |
| `watch` | object | The input to `evaluate`: free of credential secrets, but confidential. |
| `material` | array | One object per placed derived-credential decoy, in decoy order: `decoy_id`, `credential_format`, `epoch`, and that format's material fields. |
| `skipped` | array | Objects with exactly `decoy_id`, `location`, and `reason`, in decoy order. |

`watch` has exactly `deployment_id`, `runtime`, `host_profile`, `host_environment`,
`path_aliases` (the effective list, built-in first), and `decoys`: one object per
placed decoy with exactly `decoy_id`, `kind`, `location` (after relocation),
`canonical_location`, `technique`, `credential_format`, `epoch` (null unless the decoy
has a derived credential), and `canary_digest`.

An empty `watch.decoys` list is a valid result; operators SHOULD treat it as a
deployment the tripwire cannot protect.
