---
name: Decoy planning
summary: Decoy catalog, path aliases, credential material, and the plan operation
kind: contract
---
# Decoy planning

This document defines which host decoys exist, how their locations and credentials
are derived, and the `plan` operation of the Sandbox Escape Tripwire. The shared
request rules, secrets handling, and failure contract are in `component.md`.

## Decoy catalog

Each decoy has a stable `decoy_id`, a `kind` (`credential-file`, `socket`, or
`endpoint`), a host `location`, a primary MITRE ATT&CK `technique`, and, for
credential files, a `credential_format`. The catalog order is the order of placed
and skipped decoys in the result. Every catalog `decoy_id` is reserved, even when the
selected host profile does not include it.

| `decoy_id` | `kind` | `location` | `technique` | `credential_format` | Included when |
| --- | --- | --- | --- | --- | --- |
| `cloud-credentials` | `credential-file` | `/root/.aws/credentials` | `T1552.001` | `aws-access-key` | always |
| `ssh-private-key` | `credential-file` | `/root/.ssh/id_ed25519` | `T1552.004` | `ssh-ed25519` | always |
| `container-socket` | `socket` | `/var/run/docker.sock` | `T1552.007` | null | always |
| `metadata-endpoint` | `endpoint` | `169.254.169.254:80` | `T1552.005` | null | always |
| `runtime-control` | `socket` | per runtime, below | `T1611` | null | always |
| `kubeconfig` | `credential-file` | `/etc/kubernetes/admin.conf` | `T1552.001` | `kubeconfig-token` | `host_profile` is `kubernetes-node` |

`runtime-control` location by `runtime`:

| `runtime` | `location` |
| --- | --- |
| `gvisor` | `/run/runsc/control.sock` |
| `capsem` | `/run/capsem/control.sock` |
| `firecracker` | `/run/firecracker/api.sock` |
| `kata` | `/run/kata-containers/shim.sock` |
| `generic` | `/run/sandbox/control.sock` |

Operators MAY add `custom_decoys` (appended after the catalog in request order) and
MAY drop catalog decoys with `exclude`. A custom decoy has exactly `decoy_id`
(lowercase ASCII letters and digits in hyphen-separated groups, at most 64
characters, not a catalog ID), `kind`, `location`, `technique` (`T` followed by four
digits, optionally `.` and three digits), and `credential_format`, which is one of the
three formats above for a `credential-file` and null otherwise. A `credential-file`
or `socket` location is a path; an `endpoint` location is an endpoint. No two included
decoys may share a canonical location.

## Locations and path aliases

A path is absolute POSIX: it starts with `/`, contains no empty, `.`, or `..`
segment, and has no trailing `/` unless it is exactly `/`. An endpoint is
`HOST:PORT`, where `PORT` is a base-10 integer from 1 to 65535; in exposure lists only,
`HOST:*` means every port on that host. Any other spelling is invalid.

A path alias maps an `alias` path to a `target` path, such as a symlinked directory.
The effective alias list is the built-in alias `/var/run` → `/run` followed by the
request's `path_aliases`. An alias set is valid only when every `alias` is distinct and
no `target` equals or lies beneath any `alias`, so one rewrite is always final. The
**canonical** form of a path replaces its longest alias prefix (matched on a segment
boundary) with that alias's target; a path with no alias prefix is already canonical.
Endpoints have no aliases. "Beneath" always means on a segment boundary: `/run/a` is
beneath `/run`, `/running` is not.

## Credential material and canaries

All credential material derives from `derive(label)`: HMAC-SHA256 keyed with the UTF-8
seed over the UTF-8 bytes of `deployment_id`, a line feed, `decoy_id`, a line feed,
and `label`. Each format defines its material and its **identifier**, the value a
sensor observes when the credential is used. The decoy's `canary_digest` is the
lowercase hexadecimal SHA-256 of the identifier's UTF-8 bytes.

| `credential_format` | Material fields | Identifier |
| --- | --- | --- |
| `aws-access-key` | `access_key_id`: `AKIA` and the first 16 characters of the RFC 4648 base32 (uppercase, unpadded) encoding of `derive("access-key-id")`; `secret_access_key`: the first 40 characters of the RFC 4648 standard base64 encoding of `derive("secret-access-key")` | `access_key_id`, as logged by cloud audit trails |
| `ssh-ed25519` | `private_key_seed`: lowercase hex of `derive("ed25519")`, the RFC 8032 Ed25519 private key; `public_key`: `ssh-ed25519 ` and the standard base64 of the SSH public key blob (length-prefixed `ssh-ed25519`, then the length-prefixed 32-byte public key) | `fingerprint`: `SHA256:` and the unpadded standard base64 of SHA-256 over that blob, as logged by OpenSSH |
| `kubeconfig-token` | `token`: map each of the first 22 bytes of `derive("token")` to `0123456789abcdefghijklmnopqrstuvwxyz` by value modulo 36; the first 6 characters, `.`, and the remaining 16 | `token`, as presented to an authenticating proxy or token webhook |

The `ssh-ed25519` material also includes `fingerprint`. Socket and endpoint decoys
have no material and a null `canary_digest`; they are detected by contact alone.

## Operation `plan`

Request fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `operation` | string | `plan`. |
| `deployment_id` | string | The protected deployment. |
| `runtime` | string | `gvisor`, `capsem`, `firecracker`, `kata`, or `generic`. |
| `host_profile` | string | `linux-host` or `kubernetes-node`. |
| `host_environment` | string | `bare-metal` or `cloud-vm`. |
| `seed` | string | Optional; see Secrets. |
| `exposure` | object | Exactly `paths` (paths mounted, shared, or otherwise visible inside any sandbox) and `endpoints` (endpoints allowed by sandbox egress policy). |
| `occupied` | array of strings | Paths or endpoints already used by real host assets. |
| `path_aliases` | array | Objects with exactly `alias` and `target`. |
| `custom_decoys` | array | Custom decoys as defined above. |
| `exclude` | array of strings | Catalog decoy IDs to leave out. |

Each included decoy is checked in this order and skipped with the first matching
reason:

1. `excluded`: its `decoy_id` is in `exclude`.
2. `real-service`: it is `metadata-endpoint` and `host_environment` is `cloud-vm`,
   where that address is the real instance metadata service.
3. `exposed`: its canonical path equals or lies beneath the canonical form of an
   exposure path, or its endpoint equals an exposure endpoint or matches an exposure
   `HOST:*`.
4. `occupied`: its canonical location equals the canonical form of an `occupied`
   entry.

Every other decoy is placed. The result has exactly these fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `operation` | string | `plan`. |
| `warnings` | array of strings | `seed-in-request` when applicable; otherwise empty. |
| `watch` | object | The non-secret input to `evaluate`. |
| `material` | array | One object per placed `credential-file` decoy, in decoy order: `decoy_id`, `credential_format`, and that format's material fields. |
| `skipped` | array | Objects with exactly `decoy_id`, `location`, and `reason`. |

`watch` has exactly `deployment_id`, `runtime`, `host_profile`, `host_environment`,
`path_aliases` (the effective list, built-in first), and `decoys`: one object per
placed decoy with exactly `decoy_id`, `kind`, `location`, `canonical_location`,
`technique`, `credential_format`, and `canary_digest`.

An empty `watch.decoys` list is a valid result; operators SHOULD treat it as a
deployment the tripwire cannot protect.

