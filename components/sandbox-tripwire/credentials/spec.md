---
name: Decoy credentials
summary: Credential formats, rotation, context, companions, and cover files
kind: contract
---
# Decoy credentials

This document defines what planted credential decoys contain, how they rotate, and the
files that surround them. The catalog and `plan` are in `decoys/spec.md`.

## Formats

Each credential format has a **source** and an **identifier**, the value a monitored
log records when someone uses the credential. A decoy's `canary_digest` is the
lowercase hexadecimal SHA-256 of its identifier's UTF-8 bytes. Socket, endpoint, and
watched decoys have no material and a null `canary_digest`.

| Format | Source | Material fields | Identifier | Detection requires |
| --- | --- | --- | --- | --- |
| `aws-access-key` | provided | none; the operator holds the key | the access key ID | a real IAM access key whose policy denies everything, in the host's own account (so the key's account matches the host), whose audit trail including denied calls feeds `evaluate`. A key ID that exists in no account is never logged. |
| `ssh-ed25519` | derived | `private_key_seed`: lowercase hex of `derive("ed25519")`, the RFC 8032 private key; `public_key`: `ssh-ed25519 `, the standard base64 of the SSH public key blob (length-prefixed `ssh-ed25519`, then the length-prefixed 32-byte public key), a space, `OWNER@{host_name}`; `fingerprint` | `fingerprint`: `SHA256:` and the unpadded standard base64 of SHA-256 over that blob | OpenSSH servers at `LogLevel VERBOSE` on hosts an intruder would try, or an SSH honeypot. |
| `kubeconfig-token` | derived | `token`: map each of the first 22 bytes of `derive("token")` to `0123456789abcdefghijklmnopqrstuvwxyz` by value modulo 36; the first 6 characters, `.`, and the remaining 16. Also `cluster` (`context.cluster_name`), `server` (`https://` and `context.api_server`), `certificate_authority_data` (`context.cluster_ca_data`, without which clients refuse the server before sending the token), and `user` (`OWNER`). | `token` | a token authentication webhook or authenticating proxy that reports presented tokens; API server audit logs never contain tokens. |

`OWNER` is the account a real file at that location would belong to, judged on the
canonical location: `root` beneath `/root`, `NAME` beneath `/home/NAME` (both in
canonical form), and otherwise `dormant_user`, or `root` when
that is null.

Residual risks: some AWS APIs that reveal a key's identity are not logged, so a
cautious attacker can test the AWS key unseen, and the `kubeconfig-token` format is a
bootstrap-token shape that a Kubernetes-aware attacker may find unusual in a user's
kubeconfig.

A provided credential enters `plan` only as a digest, through `provided_credentials`
(objects with exactly `decoy_id`, naming an included `aws-access-key` decoy, and
`identifier_digest`, 64 lowercase hexadecimal characters). A derived credential uses
`derive(label)`: HMAC-SHA256 keyed with the UTF-8 seed over the UTF-8 bytes of
`deployment_id`, a line feed, the decoy's epoch in base 10, a line feed, `decoy_id`, a
line feed, and `label`.

`material` in the `plan` result holds one object per placed derived-credential decoy,
in decoy order, with exactly `decoy_id`, `credential_format`, `epoch`, and that
format's material fields.

## Rotation

A derived decoy's epoch defaults to 0; `epochs` (objects with exactly `decoy_id`,
naming an included derived-credential decoy, and `epoch`, an integer from 0 to 255)
overrides it, rotating that decoy alone. A credential stolen before a rotation, or
from a decoy a later plan no longer places, is still a canary, so it stays watched.
`watch.retired` lists, in one pass over decoys in decoy order: for each included derived decoy with epoch `e`,
the digests of epochs 0 to `e - 1`, and also of epoch `e` when the decoy is not placed;
for each included `aws-access-key` decoy that is not placed, its provided digest; then
each `retired_canaries` entry (objects with exactly `decoy_id`, `technique`, and
`canary_digest`) in request order. Its `decoy_id` names a credential-file catalog or custom decoy with
a null `technique`, or a former custom decoy (an identifier of the custom form that is
neither) with that decoy's technique, so credentials of a removed decoy stay watched.
To rotate a provided key, keep the old deny-all key in IAM, so its use is still
logged, and list its digest here. Each retired entry has exactly `decoy_id`, `kind`
(`credential-file`), `technique` (the decoy's), `epoch` (null when not derived), and
`canary_digest`. Each retired epoch adds about 170 to 220 bytes to `watch`, so derived decoys are rotated
rarely, during routine maintenance and never as a visible reaction to a contact. Every current and retired digest MUST be unique; otherwise the
request is invalid.

## Context

`context` grounds decoys in the host's own naming, because context-free decoys are
recognizable. It has exactly `host_name` (a lowercase DNS label), `dormant_user`,
`aws_region` (nonempty), `cluster_name`, `api_server`, and `cluster_ca_data` (the
standard base64 of the cluster's public CA certificate). These three are nonempty
strings without whitespace, required when a `kubeconfig-token` decoy is included and
not excluded, and otherwise null.

`dormant_user` is a POSIX user name (a lowercase letter or `_`, then up to 31 lowercase
letters, digits, `_`, or `-`) or null. It MUST name an account that exists only for
appearance: no login sessions, services, or tools run as it, so decoys at its default
credential paths hijack nothing. Never name an account whose AWS, SSH, or Kubernetes
tooling reads those paths: that tooling would pick up the decoy, fail, and raise false
alerts.

## Companions and cover files

A **companion** is a sibling file a real asset would have; without it a decoy looks
staged. `ssh-ed25519` has companion `LOCATION.pub` containing `public_key` and a line
feed. `aws-access-key` has companion `config` in the same directory containing
`[default]`, a line feed, `region = `, `aws_region`, and a line feed. Companions are
watched: contact with one is contact with its decoy, so a companion cannot be
inspected safely in its place.

A **cover file** is operator-written dressing that makes a decoy the obvious next step,
such as a README or runbook that mentions it: `cover_files` holds objects
with exactly `decoy_id` (an included planted decoy that is not `reachable`, since a
boundary decoy needs no cover story), `path`, and `content`. Cover files
are not watched, since people may read them. A cover file the sandbox can read would
point a sandboxed attacker at the host, so it makes its decoy exposed. Cover files with
the same path and content are one file shared by their decoys: they do not collide,
and `companions` lists it once, under the first placed decoy sharing it (or not at
all when none is placed).

`companions` in the `plan` result lists the files to create for placed decoys: objects
with exactly `decoy_id`, `path`, `content`, and `watched`, in decoy order, each decoy's
companions before its cover files.

A request is invalid when a `context` value, a relocation or custom decoy location, or
a cover file path or content contains, ignoring case, `canary`, `honeypot`,
`honeytoken`, `decoy`, or `tripwire`, because such words reveal the deception.

## Requirement: Decoy credentials are realistic, rotatable, and harmless to real tooling

The tripwire SHALL derive realistic, per-host credentials, keep rotated credentials
watched, and never place a credential decoy where a real account's tools would use it.

### Scenario: Cover story

- **WHEN** the gVisor cloud-VM plan in `decoys/spec.md` also has a cover file for `cloud-credentials` at `/home/deploy/docs/RUNBOOK.md` with content `Release cache credentials: ~/.aws/credentials\n`
- **THEN** `companions` lists `/home/deploy/.aws/config` (watched, content `[default]\nregion = us-east-1\n`), the runbook (not watched), and `/home/deploy/.ssh/id_ed25519.pub` (watched), in that order
- **AND** with exposure path `/home/deploy/docs` added, `cloud-credentials` is skipped as `exposed`, because the sandbox could read its cover story

### Scenario: No dormant account

- **WHEN** the gVisor cloud-VM plan runs with a null `dormant_user`
- **THEN** `ssh-private-key` has only its `/root` candidate and is skipped as `exposed`, and `cloud-credentials` is placed at `/root/.aws/credentials`

### Scenario: Stolen before rotation

- **GIVEN** the `watch` from the Kubernetes node plan in `decoys/spec.md`
- **WHEN** a token webhook reports event `r1`, a `credential-use` whose target is the digest of `57s1n9.u205saks22kzy6dz` (the epoch-0 token), `db4c26aa97ab843ff292fe0828a1b818d86e01f1a9cd7976698db748ec4466c6`
- **THEN** `r1/ops-kubeconfig` is `credential-exfiltrated` with techniques `["T1552.001", "T1078"]`
