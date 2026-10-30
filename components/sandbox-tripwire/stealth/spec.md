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
sensors, and responds to alerts (the operator in version 0.1.0); the engine itself has
no host side effects, and `plan` enforces the parts it can check.

## Decoys behave like the assets they imitate

- A credential-file decoy is an ordinary regular file whose owner, mode, size, and
  contents are realistic for its location and the host's own context. Reading it
  succeeds like reading any file, or fails with the same permission error a real file
  of that owner and mode gives.
- Timestamps can be made plausible, not faked: change and birth times cannot be set
  from user space, so decoys and companions SHOULD be materialized well before the
  tripwire is relied on, in the same pass as other host provisioning, with no access
  afterwards that changes any timestamp (probes open them with `O_NOATIME`).
- Companions are watched, so inspecting a decoy through its companion is a hit too.
- A socket or endpoint decoy accepts connections and answers its imitated protocol
  the way a real service that rejects the caller would, never with a banner, error,
  or delay unique to the decoy. Its listener's executable, account, service unit, and
  start time fit the service it imitates, since `ss -p` and `/proc` show them without
  a connection. Socket names SHOULD be site-specific (`relocate`),
  because the catalog's names are public (`plan` warns `public-socket-name`). An
  endpoint listener binds only its decoy address, so no other host address reaches it
  unwatched. On a host without a metadata service, the metadata decoy is reached
  through routing or address translation, never an interface address any user could
  list, and its backend runs in a network namespace no host process can reach directly.
- The dormant account looks used: a login shell, ordinary home contents with plausible
  timestamps created together with the decoys, and plausible login records (`lastlog`,
  `wtmp`). Its decoys' access times stay at materialization, since any
  read or timestamp change is a hit; an attacker comparing access times can notice
  this, an accepted residual risk.
- Decoys fit the platform: a metadata decoy only where DMI and cloud identity say the
  host is a cloud instance of that provider.
- A used decoy credential gets exactly the response a real credential without
  permissions gets: `AccessDenied` for the deny-all AWS key,
  `Permission denied (publickey)` for SSH, and `401` or `403` from Kubernetes.
  Identity details a caller can query, such as the IAM user name and path returned by
  `sts get-caller-identity`, look like a real service account.
- No decoy name, path, identity, or content contains a word or marker that reveals
  deception (such as canary, honey, decoy, trap, or tripwire), and no deployment
  reuses the public test values in this specification. `plan` rejects the most
  revealing words in operator-supplied text (`credentials/spec.md`).

## Observation is passive

- Sensors observe without interposing: their hooks always allow the operation
  (BPF-LSM programs that return the hook's default, kernel-function or exit probes), never fanotify
  permission events, blocking decisions, or access denials on decoys. A contact completes with the same
  result and no added latency an attacker could measure.
- Detection takes no inline action on the protected host: at the time of contact
  there is no process kill, network cut, login message, broadcast, file change, or
  locally visible log entry. Events leave the host in the routine telemetry stream,
  batched on a steady cadence of a few seconds, so a contact causes no distinctive
  burst of traffic.
- Responses such as containment, credential revocation, and host isolation are
  decided off the host. A response SHOULD resemble routine operations (for example a
  host drain or maintenance) rather than an immediate reaction to the touched decoy.
- Probes run on jittered schedules from processes that look like routine host
  maintenance, and also touch ordinary files, so neither their timing nor their
  targets mark which files are decoys.

## Decoy knowledge stays off the host

- Decoys sit where no filesystem snapshot readable on the host (btrfs, ZFS
  `.zfs/snapshot`, LVM) captures them, since a snapshot copies them to unwatched paths
  and dates their appearance. Exclusions that keep decoys out of backups and scanners
  name broad paths, such as the dormant account's whole home, and are root-only.
- `plan` and `evaluate` run on a system outside the protected host. `material` exists
  on the protected host only while decoys are materialized. `watch` holds no
  credential secrets but is confidential, because it lists which assets are decoys.
- Sensor and probe configuration that names decoy locations is readable only by root
  on the protected host, and SHOULD use rules broad enough (a directory or a class of files)
  that it does not enumerate decoys. Probes, materializers, and sensors never carry
  decoy paths in their arguments or environment, which other users can read in
  `/proc`. A host-root intruder can still dump sensor state,
  such as an inode set, so it also covers ordinary sensitive files, and decoy matching
  happens off-host in `evaluate`.
- No two hosts share decoy credentials, and with relocation no two share a layout: each
  host has its own `deployment_id`, so agents that pool what they learn across hosts cannot use one
  host's decoys to recognize another's.
- Every interaction an attacker can make with a decoy or its companions is a hit,
  including a metadata read (`stat`), so a decoy cannot be inspected safely before it
  is touched. Reading the containing directory's entries is not a hit, but a long
  listing (`ls -l`) stats each entry and is, unless the decoy is in `ignore_stat`.

## Known sources of false positives

Plan around these before relying on alerts: people listing directories that hold
decoys, since `ls -l`, colored `ls` (the default alias on many distributions), and
shell completion stat entries (prefer the dormant account's home, which nobody lists);
file-integrity monitors, antivirus, and secret scanners that open credential paths
(suppress them by executable, digest, and user, running interpreted scanners as
directly executed scripts, or keep decoys out of their scope); backups (exclude decoys
from them rather than suppressing the backup tool, which copies decoys elsewhere); the sensors' own file
access (exclude their processes in the sensor only by exact process identity, never by
digest, `comm`, or another name, since the engine's lineage checks never see an
excluded event); package upgrades that change a
suppressed executable's or expected helper's digest (add the new digest first);
monitoring agents that probe the Docker socket, Docker API, or metadata endpoint
(leave those opt-in decoys out); the materializer and decoy listeners themselves,
which stat, rotate, re-create, and change attributes of decoys (suppress them or
exclude them in the sensor the same way); legitimate kernel helpers such as `request-key` handlers,
`systemd-coredump`, apport, and orderly poweroff (list them in `expected_helpers`); boot-time writers of kernel interfaces, such as
`systemd-sysctl` and crash handlers writing `core_pattern`, `systemd-binfmt` writing
`register`, and systemd on cgroup v1 writing `release_agent` (suppress each with its
`value_digest`); containers outside any sandbox that share the
sandbox network's bridge and reach `gateway-ssh`; and rootless container tooling that
registers `binfmt_misc` formats in its own user namespace on recent kernels;
privileged CI steps that install emulators, such as `docker/setup-qemu-action` with
explicit platforms or `reset` (register emulators once at boot through `binfmt.d`
instead); on systemd before 258 in the pure cgroup v1 layout, the kernel running
`systemd-cgroups-agent` as a helper whenever a cgroup empties (list it in
`expected_helpers`); disk-usage scanners and desktop indexers that stat everything
under `/home`; indexers or on-access scanners that watch decoy directories for opens;
and suppressed tools or probes run with a loader or interpreter variable that
`evaluation/spec.md` lists, as many container images set `LD_LIBRARY_PATH` or
`PYTHONPATH` (clear them in the tool's unit). The probe prefix's interface and route are
visible to host users, so name them like ordinary infrastructure.
