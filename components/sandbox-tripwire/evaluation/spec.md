---
name: Event evaluation
summary: The evaluate request, event shape, hits, and result
kind: contract
---
# Event evaluation

This document defines the `evaluate` request, the shape of host sensor events, which
events hit which decoys, and the result. Attribution, verdicts, and harness
identification are in `attribution/spec.md`; sources, authentication, batching, and
tamper evidence in `telemetry/spec.md`; scenario conventions in `component.md`.

## Request

A **process identity** is an object with exactly `pid` (positive integer: the process
ID, meaning the thread-group ID, in the initial PID namespace) and `start_ticks`
(nonnegative integer: the thread-group leader's start time in `USER_HZ` clock ticks
since boot, as in field 22 of `/proc/PID/stat`). Activity of any thread, including
kernel I/O workers acting for a process, is reported as that process. Identities are
equal only when both fields are, so a reused PID never matches.

| Field | Type | Meaning |
| --- | --- | --- |
| `operation` | string | `evaluate`. |
| `watch` | object | A `watch` object from a `plan` result. |
| `sandboxes` | array | Objects with exactly `sandbox_id`, `runtime_processes` (nonempty identities of that sandbox's runtime on the host, such as the gVisor sandbox and gofer or the VMM), and `harness_processes` (identities of the agent harness that drives it, possibly empty). Sandbox IDs and identities are unique. Operators keep listing a sandbox after it ends, until reboot, because escaped descendants can outlive it. |
| `suppressions` | array | Trusted maintenance: objects with exactly `decoy_id` (in `watch.decoys`), `executable` (path), `executable_digests` (nonempty array of 64 lowercase hex SHA-256 digests of acceptable versions of the executable file), `uid` (integer), and `value_digest` (64 lowercase hex for a kernel interface, null otherwise). |
| `expected_helpers` | array | Executables the kernel legitimately launches as user-mode helpers, checked at every exec by a depth-0 process and never a shell or general-purpose interpreter: objects with exactly `path` (the fully resolved file the kernel execs: on merged-`/usr` systems `/usr/bin/kmod`, not `/sbin/modprobe`) and `digests` (nonempty array of SHA-256 digests of acceptable versions of that file; for a script, of the script, not its interpreter). Operators add a new version's digest before upgrading the package that ships it. |
| `ignore_stat` | array of strings | Planted path decoys in `watch.decoys` for which `stat` on the decoy or its companions is not a hit, where people routinely long-list the directory. This trades away detection of metadata reconnaissance on those decoys. |
| `harness_signatures` | array | See `attribution/spec.md`. |
| `sources`, `probe`, `corroboration`, `authentication`, `sensor_keys`, `max_clock_skew_seconds`, `carry` | | See `telemetry/spec.md`; `sensor_keys` is optional. |
| `window` | object | Exactly `start` and `end` timestamps, `end` after `start`. It contains the events **received** from `start` (inclusive) to `end` (exclusive). |
| `decoy_inodes` | array | Objects with exactly `decoy_id` (a placed planted path decoy), `path` (its canonical location or one of its `companion_paths`), `device` and `inode` (decimal strings without leading zeros of the `st_dev` and `st_ino` values `stat(2)` returns, which can exceed 2^53) of the decoys as currently materialized; sensors report the same encoding, including the anonymous devices of btrfs subvolumes and overlay filesystems. Inode numbers are reused once freed, so operators MUST record new entries at every boot (device numbers of `tmpfs`, btrfs, overlay, and device-mapper filesystems change across boots) and every rotation and start a new batch there. Paths and device-inode pairs are unique. |
| `events` | array | Host sensor observations. |

Everything except the elements of `events` is validated strictly and fails the
request.

## Events

An event has exactly these fields. The first ten are **core**; the rest are
**detail**. Lengths are bytes of the value as RFC 8785 (JCS) serializes it, escapes
included and surrounding quotes excluded: identifiers and `target_fs.type` at most
256, `comm` at most 64, paths and targets at most 4096, and the `environment_names`
array, serialized whole, at most 2048; `ancestry` has at
most 64 entries. Sensors truncate longer values before signing, at a character
boundary, keeping the nearest 32 and farthest 32 entries of a longer `ancestry`, so a
deep chain of forks cannot push the host-side runtime or harness out of it. These
limits keep every event under 20 KiB, so attacker-chosen names cannot make an event too
large to submit.

| Field | Type | Meaning |
| --- | --- | --- |
| `event_id` | string | Sensor-assigned identifier. |
| `deployment_id` | string | MUST equal `watch.deployment_id`. |
| `time` | timestamp | When the action was observed. |
| `received` | timestamp | Stamped on arrival by the collector, never by the sensor; MUST lie in the window. |
| `source` | string | A source declared in `sources`. |
| `sensor_instance` | string | Identifies one run of the signer, such as a boot ID plus start time. |
| `sequence` | integer | The signer's counter for this source and instance, incremented for every event it ships. |
| `action` | string | One of the actions below. |
| `target` | string | What was acted on: a path, an address endpoint, or for `credential-use` the lowercase hexadecimal SHA-256 of the observed identifier, hashed by the collector so no credential reaches the request. For `rename`, `link`, and `delete`, the path of the existing object before the operation; a `rename` or `link` also yields an event whose target is the destination and whose `target_inode` is that of any object it replaces (for an exchange, each object's). |
| `mac` | string or null | See `telemetry/spec.md`. |
| `target_inode` | object or null | Exactly `device` and `inode` of the object, encoded as in `decoy_inodes`. Sensors MUST supply it whenever the operation reached an object; it is null for a refused lookup or a missing object. |
| `target_fs` | object or null | Exactly `type` (filesystem type, such as `proc` or `cgroup`) and `path` (path within that filesystem, without a leading `/`). |
| `target_digest` | string or null | For `exec`, the SHA-256 of the file named by the exec (for a script, the script), computed from the exec'd file object at exec time. |
| `written_digest` | string or null | For `write`, the SHA-256 of the bytes passed to that one `write(2)` call. |
| `actor` | object | Exactly `process` (identity or null), `ancestry` (identities of the creation chain recorded when each process was created, parent first, each the task that created the next even under `CLONE_PARENT`, including kernel threads and unaffected by later reparenting), `helper_depth` (0 when the kernel created this process to run a user-mode helper through `call_usermodehelper`, never for init or other kernel-thread children; `n` when its nearest such ancestor is its `n`th; otherwise null), `executable` (the path of the file the process exec'd, reported like a path target, or null when only a `/proc/PID/root` form exists; for a script run directly, the script), `executable_digest` (64 lowercase hex SHA-256 of that file, computed from the exec'd file object at exec time, or null), `uid` (effective user ID in the initial user namespace, or null), `comm` (string or null), `environment_names` (array of strings or null), and `sandbox_id` (string or null). |

Actions are `stat` (also `access`, `readlink`, and extended-attribute reads), `open`
(read-only), `open-write`, `read`, `write`, `truncate`, `exec`, `delete`, `rename`,
`link`, `attr` (changes of mode, owner, extended attributes, or timestamps), `mount`
(a mount in the initial mount namespace placed or moved onto the target), `notify-mark` (an
inotify or fanotify mark placed on the target, seen by `security_path_notify`),
`connect`, `credential-use`, and `heartbeat` (a liveness record, which never hits).
A mount or remount in any mount namespace that sets a cgroup `release_agent` option is
reported as a `write` with `target_fs` `{"type": "cgroup", "path": "release_agent"}`
and `written_digest` the SHA-256 of the option's value. A successful `execve` yields
one `exec` event, whatever interpreters it passes through.
Sensors MUST observe through LSM or kernel-function hooks on the object (such as
`security_file_open`, `security_inode_getattr`, `security_unix_stream_connect` for Unix
sockets, and `security_socket_connect` for network endpoints), not system-call
tracepoints, which miss `io_uring` operations; fanotify alone cannot observe `stat`,
failed opens, or socket `connect`. Sensors MUST also record attempts the kernel refuses
before those hooks run, such as an open denied by file mode or a lookup denied by a
directory's mode (for example with exit probes on `may_open` and path lookup), because
an unprivileged intruder's attempts on root-only decoys fail there; the target of a
refused lookup is the requested path made absolute against the working directory or
`dirfd`, with symlinks substituted as far as the walk got and `.` and `..` then
resolved lexically. Endpoint decoys MUST also be observed where connections arrive
(accepts on the decoy listener, netfilter or conntrack records for its address, or the
real server's logs when `listener` is false), because guests of VM and user-space
network sandboxes reach host endpoints without any host `connect`, and TCP fast-open
and raw packets bypass connect hooks. Such arrival sources report action `connect`,
the connecting sandbox in `actor.sandbox_id` when they can tell it, and, for a peer
socket on the same host, `actor` filled from the process owning that socket, so probes
and suppressions match them. Hooks always allow the operation (`stealth/spec.md`).
Sensors MUST drop in the kernel events that can never hit (actions other than `open-write`,
`write`, and `truncate` on kernel interfaces, `stat` on decoys in `ignore_stat`) and give each watched object
its own reserved buffer capacity, so flooding other files, or harmless actions on
watched ones, cannot turn a decoy hit into a sequence gap.

Sensors MUST report a path as an absolute path at which the same object is reachable
from the root of the initial mount namespace, whichever namespace or `chroot` the
actor used: through the object's own mount when that belongs to the initial namespace,
and otherwise through an initial-namespace mount of the same filesystem that contains
it (as for mounts copied by `unshare` or systemd sandboxing, bind mounts, and container
root filesystems). Only an object reachable by no such path is reported as
`/proc/PID/root` (PID being the actor's) followed by its path within the actor's root,
which no decoy location equals, so only an inode binding matches it, and a container's
own `/root/.aws` never does. A refused lookup is reported the same way, through the
mounts its walk crossed. Sensors MUST NOT report a connection to a loopback address
from a socket outside the initial network namespace, which cannot reach the host's
loopback. A `target` MUST be, or the event is rejected at `/target`:
the empty string for `heartbeat`; 64 lowercase hexadecimal characters for
`credential-use`; a path or an address endpoint for `connect`; and otherwise a string
starting with `/`, which is matched as a path even when truncated.
Text is UTF-8 with each invalid byte replaced by U+FFFD; an escaped lone surrogate is
an invalid value.
`environment_names` holds variable **names** only: sensors MUST NOT collect values.

An event with an invalid core field is **rejected** and recorded at the first invalid
field. An event with a valid core but an invalid detail field is evaluated with that
field treated as null (`actor` fields individually; `ancestry` as empty) and recorded
in `repaired`, so a crafted file name or environment cannot turn an attacker's own hit
into a rejection. An unknown event field is dropped and recorded in `repaired` the same way. A repeated object key makes
the request invalid at that object, except inside an element of `events`, where it
rejects that event at that object, so one forged event cannot void a batch. Events sharing an `event_id` are all evaluated; the ID is listed in
`duplicate_event_ids`, and each of their alert IDs gains `#` and the event's index.

## Hits

For matching, a path target is normalized (repeated `/` collapsed, a trailing `/`
removed, then `.` and `..` resolved lexically) and canonicalized under
`watch.path_aliases`; suppression and probe executables are canonicalized the same way
and, like `expected_helpers`, MUST name resolved files. An
endpoint target is canonicalized with `0.0.0.0` rewritten to `127.0.0.1` and `[::]` to
`[::1]`, the loopback addresses Linux connects them to. An accepted event **hits**:

- any decoy or `watch.retired` entry whose `canary_digest` equals `target`, when
  `action` is `credential-use`;
- a `kernel-interface` decoy, when `action` is `open-write`, `write`, or `truncate`
  and either the canonical target equals its `canonical_location` (scope `exact`) or
  lies beneath it with final segment `name` (scope `name-beneath`), or `target_fs.type`
  equals its `fs_type` and `target_fs.path` equals its `fs_path` (scope `exact`) or has
  final segment `name` (scope `name-beneath`);
- `helper-exec`, when `action` is `exec`, `actor.helper_depth` is 0, and no expected
  helper has a canonical `path` equal to the canonical target and a digest in `digests`
  equal to `target_digest`;
- a planted path decoy, when `action` is any action except `credential-use` and
  `heartbeat` (and `stat` for decoys in `ignore_stat`), and either `target_inode`
  equals a `decoy_inodes` entry of that decoy (catching hard links and bind mounts) or
  the canonical target equals its `canonical_location` or one of its
  `companion_paths`, or for `mount` is the parent directory of one of them (a `notify-mark` hits only on the
  object itself, since systemd and others mark directories such as `/run` routinely);
  or
- an endpoint decoy, when `action` is `connect` and the canonical target equals its
  `canonical_location`.

An event hits at most one decoy: inode matches take precedence over path matches,
then the first matching decoy in `watch.decoys` order, then retired entries in order.
An accepted non-`heartbeat` event that hits nothing is **ignored**. The same matching,
applied to whatever fields of a rejected event parse, lists it in `rejected_hits`
(`index` and `decoy_id`), because a malformed or forged event on a decoy needs
investigation. When a placed planted path decoy or one of its companions has no
`decoy_inodes` entry, the result warns `missing-inode-binding`; when an accepted event's
canonical target is a bound path but its non-null `target_inode` differs from that
path's binding, it warns `inode-binding-mismatch`, since a replaced decoy or a wrongly encoded
device would otherwise leave hard links and private mounts unmatched. A rejected event
whose `action` is invalid is matched under every rule its valid fields allow.

A hit is a **probe hit** when `probe` is not null, the decoy is planted, the action is
`stat`, `open`, `read`, or `connect`, and the actor's canonical `executable`,
`executable_digest`, and `uid` equal the probe's, and the decoy has no
`decoy_inodes` entry for the target's path or `target_inode` matches it. Otherwise it is **suppressed** when a
suppression names its `decoy_id`, the actor's non-null canonical `executable` and `uid`, and a
digest in `executable_digests` equal to the actor's non-null `executable_digest`, and, for a `write` to a kernel interface, the event's
`written_digest` equals the suppression's `value_digest`, so a maintenance tool
writing an unexpected value still alerts. `credential-use` and `helper-exec` hits are
never probe hits or suppressed, nor is a hit whose actor is a sandbox's runtime or
harness process, descends from one, or has a non-null `helper_depth`, nor one whose
`actor.process`, `ancestry`, or `helper_depth` was repaired. Every other hit is an
alert.

## Result

| Field | Meaning |
| --- | --- |
| `operation`, `deployment_id` | `evaluate`, and `watch.deployment_id`. |
| `warnings` | In this order, each when applicable: `keys-in-request`, `unauthenticated`, `missing-inode-binding`, `inode-binding-mismatch`. |
| `breached` | True when `alerts` or `rejected_hits` is nonempty, since a demoted hit still needs response. |
| `degraded` | True when `warnings` contains `missing-inode-binding` or `inode-binding-mismatch`, or any of `rejected`, `repaired`, `rejected_hits`, `duplicate_event_ids`, or the tamper lists is nonempty. |
| `alerts` | Ordered by `time` instant, then `event_id`, then index. |
| `incidents` | Alerts grouped by sandbox. |
| `suppressed` | Objects with exactly `event_id` and `decoy_id`, in event order. |
| `rejected`, `repaired` | Objects with exactly `index` and `field` (an RFC 6901 pointer within the event), ordered by index then field. |
| `rejected_hits` | Objects with exactly `index` and `decoy_id`, in index order. |
| `duplicate_event_ids` | In order of first occurrence. |
| `sequence_gaps`, `late_fills`, `sequence_duplicates`, `sensor_restarts`, `silence_gaps`, `watch_gaps`, `uncorroborated`, `clock_skew` | The tamper lists, defined in `telemetry/spec.md`. |
| `carry` | State for the next batch (`telemetry/spec.md`). |
| `probe_hits`, `ignored` | Counts. |

Each alert has exactly `alert_id` (`event_id`, `/`, `decoy_id`, plus any duplicate
suffix), `event_id`, `decoy_id`, `kind`, `location` (null for a retired entry),
`observed_target` (the event's `target`, but null for `credential-use`, so a credential
never reaches alert storage), `severity`, `verdict`, `techniques`, `sandbox_id`,
`attribution`, `harness`, `executable`, `uid`, `comm`, `time`, and `source`. Incidents
group alerts by `sandbox_id`, unattributed alerts forming one incident with null
`sandbox_id`; each has exactly `sandbox_id`, `first_seen` and `last_seen` (the `time`
of its first and last alerts), and `alert_ids` in alert order, ordered by `first_seen` instant, then `sandbox_id`, with the
unattributed incident last among equals. Timestamps are echoed exactly as received.
