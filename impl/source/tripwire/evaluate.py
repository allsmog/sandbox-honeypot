"""The `evaluate` operation: validation, hits, outcomes, alerts, telemetry."""

from . import catalog as cat
from . import validate as v
from .attribution import Sandboxes, identify_harness, techniques, verdict
from .common import (Invalid, alias_conflict, beneath, canonical_path, format_endpoint,
                     is_duplicate, is_hex64, is_path, is_str, parse_endpoint, parse_json,
                     strip_repeated,
                     parse_timestamp, parent_dir, normalize_path, ptr, target_endpoint)
from .credentials import FORMATS
from .events import (Context, core_fault, loads_code, parse_view, repaired_under,
                     structural_fault)
from .telemetry import Hit, corroborate, sequences, silence, watch_gaps

# ------------------------------------------------------------ phase one

WATCH_DECOY = v.obj(
    ("decoy_id", v.decoy_id_form),
    ("kind", v.enum(*cat.KINDS)),
    ("location", v.nullable(v.location)),
    ("canonical_location", v.nullable(v.location)),
    ("companion_paths", v.array_of(v.path)),
    ("listener", v.boolean),
    ("scope", v.enum("exact", "name-beneath")),
    ("name", v.nullable(v.nonempty_string)),
    ("fs_type", v.nullable(v.nonempty_string)),
    ("fs_path", v.nullable(v.string)),
    ("reachable", v.boolean),
    ("technique", v.technique),
    ("credential_format", v.nullable(v.enum(*FORMATS))),
    ("epoch", v.nullable(v.integer(0, 255))),
    ("canary_digest", v.nullable(v.hex64)),
)

WATCH = v.obj(
    ("deployment_id", v.identifier),
    ("runtime", v.enum(*cat.RUNTIMES)),
    ("host_profile", v.enum(*cat.HOST_PROFILES)),
    ("path_aliases", v.array_of(v.obj(("alias", v.path), ("target", v.path)))),
    ("decoys", v.array_of(WATCH_DECOY)),
    ("retired", v.array_of(v.obj(
        ("decoy_id", v.decoy_id_form),
        ("kind", v.enum("credential-file")),
        ("technique", v.technique),
        ("epoch", v.nullable(v.integer(0, 255))),
        ("canary_digest", v.hex64)))),
)


def _sensor_keys(value, pointer):
    if not isinstance(value, dict) or is_duplicate(value):
        raise Invalid(pointer)
    for key in sorted(value):
        if not is_str(key) or not is_hex64(value[key]):
            raise Invalid(ptr(pointer, key))


def _array(value, pointer):
    if not isinstance(value, list):
        raise Invalid(pointer)


HIT_FIELDS = (("event_id", v.identifier), ("decoy_id", v.identifier),
              ("source", v.identifier), ("time", v.timestamp), ("received", v.timestamp))

CARRY = v.obj(
    ("window_end", v.timestamp),
    ("sequences", v.array_of(v.obj(
        ("source", v.identifier),
        ("sensor_instance", v.identifier),
        ("highest", v.integer()),
        ("missing", v.array_of(v.obj(("from", v.integer(1)), ("to", v.integer(1))),
                               0, 16)),
        ("last_received", v.timestamp)))),
    ("last_seen", v.array_of(v.obj(("source", v.identifier), ("received", v.timestamp)))),
    ("last_probe", v.array_of(v.obj(("decoy_id", v.identifier),
                                    ("received", v.timestamp)))),
    ("recent_hits", v.array_of(v.obj(*HIT_FIELDS))),
    ("pending", v.array_of(v.obj(*(HIT_FIELDS + (
        ("missing_sources", v.array_of(v.identifier)),))))),
)

EVALUATE_FIELDS = v.fields(
    ("operation", v.enum("evaluate")),
    ("watch", WATCH),
    ("sandboxes", v.array_of(v.obj(
        ("sandbox_id", v.identifier),
        ("runtime_processes", v.array_of(v.identity, 1)),
        ("harness_processes", v.array_of(v.identity))))),
    ("suppressions", v.array_of(v.obj(
        ("decoy_id", v.identifier),
        ("executable", v.path),
        ("executable_digests", v.array_of(v.hex64, 1)),
        ("uid", v.integer()),
        ("value_digest", v.nullable(v.hex64))))),
    ("expected_helpers", v.array_of(v.obj(("path", v.path),
                                          ("digests", v.array_of(v.hex64, 1))))),
    ("ignore_stat", v.array_of(v.identifier)),
    ("harness_signatures", v.array_of(v.obj(
        ("harness_id", v.identifier),
        ("environment_names", v.array_of(v.string)),
        ("executables", v.array_of(v.string))))),
    ("sources", v.array_of(v.obj(
        ("source", v.identifier),
        ("signer", v.enum("sensor", "collector")),
        ("max_silence_seconds", v.nullable(v.integer(1))),
        ("max_delay_seconds", v.integer(1))))),
    ("probe", v.nullable(v.obj(
        ("executable", v.path),
        ("executable_digest", v.hex64),
        ("uid", v.integer()),
        ("max_interval_seconds", v.integer(1))))),
    ("corroboration", v.nullable(v.obj(
        ("window_seconds", v.integer(1)),
        ("decoys", v.array_of(v.obj(("decoy_id", v.identifier),
                                    ("sources", v.array_of(v.identifier, 2)))))))),
    ("authentication", v.enum("required", "off")),
    ("sensor_keys", _sensor_keys, False),
    ("max_clock_skew_seconds", v.integer(1)),
    ("carry", v.nullable(CARRY)),
    ("window", v.obj(("start", v.timestamp), ("end", v.timestamp))),
    ("decoy_inodes", v.array_of(v.obj(
        ("decoy_id", v.identifier),
        ("path", v.path),
        ("device", v.decimal_string),
        ("inode", v.decimal_string)))),
    ("events", _array),
)


# ------------------------------------------------------------ phase two

def _rule1(req, env):
    if req["authentication"] != "required":
        return None
    in_request = "sensor_keys" in req
    in_env = "SANDBOX_HONEYPOT_SENSOR_KEYS" in env
    if in_request == in_env:
        raise Invalid("/sensor_keys")
    if in_request:
        keys = req["sensor_keys"]
    else:
        try:
            keys = parse_json(env["SANDBOX_HONEYPOT_SENSOR_KEYS"])
        except (ValueError, RecursionError):
            raise Invalid("/sensor_keys")
        if not isinstance(keys, dict) or is_duplicate(keys) or not all(
                is_str(k) and is_hex64(val) for k, val in keys.items()):
            raise Invalid("/sensor_keys")
    declared = {s["source"] for s in req["sources"]}
    if set(keys) != declared:
        raise Invalid("/sensor_keys")
    return dict(keys)


def _canonical_of(location, aliases):
    if location is None:
        return None
    if is_path(location):
        return canonical_path(location, aliases)
    return format_endpoint(parse_endpoint(location))


def _rule2(watch):
    seen = set()
    for i, decoy in enumerate(watch["decoys"]):
        if decoy["decoy_id"] in seen:
            raise Invalid(ptr("/watch/decoys", i, "decoy_id"))
        seen.add(decoy["decoy_id"])
    aliases = [(a["alias"], a["target"]) for a in watch["path_aliases"]]
    conflict = alias_conflict(aliases)
    if conflict is not None:
        raise Invalid(ptr("/watch/path_aliases", conflict[0], conflict[1]))
    for i, decoy in enumerate(watch["decoys"]):
        if _canonical_of(decoy["location"], aliases) != decoy["canonical_location"]:
            raise Invalid(ptr("/watch/decoys", i, "canonical_location"))
    digests = [(d["canary_digest"], ptr("/watch/decoys", i, "canary_digest"))
               for i, d in enumerate(watch["decoys"]) if d["canary_digest"] is not None]
    digests += [(r["canary_digest"], ptr("/watch/retired", i, "canary_digest"))
                for i, r in enumerate(watch["retired"])]
    seen = set()
    for digest, pointer in digests:
        if digest in seen:
            raise Invalid(pointer)
        seen.add(digest)


def _rule3(req):
    start = parse_timestamp(req["window"]["start"])
    end = parse_timestamp(req["window"]["end"])
    if end <= start:
        raise Invalid("/window/end")
    carry = req["carry"]
    if carry is not None and parse_timestamp(carry["window_end"]) != start:
        raise Invalid("/window/start")


def _rule4(req):
    runtime_seen, harness_seen, ids = set(), set(), set()
    for i, sandbox in enumerate(req["sandboxes"]):
        if sandbox["sandbox_id"] in ids:
            raise Invalid(ptr("/sandboxes", i, "sandbox_id"))
        ids.add(sandbox["sandbox_id"])
        for j, proc in enumerate(sandbox["runtime_processes"]):
            key = v.identity_key(proc)
            if key in runtime_seen or key in harness_seen:
                raise Invalid(ptr("/sandboxes", i, "runtime_processes", j))
            runtime_seen.add(key)
        for j, proc in enumerate(sandbox["harness_processes"]):
            key = v.identity_key(proc)
            if key in runtime_seen:
                raise Invalid(ptr("/sandboxes", i, "harness_processes", j))
            harness_seen.add(key)
    checks = [
        [(x, ptr("/ignore_stat", i)) for i, x in enumerate(req["ignore_stat"])],
        [(h["harness_id"], ptr("/harness_signatures", i, "harness_id"))
         for i, h in enumerate(req["harness_signatures"])],
        [(s["source"], ptr("/sources", i, "source")) for i, s in enumerate(req["sources"])],
    ]
    if req["corroboration"] is not None:
        checks.append([(d["decoy_id"], ptr("/corroboration/decoys", i, "decoy_id"))
                       for i, d in enumerate(req["corroboration"]["decoys"])])
    for values in checks:
        seen = set()
        for key, pointer in values:
            if key in seen:
                raise Invalid(pointer)
            seen.add(key)
    per_path = {}
    current_pairs = set()
    for i, entry in enumerate(req["decoy_inodes"]):
        pair = (entry["device"], entry["inode"])
        earlier = per_path.setdefault(entry["path"], [])
        if len(earlier) >= 2 or (earlier and earlier[0] == pair):
            raise Invalid(ptr("/decoy_inodes", i))
        if not earlier:
            if pair in current_pairs:
                raise Invalid(ptr("/decoy_inodes", i))
            current_pairs.add(pair)
        earlier.append(pair)


def _rule5(req, decoys, declared):
    for i, s in enumerate(req["suppressions"]):
        decoy = decoys.get(s["decoy_id"])
        if decoy is None:
            raise Invalid(ptr("/suppressions", i, "decoy_id"))
        if (decoy["kind"] == "kernel-interface") != (s["value_digest"] is not None):
            raise Invalid(ptr("/suppressions", i, "value_digest"))
    for i, decoy_id in enumerate(req["ignore_stat"]):
        decoy = decoys.get(decoy_id)
        if decoy is None or decoy["kind"] not in cat.PATH_KINDS:
            raise Invalid(ptr("/ignore_stat", i))
    if req["corroboration"] is not None:
        for i, entry in enumerate(req["corroboration"]["decoys"]):
            decoy = decoys.get(entry["decoy_id"])
            if decoy is None or decoy["kind"] not in cat.PLANTED_KINDS + ("kernel-interface",):
                raise Invalid(ptr("/corroboration/decoys", i, "decoy_id"))
            for j, source in enumerate(entry["sources"]):
                if source not in declared:
                    raise Invalid(ptr("/corroboration/decoys", i, "sources", j))
    for i, entry in enumerate(req["decoy_inodes"]):
        decoy = decoys.get(entry["decoy_id"])
        if decoy is None or decoy["kind"] not in cat.PATH_KINDS:
            raise Invalid(ptr("/decoy_inodes", i, "decoy_id"))


def _rule10(req, decoys):
    for i, sig in enumerate(req["harness_signatures"]):
        if not sig["environment_names"] and not sig["executables"]:
            raise Invalid(ptr("/harness_signatures", i, "executables"))
    if req["corroboration"] is not None:
        for i, entry in enumerate(req["corroboration"]["decoys"]):
            seen = set()
            for j, source in enumerate(entry["sources"]):
                if source in seen:
                    raise Invalid(ptr("/corroboration/decoys", i, "sources", j))
                seen.add(source)
    carry = req["carry"]
    if carry is not None:
        seen = set()
        for i, entry in enumerate(carry["sequences"]):
            key = (entry["source"], entry["sensor_instance"])
            if key in seen:
                raise Invalid(ptr("/carry/sequences", i, "sensor_instance"))
            seen.add(key)
            for j, rng in enumerate(entry["missing"]):
                if not rng["from"] <= rng["to"] < entry["highest"]:
                    raise Invalid(ptr("/carry/sequences", i, "missing", j, "to"))
        for name, field in (("last_seen", "source"), ("last_probe", "decoy_id")):
            seen = set()
            for i, entry in enumerate(carry[name]):
                if entry[field] in seen:
                    raise Invalid(ptr("/carry", name, i, field))
                seen.add(entry[field])
    for i, entry in enumerate(req["decoy_inodes"]):
        decoy = decoys[entry["decoy_id"]]
        if entry["path"] != decoy["canonical_location"] and \
                entry["path"] not in decoy["companion_paths"]:
            raise Invalid(ptr("/decoy_inodes", i, "path"))


# ------------------------------------------------------------ evaluation

class Evaluator:
    def __init__(self, req, keys):
        self.req = req
        watch = req["watch"]
        self.watch = watch
        self.aliases = [(a["alias"], a["target"]) for a in watch["path_aliases"]]
        self.decoys = watch["decoys"]
        self.retired = watch["retired"]
        self.ignore_stat = set(req["ignore_stat"])
        self.sandboxes = Sandboxes(req["sandboxes"])
        self.sources = {s["source"]: s for s in req["sources"]}
        self.window_start = (parse_timestamp(req["window"]["start"]), req["window"]["start"])
        self.window_end = (parse_timestamp(req["window"]["end"]), req["window"]["end"])
        self.ctx = Context(watch["deployment_id"], self.window_start[0], self.window_end[0],
                           set(self.sources), req["authentication"] == "required", keys)
        self.helpers = [(self.canon(h["path"]), set(h["digests"]))
                        for h in req["expected_helpers"]]
        self.bindings = self._effective_bindings(req["decoy_inodes"])
        probe = req["probe"]
        self.probe = probe
        if probe is not None:
            self.probe_exe = self.canon(probe["executable"])

    def canon(self, path):
        return canonical_path(path, self.aliases)

    @staticmethod
    def _effective_bindings(entries):
        """path -> [(decoy_id, (device, inode))], dropping a previous entry
        whose pair is another path's current pair."""
        per_path = {}
        for entry in entries:
            per_path.setdefault(entry["path"], []).append(
                (entry["decoy_id"], (entry["device"], entry["inode"])))
        current = {path: items[0][1] for path, items in per_path.items()}
        out = {}
        for path, items in per_path.items():
            kept = [items[0]]
            for item in items[1:]:
                if not any(pair == item[1] for other, pair in current.items()
                           if other != path):
                    kept.append(item)
            out[path] = kept
        return out

    def _decoy_pairs(self, decoy_id):
        return [pair for items in self.bindings.values()
                for owner, pair in items if owner == decoy_id]

    def target_forms(self, target):
        """Return (canonical path or None, canonical endpoint text or None)."""
        if target is None:
            return None, None
        if target.startswith("/"):
            return self.canon(normalize_path(target)), None
        endpoint = parse_endpoint(target)
        if endpoint is None:
            return None, None
        return None, format_endpoint(target_endpoint(endpoint))

    def match(self, view):
        """Return (entry, is_retired) of the decoy or retired entry hit."""
        action = view.action

        def allows(*names):
            return action is None or action in names

        path, endpoint = self.target_forms(view.target)
        if action == "heartbeat":
            return None, False
        inode_hits, other_hits = [], []
        for decoy in self.decoys:
            kind = decoy["kind"]
            if (allows("credential-use") and decoy["canary_digest"] is not None
                    and view.target == decoy["canary_digest"]):
                other_hits.append(decoy)
                continue
            if kind in cat.PATH_KINDS:
                if action == "credential-use":
                    continue
                if action == "stat" and decoy["decoy_id"] in self.ignore_stat:
                    continue
                if view.target_inode is not None and \
                        view.target_inode in self._decoy_pairs(decoy["decoy_id"]):
                    inode_hits.append(decoy)
                    continue
                if path is None:
                    continue
                own = [decoy["canonical_location"]] + list(decoy["companion_paths"])
                if path in own or (allows("mount", "notify-mark")
                                   and any(parent_dir(p) == path for p in own)):
                    other_hits.append(decoy)
            elif kind == "endpoint":
                if allows("connect") and endpoint is not None \
                        and endpoint == decoy["canonical_location"]:
                    other_hits.append(decoy)
            elif kind == "kernel-interface":
                if allows("open-write", "write", "truncate") and \
                        self._kernel_match(decoy, path, view.target_fs):
                    other_hits.append(decoy)
            elif kind == "kernel-helper":
                if allows("exec") and view.actor["helper_depth"] == 0 and path is not None \
                        and not any(p == path and view.target_digest in digests
                                    for p, digests in self.helpers):
                    other_hits.append(decoy)
        if inode_hits:
            return inode_hits[0], False
        if other_hits:
            return other_hits[0], False
        if allows("credential-use"):
            for entry in self.retired:
                if view.target == entry["canary_digest"]:
                    return entry, True
        return None, False

    @staticmethod
    def _kernel_match(decoy, path, target_fs):
        exact = decoy["scope"] == "exact"
        location = decoy["canonical_location"]
        if path is not None and location is not None:
            if exact and path == location:
                return True
            if not exact and beneath(path, location) and \
                    path.rsplit("/", 1)[-1] == decoy["name"]:
                return True
        if target_fs is not None and decoy["fs_type"] is not None \
                and target_fs[0] == decoy["fs_type"]:
            if exact and target_fs[1] == decoy["fs_path"]:
                return True
            if not exact and target_fs[1].rsplit("/", 1)[-1] == decoy["name"]:
                return True
        return False

    def _binding_ok(self, decoy, view):
        """No binding of this decoy for the target's path, or the event's
        inode matches one of them."""
        path, _ = self.target_forms(view.target)
        if path is None:
            return True
        pairs = [pair for owner, pair in self.bindings.get(path, [])
                 if owner == decoy["decoy_id"]]
        return not pairs or view.target_inode in pairs

    def _trust_excluded(self, view):
        actor = view.actor
        return (self.sandboxes.lineage_trusted_out(actor)
                or actor["helper_depth"] is not None
                or repaired_under(view, "process") or repaired_under(view, "ancestry")
                or repaired_under(view, "helper_depth")
                or repaired_under(view, "environment_names")
                or loads_code(actor["environment_names"]))

    def _actor_exe(self, view):
        exe = view.actor["executable"]
        return None if exe is None else self.canon(normalize_path(exe))

    def outcome(self, view, decoy):
        """'probe', 'suppressed', or 'alert' for a hit on a current decoy."""
        kind = decoy["kind"]
        if view.action == "credential-use" or kind == "kernel-helper":
            return "alert"
        if self._trust_excluded(view):
            return "alert"
        actor = view.actor
        exe = self._actor_exe(view)
        probe = self.probe
        if (probe is not None and kind in cat.PLANTED_KINDS
                and view.action in ("stat", "open", "read", "connect")
                and exe == self.probe_exe
                and actor["executable_digest"] == probe["executable_digest"]
                and actor["uid"] is not None and actor["uid"] == probe["uid"]
                and self._binding_ok(decoy, view)):
            return "probe"
        if exe is None or actor["uid"] is None or actor["executable_digest"] is None:
            return "alert"
        for s in self.req["suppressions"]:
            if s["decoy_id"] != decoy["decoy_id"] or self.canon(s["executable"]) != exe:
                continue
            if s["uid"] != actor["uid"] or \
                    actor["executable_digest"] not in s["executable_digests"]:
                continue
            if kind == "kernel-interface" and view.action == "write" and \
                    view.written_digest != s["value_digest"]:
                continue
            return "suppressed"
        return "alert"

    def own_location_probe(self, decoy, view):
        path, endpoint = self.target_forms(view.target)
        location = decoy["canonical_location"]
        if decoy["kind"] == "endpoint":
            return endpoint == location
        if path == location:
            return True
        return view.target_inode is not None and any(
            owner == decoy["decoy_id"] and pair == view.target_inode
            for owner, pair in self.bindings.get(location, []))

    def run(self):
        req = self.req
        accepted, rejected, repaired, rejected_hits = [], [], [], []
        for index, event in enumerate(req["events"]):
            if not isinstance(event, dict):
                rejected.append({"index": index, "field": ""})
                continue
            fault = structural_fault(event)
            if fault is None:
                fault = core_fault(event, self.ctx)
            if fault is not None:
                rejected.append({"index": index, "field": fault})
                view = parse_view(strip_repeated(event), self.ctx, False)
                entry, _ = self.match(view)
                if entry is not None:
                    rejected_hits.append({"index": index, "decoy_id": entry["decoy_id"]})
                continue
            view = parse_view(event, self.ctx, True)
            view.index = index
            for pointer in sorted(set(view.repaired)):
                repaired.append({"index": index, "field": pointer})
            accepted.append(view)

        counts = {}
        for view in accepted:
            counts[view.event_id] = counts.get(view.event_id, 0) + 1
        duplicate_ids = []
        for view in accepted:
            if counts[view.event_id] > 1 and view.event_id not in duplicate_ids:
                duplicate_ids.append(view.event_id)

        warnings = []
        if "sensor_keys" in req and req["authentication"] == "required":
            warnings.append("keys-in-request")
        if req["authentication"] == "off":
            warnings.append("unauthenticated")
        bound_paths = {e["path"] for e in req["decoy_inodes"]}
        missing_binding = False
        for decoy in self.decoys:
            if decoy["kind"] in cat.PATH_KINDS:
                for path in [decoy["canonical_location"]] + list(decoy["companion_paths"]):
                    if not any(owner == decoy["decoy_id"]
                               for owner, _ in self.bindings.get(path, [])):
                        missing_binding = True
        if missing_binding:
            warnings.append("missing-inode-binding")

        alerts, suppressed, batch_hits = [], [], []
        probe_times = {}
        probe_hits = ignored = 0
        mismatch = False
        planted_ids = [d["decoy_id"] for d in self.decoys if d["kind"] in cat.PLANTED_KINDS]
        signatures = req["harness_signatures"]
        for view in accepted:
            path, _ = self.target_forms(view.target)
            if path is not None and path in bound_paths and view.target_inode is not None \
                    and view.action not in ("heartbeat", "credential-use") \
                    and view.target_inode not in [p for _, p in self.bindings[path]]:
                mismatch = True
            entry, is_retired = self.match(view)
            if entry is None:
                if view.action != "heartbeat":
                    ignored += 1
                continue
            decoy_id = entry["decoy_id"]
            if not is_retired and view.action != "credential-use":
                batch_hits.append(Hit(view.event_id, decoy_id, view.source, view.time,
                                      view.received, index=view.index))
            result = "alert" if is_retired else self.outcome(view, entry)
            if result == "probe":
                probe_hits += 1
                if self.own_location_probe(entry, view):
                    probe_times.setdefault(decoy_id, []).append(view.received)
                continue
            if result == "suppressed":
                suppressed.append({"event_id": view.event_id, "decoy_id": decoy_id})
                continue
            sandbox_id, attribution = self.sandboxes.attribute(view.actor)
            kind = entry["kind"]
            verdict_name = verdict(view.action, kind, attribution)
            alert_id = view.event_id + "/" + decoy_id
            if counts[view.event_id] > 1:
                alert_id += "#" + str(view.index)
            alerts.append(((view.time[0], view.event_id, view.index), {
                "alert_id": alert_id,
                "event_id": view.event_id,
                "decoy_id": decoy_id,
                "kind": kind,
                "location": None if is_retired else entry["location"],
                "observed_target": None if view.action == "credential-use" else view.target,
                "severity": "critical",
                "verdict": verdict_name,
                "techniques": techniques(verdict_name, entry["technique"]),
                "sandbox_id": sandbox_id,
                "attribution": attribution,
                "harness": identify_harness(signatures, view.actor),
                "executable": view.actor["executable"],
                "uid": view.actor["uid"],
                "comm": view.actor["comm"],
                "time": view.time[1],
                "source": view.source,
            }))
        if mismatch:
            warnings.append("inode-binding-mismatch")
        alerts.sort(key=lambda pair: pair[0])
        alert_list = [a for _, a in alerts]
        incidents = self._incidents(alerts)

        clock_skew = []
        skew_limit = int(req["max_clock_skew_seconds"]) * 1_000_000_000
        for view in accepted:
            delay = int(self.sources[view.source]["max_delay_seconds"]) * 1_000_000_000
            if view.received[0] - view.time[0] > delay or \
                    view.time[0] - view.received[0] > skew_limit:
                clock_skew.append(view.event_id)

        carry = self._prepared_carry()
        seq = sequences(accepted, carry, set(self.sources))
        silence_gaps, last_seen = silence(accepted, self.sources, carry,
                                          self.window_start, self.window_end)
        gaps, last_probe = watch_gaps(planted_ids, self.probe, probe_times, carry,
                                      self.window_start, self.window_end)
        uncorroborated, recent, pending = corroborate(
            req["corroboration"], self.sources, batch_hits, carry, self.window_end)

        tamper = {
            "sequence_gaps": seq["sequence_gaps"],
            "late_fills": seq["late_fills"],
            "sequence_duplicates": seq["sequence_duplicates"],
            "sensor_restarts": seq["sensor_restarts"],
            "silence_gaps": silence_gaps,
            "watch_gaps": gaps,
            "uncorroborated": uncorroborated,
            "clock_skew": clock_skew,
        }
        repaired.sort(key=lambda r: (r["index"], r["field"]))
        rejected.sort(key=lambda r: (r["index"], r["field"]))
        degraded = (any(w in warnings for w in ("missing-inode-binding",
                                                 "inode-binding-mismatch"))
                    or bool(rejected or repaired or rejected_hits or duplicate_ids)
                    or any(tamper.values()))
        result = {
            "operation": "evaluate",
            "deployment_id": self.watch["deployment_id"],
            "warnings": warnings,
            "breached": bool(alert_list or rejected_hits),
            "degraded": degraded,
            "alerts": alert_list,
            "incidents": incidents,
            "suppressed": suppressed,
            "rejected": rejected,
            "repaired": repaired,
            "rejected_hits": rejected_hits,
            "duplicate_event_ids": duplicate_ids,
        }
        result.update(tamper)
        result["carry"] = {
            "window_end": self.window_end[1],
            "sequences": seq["carry"],
            "last_seen": last_seen,
            "last_probe": last_probe,
            "recent_hits": recent,
            "pending": pending,
        }
        result["probe_hits"] = probe_hits
        result["ignored"] = ignored
        return result

    @staticmethod
    def _incidents(alerts):
        groups = {}
        order = []
        for (instant, _, _), alert in alerts:
            sid = alert["sandbox_id"]
            if sid not in groups:
                groups[sid] = {"first": (instant, alert["time"]), "last": alert["time"],
                               "ids": []}
                order.append(sid)
            groups[sid]["last"] = alert["time"]
            groups[sid]["ids"].append(alert["alert_id"])
        order.sort(key=lambda sid: (groups[sid]["first"][0], sid is None, sid or ""))
        return [{"sandbox_id": sid, "first_seen": groups[sid]["first"][1],
                 "last_seen": groups[sid]["last"], "alert_ids": groups[sid]["ids"]}
                for sid in order]

    def _prepared_carry(self):
        carry = self.req["carry"]
        if carry is None:
            return None

        def pair(text):
            return (parse_timestamp(text), text)

        planted = {d["decoy_id"] for d in self.decoys if d["kind"] in cat.PLANTED_KINDS}
        out = {
            "sequences": [dict(e, last_received_pair=pair(e["last_received"]))
                          for e in carry["sequences"] if e["source"] in self.sources],
            "last_seen": [dict(e, received_pair=pair(e["received"]))
                          for e in carry["last_seen"]
                          if e["source"] in self.sources
                          and self.sources[e["source"]]["max_silence_seconds"] is not None],
            "last_probe": [dict(e, received_pair=pair(e["received"]))
                           for e in carry["last_probe"]
                           if self.probe is not None and e["decoy_id"] in planted],
            "recent_hits_objs": [Hit(e["event_id"], e["decoy_id"], e["source"],
                                     pair(e["time"]), pair(e["received"]))
                                 for e in carry["recent_hits"]],
            "pending_objs": [Hit(e["event_id"], e["decoy_id"], e["source"],
                                 pair(e["time"]), pair(e["received"]),
                                 missing=list(e["missing_sources"]))
                             for e in carry["pending"]],
        }
        return out


def evaluate(req, env):
    v.check_object(req, "", EVALUATE_FIELDS)
    keys = _rule1(req, env)
    _rule2(req["watch"])
    _rule3(req)
    _rule4(req)
    decoys = {d["decoy_id"]: d for d in req["watch"]["decoys"]}
    declared = {s["source"] for s in req["sources"]}
    _rule5(req, decoys, declared)
    _rule10(req, decoys)
    return Evaluator(req, keys).run()
