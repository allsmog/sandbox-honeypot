"""The `plan` operation: validation (phases one and two) and decoy placement."""

import re

from . import catalog as cat
from . import validate as v
from .common import (Invalid, alias_conflict, at_or_beneath, canonical_path,
                     format_endpoint, has_lone_surrogate, is_path, nested,
                     parse_address, parse_endpoint, parse_exposure_endpoint,
                     exposure_covers, is_unspecified, ptr)
from .credentials import (DERIVED_FORMATS, FORMATS, companion_paths, identifier_digest,
                          kube_token, layout_byte, owner, ssh_key)

TEST_SEED = "tripwire-test-seed-0123456789abcdef"
BUILTIN_ALIAS = ("/var/run", "/run")
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
POSIX_USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
NO_SPACE = re.compile(r"\S+")
BASE64 = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")


# ------------------------------------------------------------ phase one

def _regex_string(pattern, nonempty=True):
    def check(value, pointer):
        v.string(value, pointer)
        if (nonempty and value == "") or pattern.fullmatch(value) is None:
            raise Invalid(pointer)
    return check


def _gateway(value, pointer):
    v.string(value, pointer)
    address = parse_address(value, False)
    if address is None or is_unspecified(address):
        raise Invalid(pointer)


def _exposure_endpoint(value, pointer):
    if parse_exposure_endpoint(value) is None:
        raise Invalid(pointer)


def _path_or_endpoint(value, pointer):
    if not is_path(value) and parse_endpoint(value) is None:
        raise Invalid(pointer)


def _custom_id(value, pointer):
    v.decoy_id_form(value, pointer)
    if value in cat.CATALOG_IDS:
        raise Invalid(pointer)


CONTEXT = v.obj(
    ("host_name", v.not_revealing(_regex_string(DNS_LABEL))),
    ("dormant_user", v.not_revealing(v.nullable(_regex_string(POSIX_USER)))),
    ("aws_region", v.not_revealing(v.nonempty_string)),
    ("cluster_name", v.not_revealing(v.nullable(_regex_string(NO_SPACE)))),
    ("api_server", v.not_revealing(v.nullable(_regex_string(NO_SPACE)))),
    ("cluster_ca_data", v.not_revealing(v.nullable(_regex_string(BASE64)))),
)

PLAN_FIELDS = v.fields(
    ("operation", v.enum("plan")),
    ("deployment_id", v.identifier),
    ("runtime", v.enum(*cat.RUNTIMES)),
    ("host_profile", v.enum(*cat.HOST_PROFILES)),
    ("metadata_service", v.boolean),
    ("include", v.array_of(v.enum(*cat.OPT_IN))),
    ("seed", v.string, False),
    ("context", CONTEXT),
    ("sandbox_gateway", v.nullable(_gateway)),
    ("exposure", v.obj(("paths", v.array_of(v.path)),
                       ("endpoints", v.array_of(_exposure_endpoint)))),
    ("occupied", v.array_of(_path_or_endpoint)),
    ("path_aliases", v.array_of(v.obj(("alias", v.path), ("target", v.path)))),
    ("exclude", v.array_of(v.enum(*cat.CATALOG_IDS))),
    ("relocate", v.array_of(v.obj(("decoy_id", v.identifier),
                                  ("location", v.not_revealing(v.location))))),
    ("custom_decoys", v.array_of(v.obj(
        ("decoy_id", _custom_id),
        ("kind", v.enum(*cat.PLANTED_KINDS)),
        ("location", v.not_revealing(v.location)),
        ("technique", v.technique),
        ("credential_format", v.nullable(v.enum(*FORMATS)))))),
    ("epochs", v.array_of(v.obj(("decoy_id", v.identifier),
                                ("epoch", v.integer(0, 255))))),
    ("provided_credentials", v.array_of(v.obj(("decoy_id", v.identifier),
                                              ("identifier_digest", v.hex64)))),
    ("retired_canaries", v.array_of(v.obj(("decoy_id", v.decoy_id_form),
                                          ("technique", v.nullable(v.technique)),
                                          ("canary_digest", v.hex64)))),
    ("cover_files", v.array_of(v.obj(("decoy_id", v.identifier),
                                     ("path", v.not_revealing(v.path)),
                                     ("content", v.not_revealing(v.string))))),
)


# ------------------------------------------------------------ the decoy model

class Decoy:
    def __init__(self, decoy_id, kind, technique, fmt, candidates, custom=False,
                 fs_type=None, fs_path=None):
        self.id = decoy_id
        self.kind = kind
        self.technique = technique
        self.fmt = fmt
        self.candidates = candidates
        self.custom = custom
        self.fs_type = fs_type
        self.fs_path = fs_path
        self.scope = "name-beneath" if decoy_id == "cgroup-release-agent" and not custom else "exact"
        self.name = "release_agent" if self.scope == "name-beneath" else None
        self.reachable = decoy_id == "gateway-ssh" and not custom


def _catalog_included(decoy_id, req):
    if decoy_id in cat.OPT_IN:
        return decoy_id in req["include"]
    if decoy_id == "kubeconfig":
        return req["host_profile"] == "kubernetes-node"
    if decoy_id == "gateway-ssh":
        return req["sandbox_gateway"] is not None
    return True


def _decoys(req):
    """Included catalog decoys in catalog order, then custom decoys."""
    user = req["context"]["dormant_user"]
    gateway = req["sandbox_gateway"]
    out = []
    for decoy_id, kind, cands, technique, fmt, fs_type, fs_path in cat.CATALOG:
        if not _catalog_included(decoy_id, req):
            continue
        if decoy_id == "runtime-control":
            cands = list(cat.RUNTIME_SOCKETS[req["runtime"]])
        resolved = []
        for cand in cands:
            if "{user}" in cand:
                if user is None:
                    continue
                cand = cand.replace("{user}", user)
            if "{gateway}" in cand:
                cand = cand.replace("{gateway}", "[" + gateway + "]" if ":" in gateway else gateway)
            resolved.append(cand)
        out.append(Decoy(decoy_id, kind, technique, fmt, resolved,
                         fs_type=fs_type, fs_path=fs_path))
    for custom in req["custom_decoys"]:
        out.append(Decoy(custom["decoy_id"], custom["kind"], custom["technique"],
                         custom["credential_format"], [custom["location"]], custom=True))
    return out


class Item:
    """One footprint item: a canonical path or a canonical endpoint."""

    def __init__(self, kind, value, origin, endpoint=None, cover=None):
        self.kind = kind          # "path" or "endpoint"
        self.value = value        # canonical path or canonical endpoint text
        self.origin = origin      # (rank tuple, pointer) of the request item
        self.endpoint = endpoint  # parsed canonical endpoint
        self.cover = cover        # content when the item is a cover file


def _collide(a, b):
    if a.kind != b.kind:
        return False
    if a.kind == "endpoint":
        return a.value == b.value
    if a.cover is not None and b.cover is not None and a.value == b.value \
            and a.cover == b.cover:
        return False
    return nested(a.value, b.value)


def _any_collision(items_a, items_b):
    return any(_collide(a, b) for a in items_a for b in items_b)


def _intra_collision(items):
    return any(_collide(items[i], items[j])
               for i in range(len(items)) for j in range(i + 1, len(items)))


class Planner:
    def __init__(self, req, seed):
        self.req = req
        self.seed = seed
        self.aliases = [BUILTIN_ALIAS] + [(a["alias"], a["target"])
                                         for a in req["path_aliases"]]
        self.decoys = _decoys(req)
        self.by_id = {d.id: d for d in self.decoys}
        self.exclude = set(req["exclude"])
        self.relocate = {}
        for index, entry in enumerate(req["relocate"]):
            self.relocate[entry["decoy_id"]] = (entry["location"], index)
        self.custom_index = {c["decoy_id"]: i for i, c in enumerate(req["custom_decoys"])}
        self.covers = {}
        for index, cover in enumerate(req["cover_files"]):
            self.covers.setdefault(cover["decoy_id"], []).append((index, cover))
        self.epochs = {e["decoy_id"]: int(e["epoch"]) for e in req["epochs"]}
        self.provided = {p["decoy_id"]: p["identifier_digest"]
                         for p in req["provided_credentials"]}

    def canon(self, path):
        return canonical_path(path, self.aliases)

    def canonical_location(self, location):
        if location is None:
            return None
        if is_path(location):
            return self.canon(location)
        return format_endpoint(parse_endpoint(location))

    def footprint(self, decoy, location, origin=None):
        items = []
        if location is None:
            return items
        if is_path(location):
            items.append(Item("path", self.canon(location), origin))
            if decoy.kind == "credential-file":
                for comp in companion_paths(location, decoy.fmt):
                    items.append(Item("path", self.canon(comp), origin))
        else:
            endpoint = parse_endpoint(location)
            items.append(Item("endpoint", format_endpoint(endpoint), origin,
                              endpoint=endpoint))
        for index, cover in self.covers.get(decoy.id, []):
            items.append(Item("path", self.canon(cover["path"]),
                              ((2, index), ptr("/cover_files", index, "path")),
                              cover=cover["content"]))
        return items

    def fixed_footprints(self):
        """Footprints of relocated and custom decoys, keyed by decoy ID."""
        out = {}
        for decoy_id, (location, index) in self.relocate.items():
            decoy = self.by_id.get(decoy_id)
            if decoy is None:
                continue
            out[decoy_id] = self.footprint(
                decoy, location, ((0, index), ptr("/relocate", index, "location")))
        for decoy_id, index in self.custom_index.items():
            decoy = self.by_id[decoy_id]
            out[decoy_id] = self.footprint(
                decoy, decoy.candidates[0],
                ((1, index), ptr("/custom_decoys", index, "location")))
        return out

    # -- exposure and occupancy
    def exposed(self, items):
        paths = [self.canon(p) for p in self.req["exposure"]["paths"]]
        endpoints = [parse_exposure_endpoint(e) for e in self.req["exposure"]["endpoints"]]
        for item in items:
            if item.kind == "path":
                if any(at_or_beneath(item.value, p) for p in paths):
                    return True
            elif any(exposure_covers(e, item.endpoint) for e in endpoints):
                return True
        return False

    def occupied(self, items):
        paths = []
        endpoints = []
        for entry in self.req["occupied"]:
            if is_path(entry):
                paths.append(self.canon(entry))
            else:
                endpoints.append(parse_endpoint(entry))
        for item in items:
            if item.kind == "path":
                if any(at_or_beneath(item.value, p) for p in paths):
                    return True
            else:
                for address, port in endpoints:
                    if port == item.endpoint[1] and (is_unspecified(address)
                                                     or address == item.endpoint[0]):
                        return True
        return False

    def run(self):
        req = self.req
        fixed = self.fixed_footprints()
        placed_items = []
        placed = []          # (decoy, location, listener)
        skipped = []

        def collision(decoy, items):
            if _intra_collision(items):
                return True
            for other_id, other_items in fixed.items():
                if other_id != decoy.id and _any_collision(items, other_items):
                    return True
            return _any_collision(items, placed_items)

        def eligible(decoy, location):
            items = self.footprint(decoy, location)
            if not decoy.reachable and self.exposed(items):
                return False
            if decoy.id != "gateway-ssh" and self.occupied(items):
                return False
            return not collision(decoy, items)

        for decoy in self.decoys:
            if decoy.kind in cat.WATCHED_KINDS:
                location = decoy.candidates[0] if decoy.candidates else None
                if decoy.id in self.exclude:
                    skipped.append({"decoy_id": decoy.id, "location": location,
                                    "reason": "excluded"})
                else:
                    placed.append((decoy, location, False))
                    placed_items.extend(self.footprint(decoy, location))
                continue
            if decoy.id in self.relocate:
                location = self.relocate[decoy.id][0]
            elif decoy.custom:
                location = decoy.candidates[0]
            else:
                choices = [c for c in decoy.candidates if eligible(decoy, c)]
                if choices:
                    b = layout_byte(self.seed, req["deployment_id"], decoy.id)
                    location = choices[b % len(choices)]
                else:
                    location = decoy.candidates[0]
            items = self.footprint(decoy, location)
            if decoy.id in self.exclude:
                reason = "excluded"
            elif decoy.id == "metadata-endpoint" and req["metadata_service"]:
                reason = "real-service"
            elif not decoy.reachable and self.exposed(items):
                reason = "exposed"
            elif decoy.id != "gateway-ssh" and self.occupied(items):
                reason = "occupied"
            elif collision(decoy, items):
                reason = "collision"
            elif decoy.fmt == "aws-access-key" and decoy.id not in self.provided:
                reason = "unprovisioned"
            else:
                reason = None
            if reason is not None:
                skipped.append({"decoy_id": decoy.id, "location": location,
                                "reason": reason})
                continue
            listener = decoy.kind in ("socket", "endpoint")
            if decoy.id == "gateway-ssh" and self.occupied(items):
                listener = False
            placed.append((decoy, location, listener))
            placed_items.extend(items)
        return self.result(placed, skipped)

    def epoch(self, decoy):
        return self.epochs.get(decoy.id, 0)

    def result(self, placed, skipped):
        req = self.req
        ctx = req["context"]
        dep = req["deployment_id"]
        decoys_out = []
        material = []
        companions = []
        listed_covers = set()
        placed_ids = set()
        public = {self.canon(p) for p in cat.PUBLIC_SOCKETS}
        warnings = []
        if "seed" in req:
            warnings.append("seed-in-request")
        for decoy, location, listener in placed:
            placed_ids.add(decoy.id)
            canonical = self.canonical_location(location)
            comps = (companion_paths(location, decoy.fmt)
                     if decoy.kind == "credential-file" else [])
            epoch = self.epoch(decoy) if decoy.fmt in DERIVED_FORMATS else None
            digest = None
            if decoy.fmt == "aws-access-key":
                digest = self.provided[decoy.id]
            elif decoy.fmt in DERIVED_FORMATS:
                account = owner(canonical, self.aliases, ctx["dormant_user"])
                entry = {"decoy_id": decoy.id, "credential_format": decoy.fmt,
                         "epoch": epoch}
                if decoy.fmt == "ssh-ed25519":
                    private, blob, fingerprint = ssh_key(self.seed, dep, epoch, decoy.id)
                    public_key = "ssh-ed25519 %s %s@%s" % (blob, account, ctx["host_name"])
                    entry.update({"private_key_seed": private, "public_key": public_key,
                                  "fingerprint": fingerprint})
                    digest = identifier_digest(self.seed, dep, epoch, decoy.id, decoy.fmt)
                    companion_content = [public_key + "\n"]
                else:
                    token = kube_token(self.seed, dep, epoch, decoy.id)
                    entry.update({"token": token, "cluster": ctx["cluster_name"],
                                  "server": "https://" + ctx["api_server"],
                                  "certificate_authority_data": ctx["cluster_ca_data"],
                                  "user": account})
                    digest = identifier_digest(self.seed, dep, epoch, decoy.id, decoy.fmt)
                material.append(entry)
            if decoy.fmt == "aws-access-key":
                companion_content = ["[default]\nregion = %s\n" % ctx["aws_region"]]
            for index, comp in enumerate(comps):
                companions.append({"decoy_id": decoy.id, "path": comp,
                                   "content": companion_content[index], "watched": True})
            for _, cover in self.covers.get(decoy.id, []):
                key = (self.canon(cover["path"]), cover["content"])
                if key in listed_covers:
                    continue
                listed_covers.add(key)
                companions.append({"decoy_id": decoy.id, "path": cover["path"],
                                   "content": cover["content"], "watched": False})
            if decoy.id == "runtime-control" and canonical in public:
                warnings.append("public-socket-name")
            decoys_out.append({
                "decoy_id": decoy.id,
                "kind": decoy.kind,
                "location": location,
                "canonical_location": canonical,
                "companion_paths": [self.canon(c) for c in comps],
                "listener": listener,
                "scope": decoy.scope,
                "name": decoy.name,
                "fs_type": decoy.fs_type,
                "fs_path": decoy.fs_path,
                "reachable": decoy.reachable,
                "technique": decoy.technique,
                "credential_format": decoy.fmt,
                "epoch": epoch,
                "canary_digest": digest,
            })
        retired = []
        for decoy in self.decoys:
            if decoy.fmt in DERIVED_FORMATS:
                epoch = self.epoch(decoy)
                last = epoch if decoy.id in placed_ids else epoch + 1
                for old in range(last):
                    retired.append(self.retired_entry(
                        decoy.id, decoy.technique, old,
                        identifier_digest(self.seed, dep, old, decoy.id, decoy.fmt)))
            elif decoy.fmt == "aws-access-key" and decoy.id not in placed_ids \
                    and decoy.id in self.provided:
                retired.append(self.retired_entry(decoy.id, decoy.technique, None,
                                                  self.provided[decoy.id]))
        for entry in req["retired_canaries"]:
            technique = entry["technique"]
            if technique is None:
                technique = self.known_technique(entry["decoy_id"])
            retired.append(self.retired_entry(entry["decoy_id"], technique, None,
                                              entry["canary_digest"]))
        return {
            "operation": "plan",
            "warnings": warnings,
            "watch": {
                "deployment_id": dep,
                "runtime": req["runtime"],
                "host_profile": req["host_profile"],
                "path_aliases": [{"alias": a, "target": t} for a, t in self.aliases],
                "decoys": decoys_out,
                "retired": retired,
            },
            "material": material,
            "companions": companions,
            "skipped": skipped,
        }

    @staticmethod
    def retired_entry(decoy_id, technique, epoch, digest):
        return {"decoy_id": decoy_id, "kind": "credential-file", "technique": technique,
                "epoch": epoch, "canary_digest": digest}

    def known_technique(self, decoy_id):
        if decoy_id in self.custom_index:
            return self.by_id[decoy_id].technique
        return cat.CATALOG_BY_ID[decoy_id][3]


# ------------------------------------------------------------ phase two

def _resolve_seed(req, env):
    in_request = "seed" in req
    in_env = "SANDBOX_HONEYPOT_SEED" in env
    if in_request == in_env:
        raise Invalid("/seed")
    seed = req["seed"] if in_request else env["SANDBOX_HONEYPOT_SEED"]
    if has_lone_surrogate(seed) or len(seed.encode("utf-8")) < 32:
        raise Invalid("/seed")
    if not in_request and seed == TEST_SEED:
        raise Invalid("/seed")
    return seed


def _first_repeat(values):
    """values: list of (key, pointer). Return the pointer of the first later
    occurrence of a repeated key, or None."""
    seen = set()
    for key, pointer in values:
        if key in seen:
            return pointer
        seen.add(key)
    return None


def _rule4(req):
    lists = []
    lists.append([(x, ptr("/include", i)) for i, x in enumerate(req["include"])])
    lists.append([(x, ptr("/exclude", i)) for i, x in enumerate(req["exclude"])])
    for name in ("relocate", "custom_decoys", "epochs", "provided_credentials"):
        lists.append([(e["decoy_id"], ptr("/" + name, i, "decoy_id"))
                      for i, e in enumerate(req[name])])
    for values in lists:
        found = _first_repeat(values)
        if found is not None:
            raise Invalid(found)


def _rule5(req, planner):
    by_id = planner.by_id
    for i, entry in enumerate(req["relocate"]):
        decoy = by_id.get(entry["decoy_id"])
        if (decoy is None or decoy.custom or decoy.kind not in cat.PLANTED_KINDS
                or decoy.id == "gateway-ssh"):
            raise Invalid(ptr("/relocate", i, "decoy_id"))
    for i, entry in enumerate(req["epochs"]):
        decoy = by_id.get(entry["decoy_id"])
        if decoy is None or decoy.fmt not in DERIVED_FORMATS:
            raise Invalid(ptr("/epochs", i, "decoy_id"))
    for i, entry in enumerate(req["provided_credentials"]):
        decoy = by_id.get(entry["decoy_id"])
        if decoy is None or decoy.fmt != "aws-access-key":
            raise Invalid(ptr("/provided_credentials", i, "decoy_id"))
    for i, entry in enumerate(req["retired_canaries"]):
        decoy_id = entry["decoy_id"]
        if decoy_id in cat.CATALOG_IDS:
            current = True
            kind = cat.CATALOG_BY_ID[decoy_id][1]
        elif decoy_id in planner.custom_index:
            current = True
            kind = by_id[decoy_id].kind
        else:
            current = False
            kind = "credential-file"
        if kind != "credential-file":
            raise Invalid(ptr("/retired_canaries", i, "decoy_id"))
        if current != (entry["technique"] is None):
            raise Invalid(ptr("/retired_canaries", i, "technique"))
    for i, entry in enumerate(req["cover_files"]):
        decoy = by_id.get(entry["decoy_id"])
        if decoy is None or decoy.kind not in cat.PLANTED_KINDS or decoy.reachable:
            raise Invalid(ptr("/cover_files", i, "decoy_id"))


def _rule6(req, planner):
    needed = any(d.fmt == "kubeconfig-token" and d.id not in planner.exclude
                 for d in planner.decoys)
    for name in ("cluster_name", "api_server", "cluster_ca_data"):
        if (req["context"][name] is None) == needed:
            raise Invalid(ptr("/context", name))


def _rule7(req, planner):
    conflict = alias_conflict(planner.aliases)
    if conflict is not None:
        index, field = conflict
        assert index >= 1, "the built-in alias cannot conflict with itself"
        raise Invalid(ptr("/path_aliases", index - 1, field))


def _rule8(planner):
    fixed = planner.fixed_footprints()
    items = [item for footprint in fixed.values() for item in footprint]
    worst = None
    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            if _collide(items[i], items[j]):
                later = max(items[i].origin, items[j].origin)
                if worst is None or later < worst:
                    worst = later
    if worst is not None:
        raise Invalid(worst[1])


def _rule9(req, planner):
    dep = req["deployment_id"]
    derived = set()
    for decoy in planner.decoys:
        if decoy.fmt in DERIVED_FORMATS:
            for epoch in range(planner.epoch(decoy) + 1):
                derived.add(identifier_digest(planner.seed, dep, epoch, decoy.id,
                                              decoy.fmt))
    seen = set(derived)
    fields_ = [(e["identifier_digest"], ptr("/provided_credentials", i, "identifier_digest"))
               for i, e in enumerate(req["provided_credentials"])]
    fields_ += [(e["canary_digest"], ptr("/retired_canaries", i, "canary_digest"))
                for i, e in enumerate(req["retired_canaries"])]
    for digest, pointer in fields_:
        if digest in seen:
            raise Invalid(pointer)
        seen.add(digest)


def _location_fits(kind, location):
    wanted = cat.location_type(kind)
    return is_path(location) if wanted == "path" else not is_path(location)


def _rule10(req, planner):
    for i, entry in enumerate(req["relocate"]):
        decoy = planner.by_id[entry["decoy_id"]]
        if not _location_fits(decoy.kind, entry["location"]):
            raise Invalid(ptr("/relocate", i, "location"))
    for i, entry in enumerate(req["custom_decoys"]):
        if not _location_fits(entry["kind"], entry["location"]):
            raise Invalid(ptr("/custom_decoys", i, "location"))
        if (entry["kind"] == "credential-file") != (entry["credential_format"] is not None):
            raise Invalid(ptr("/custom_decoys", i, "credential_format"))


def plan(req, env):
    v.check_object(req, "", PLAN_FIELDS)
    seed = _resolve_seed(req, env)                        # rule 1
    planner = Planner(req, seed)
    _rule4(req)
    _rule5(req, planner)
    _rule6(req, planner)
    _rule7(req, planner)
    _rule8(planner)
    _rule9(req, planner)
    _rule10(req, planner)
    return planner.run()
