"""Event shape: structural scan, core-field rejection, detail repair."""

import hmac as _hmac
import math

from .common import (as_int, hmac_sha256, is_decimal_string, is_duplicate, is_hex64,
                     is_str, jcs, jcs_length, parse_endpoint, parse_timestamp, ptr)

CORE = ("event_id", "deployment_id", "time", "received", "source", "sensor_instance",
        "sequence", "action", "target", "mac")
DETAIL = ("target_inode", "target_fs", "target_digest", "written_digest", "actor")
ACTOR = ("process", "ancestry", "helper_depth", "executable", "executable_digest", "uid",
         "comm", "environment_names", "sandbox_id")
ACTIONS = ("stat", "open", "open-write", "read", "write", "truncate", "exec", "delete",
           "rename", "link", "attr", "mount", "notify-mark", "connect", "credential-use",
           "heartbeat")
LOADER_NAMES = frozenset((
    "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH", "GCONV_PATH", "PYTHONPATH", "PYTHONHOME",
    "PERL5OPT", "PERL5LIB", "PERLLIB", "PYTHONUSERBASE", "RUBYOPT", "RUBYLIB",
    "NODE_OPTIONS", "NODE_PATH", "LUA_INIT", "BASH_ENV"))
MAX_DEPTH = 8

_IDENTITY_SCHEMA = {"order": ("pid", "start_ticks")}
_SCHEMA = {
    "order": CORE + DETAIL,
    "children": {
        "target_inode": {"order": ("device", "inode")},
        "target_fs": {"order": ("type", "path")},
        "actor": {"order": ACTOR, "children": {
            "process": _IDENTITY_SCHEMA,
            "ancestry": {"items": _IDENTITY_SCHEMA},
        }},
    },
}


def _ordered_keys(value, schema):
    order = schema.get("order", ()) if schema else ()
    known = [key for key in order if key in value]
    return known + sorted(key for key in value if key not in order)


def structural_fault(value, pointer="", depth=1, schema=_SCHEMA):
    """First repeated-key object, over-deep container, or non-finite number,
    visiting known fields in listed order and then unknown ones in key order."""
    if isinstance(value, dict):
        if depth > MAX_DEPTH or is_duplicate(value):
            return pointer
        children = schema.get("children", {}) if schema else {}
        for key in _ordered_keys(value, schema):
            found = structural_fault(value[key], ptr(pointer, key), depth + 1,
                                     children.get(key))
            if found is not None:
                return found
        return None
    if isinstance(value, list):
        if depth > MAX_DEPTH:
            return pointer
        items = schema.get("items") if schema else None
        for index, item in enumerate(value):
            found = structural_fault(item, ptr(pointer, index), depth + 1, items)
            if found is not None:
                return found
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return pointer
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) > 2 ** 1023:
        try:
            float(value)
        except OverflowError:
            return pointer
    return None


def _ident(value, limit=256):
    return is_str(value) and value != "" and jcs_length(value) <= limit


def valid_target(action, value):
    if not is_str(value) or jcs_length(value) > 4096:
        return False
    if action == "heartbeat":
        return value == ""
    if action == "credential-use":
        return is_hex64(value)
    if action == "connect":
        return value.startswith("/") or parse_endpoint(value) is not None
    return value.startswith("/")


def compute_mac(event, key_hex):
    body = {k: v for k, v in event.items() if k not in ("mac", "received")}
    message = jcs(body).encode("utf-8", "surrogatepass")
    return hmac_sha256(bytes.fromhex(key_hex), message).hex()


class Context:
    """What event checks need from the request."""

    def __init__(self, deployment_id, window_start, window_end, sources, required, keys):
        self.deployment_id = deployment_id
        self.window_start = window_start
        self.window_end = window_end
        self.sources = sources          # set of declared source names
        self.required = required
        self.keys = keys                # source -> hex key, when required


def core_fault(event, ctx):
    """Return the pointer of the first invalid core field, or None."""
    for name in CORE:
        pointer = "/" + name
        if name not in event:
            return pointer
        value = event[name]
        if name in ("event_id", "sensor_instance"):
            ok = _ident(value)
        elif name == "deployment_id":
            ok = _ident(value) and value == ctx.deployment_id
        elif name == "time":
            ok = parse_timestamp(value) is not None
        elif name == "received":
            instant = parse_timestamp(value)
            ok = instant is not None and ctx.window_start <= instant < ctx.window_end
        elif name == "source":
            ok = _ident(value) and value in ctx.sources
        elif name == "sequence":
            ok = as_int(value) is not None
        elif name == "action":
            ok = is_str(value) and value in ACTIONS
        elif name == "target":
            ok = valid_target(event["action"], value)
        else:
            if ctx.required:
                ok = is_hex64(value) and _hmac.compare_digest(
                    value, compute_mac(event, ctx.keys[event["source"]]))
            else:
                ok = value is None or is_str(value)
        if not ok:
            return pointer
    return None


# ------------------------------------------------------------- detail fields

def _identity(value):
    if not isinstance(value, dict) or is_duplicate(value):
        return None
    if set(value) - {"pid", "start_ticks"}:
        value = {k: value[k] for k in ("pid", "start_ticks") if k in value}
    if "pid" not in value or "start_ticks" not in value:
        return None
    pid = as_int(value["pid"], 1)
    ticks = as_int(value["start_ticks"], 0)
    if pid is None or ticks is None:
        return None
    return (pid, ticks)


def _drop_unknown(value, known, pointer, repaired):
    if not isinstance(value, dict) or is_duplicate(value):
        return value
    extra = [key for key in value if key not in known]
    for key in extra:
        repaired.append(ptr(pointer, key))
    return {k: value[k] for k in value if k in known}


def _target_inode(value):
    if value is None:
        return True, None
    if not isinstance(value, dict) or is_duplicate(value) or set(value) != {"device", "inode"}:
        return False, None
    if not is_decimal_string(value["device"]) or not is_decimal_string(value["inode"]):
        return False, None
    return True, (value["device"], value["inode"])


def _target_fs(value):
    if value is None:
        return True, None
    if not isinstance(value, dict) or is_duplicate(value) or set(value) != {"type", "path"}:
        return False, None
    fs_type, fs_path = value["type"], value["path"]
    if not _ident(fs_type) or not is_str(fs_path) or jcs_length(fs_path) > 4096 \
            or fs_path.startswith("/"):
        return False, None
    return True, (fs_type, fs_path)


def _digest(value):
    if value is None:
        return True, None
    return (True, value) if is_hex64(value) else (False, None)


def _actor_member(name, value):
    if name == "process":
        if value is None:
            return True, None
        identity = _identity(value)
        return (identity is not None), identity
    if name == "ancestry":
        if not isinstance(value, list) or len(value) > 64:
            return False, ()
        chain = tuple(_identity(item) for item in value)
        if any(item is None for item in chain):
            return False, ()
        return True, chain
    if value is None:
        return True, None
    if name in ("helper_depth", "uid"):
        number = as_int(value)
        return (number is not None), number
    if name == "executable":
        ok = is_str(value) and value.startswith("/") and jcs_length(value) <= 4096
        return ok, (value if ok else None)
    if name == "executable_digest":
        return _digest(value)
    if name == "comm":
        ok = is_str(value) and jcs_length(value) <= 64
        return ok, (value if ok else None)
    if name == "environment_names":
        ok = (isinstance(value, list) and all(is_str(n) for n in value)
              and jcs_length_array(value) <= 2048)
        return ok, (tuple(value) if ok else None)
    if name == "sandbox_id":
        ok = _ident(value)
        return ok, (value if ok else None)
    raise AssertionError("unknown actor member " + name)


def jcs_length_array(values):
    return len(jcs(list(values)).encode("utf-8", "surrogatepass"))


class View:
    """Parsed event fields; invalid ones are None (ancestry empty)."""

    def __init__(self):
        self.index = None
        self.event_id = None
        self.time = None            # (instant, text)
        self.received = None        # (instant, text)
        self.source = None
        self.sensor_instance = None
        self.sequence = None
        self.action = None
        self.target = None
        self.target_inode = None
        self.target_fs = None
        self.target_digest = None
        self.written_digest = None
        self.actor = {name: None for name in ACTOR}
        self.actor["ancestry"] = ()
        self.repaired = []          # pointers within the event


def parse_view(event, ctx, record):
    """Parse every field that is valid on its own. When record is True
    (accepted events) unknown fields and invalid details go to repaired."""
    view = View()
    repaired = view.repaired
    if record:
        for key in event:
            if key not in CORE and key not in DETAIL:
                repaired.append(ptr("", key))
    if _ident(event.get("event_id")):
        view.event_id = event["event_id"]
    for name in ("time", "received"):
        instant = parse_timestamp(event.get(name))
        if instant is not None:
            setattr(view, name, (instant, event[name]))
    if _ident(event.get("source")):
        view.source = event["source"]
    if _ident(event.get("sensor_instance")):
        view.sensor_instance = event["sensor_instance"]
    view.sequence = as_int(event.get("sequence")) if "sequence" in event else None
    action = event.get("action")
    if is_str(action) and action in ACTIONS:
        view.action = action
    target = event.get("target")
    if is_str(target) and jcs_length(target) <= 4096:
        view.target = target

    def detail(name, parser, known=None):
        pointer = "/" + name
        if name not in event:
            if record:
                repaired.append(pointer)
            return None
        value = event[name]
        if known is not None and record:
            value = _drop_unknown(value, known, pointer, repaired)
        elif known is not None and isinstance(value, dict) and not is_duplicate(value):
            value = {k: value[k] for k in value if k in known}
        ok, parsed = parser(value)
        if not ok and record:
            repaired.append(pointer)
        return parsed

    view.target_inode = detail("target_inode", _target_inode, ("device", "inode"))
    view.target_fs = detail("target_fs", _target_fs, ("type", "path"))
    view.target_digest = detail("target_digest", _digest)
    view.written_digest = detail("written_digest", _digest)

    if "actor" not in event:
        if record:
            repaired.append("/actor")
        return view
    actor = event["actor"]
    if not isinstance(actor, dict) or is_duplicate(actor):
        if record:
            repaired.append("/actor")
        return view
    for key in actor:
        if key not in ACTOR and record:
            repaired.append(ptr("/actor", key))
    for name in ACTOR:
        pointer = ptr("/actor", name)
        if name not in actor:
            if record:
                repaired.append(pointer)
            continue
        value = actor[name]
        if name == "process" and isinstance(value, dict):
            value = _drop_unknown(value, ("pid", "start_ticks"), pointer,
                                  repaired if record else [])
        elif name == "ancestry" and isinstance(value, list):
            value = [_drop_unknown(item, ("pid", "start_ticks"), ptr(pointer, i),
                                   repaired if record else [])
                     for i, item in enumerate(value)]
        ok, parsed = _actor_member(name, value)
        if not ok and record:
            repaired.append(pointer)
        view.actor[name] = parsed
    return view


def repaired_under(view, member):
    prefix = "/actor/" + member
    return any(p == "/actor" or p == prefix or p.startswith(prefix + "/")
               for p in view.repaired)


def loads_code(names):
    if names is None:
        return False
    return any(name in LOADER_NAMES or name.startswith("BASH_FUNC_") for name in names)
