"""Shared primitives: errors, JSON parsing, pointers, scalars, timestamps,
paths, aliases, endpoints, and RFC 8785 canonical JSON."""

import hashlib
import hmac
import ipaddress
import json
import math
import re
from decimal import Decimal

MAX_INT = 2 ** 53 - 1
REVEALING_WORDS = ("canary", "honeypot", "honeytoken", "decoy", "tripwire")
HEX64 = re.compile(r"[0-9a-f]{64}")
DECIMAL_STRING = re.compile(r"0|[1-9][0-9]*")


class Invalid(Exception):
    """An invalid request, reported at an RFC 6901 pointer."""

    def __init__(self, pointer):
        super().__init__(pointer)
        self.pointer = pointer


class JObj(dict):
    """A parsed JSON object that remembers which keys were repeated."""

    duplicate = False
    repeated = frozenset()


def strip_repeated(value, depth=0):
    """A copy without repeated keys (their values are ambiguous). Only the
    shallow levels that event fields occupy are copied; deeper values are
    left as they are."""
    if depth > 10:
        return value
    if isinstance(value, dict):
        repeated = getattr(value, "repeated", frozenset())
        return {k: strip_repeated(v, depth + 1) for k, v in value.items()
                if k not in repeated}
    if isinstance(value, list):
        return [strip_repeated(item, depth + 1) for item in value]
    return value


_WS = " \t\n\r"
_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_STRING = re.compile(r'"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"')


def _skip(text, i):
    n = len(text)
    while i < n and text[i] in _WS:
        i += 1
    return i


def _read_string(text, i):
    match = _STRING.match(text, i)
    if match is None:
        raise ValueError("bad string at %d" % i)
    return json.loads(match.group(0)), match.end()


def _read_key(text, i):
    if i >= len(text) or text[i] != '"':
        raise ValueError("expected key at %d" % i)
    key, i = _read_string(text, i)
    i = _skip(text, i)
    if i >= len(text) or text[i] != ":":
        raise ValueError("expected ':' at %d" % i)
    return key, _skip(text, i + 1)


def _number(token):
    if any(c in token for c in ".eE"):
        return float(token)
    digits = token.lstrip("-")
    if len(digits) > 400:
        return float("-inf") if token.startswith("-") else float("inf")
    return int(token)


def parse_json(text):
    """Parse strict JSON without recursion, so nesting depth is unbounded.
    Objects become JObj, which records repeated keys."""
    n = len(text)
    stack = []
    i = _skip(text, 0)
    while True:
        ch = text[i] if i < n else ""
        if ch == "{":
            i = _skip(text, i + 1)
            if i < n and text[i] == "}":
                value, i = JObj(), i + 1
            else:
                key, i = _read_key(text, i)
                stack.append([JObj(), key])
                continue
        elif ch == "[":
            i = _skip(text, i + 1)
            if i < n and text[i] == "]":
                value, i = [], i + 1
            else:
                stack.append([[], None])
                continue
        elif ch == '"':
            value, i = _read_string(text, i)
        elif text.startswith("true", i):
            value, i = True, i + 4
        elif text.startswith("false", i):
            value, i = False, i + 5
        elif text.startswith("null", i):
            value, i = None, i + 4
        else:
            match = _NUMBER.match(text, i)
            if match is None:
                raise ValueError("unexpected input at %d" % i)
            value, i = _number(match.group(0)), match.end()
        while True:
            i = _skip(text, i)
            if not stack:
                if i != n:
                    raise ValueError("trailing data at %d" % i)
                return value
            frame = stack[-1]
            container = frame[0]
            if isinstance(container, list):
                container.append(value)
                closer = "]"
            else:
                if frame[1] in container:
                    container.duplicate = True
                    container.repeated = container.repeated | {frame[1]}
                container[frame[1]] = value
                closer = "}"
            if i < n and text[i] == ",":
                i = _skip(text, i + 1)
                if closer == "}":
                    frame[1], i = _read_key(text, i)
                break
            if i < n and text[i] == closer:
                i += 1
                value = container
                stack.pop()
                continue
            raise ValueError("expected ',' or %r at %d" % (closer, i))


def is_duplicate(obj):
    return bool(getattr(obj, "duplicate", False))


def esc(token):
    return token.replace("~", "~0").replace("/", "~1")


def ptr(base, *tokens):
    out = base
    for token in tokens:
        out += "/" + esc(str(token))
    return out


# ---------------------------------------------------------------- scalars

def has_lone_surrogate(text):
    return any("\ud800" <= ch <= "\udfff" for ch in text)


def is_str(value):
    return isinstance(value, str) and not has_lone_surrogate(value)


def as_int(value, low=0, high=MAX_INT):
    """Return the integer a JSON number denotes, or None when it is not an
    integer in [low, high]."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer():
            return None
        number = int(value)
    else:
        return None
    if number < low or number > high:
        return None
    return number


def is_hex64(value):
    return is_str(value) and HEX64.fullmatch(value) is not None


def is_decimal_string(value):
    return is_str(value) and DECIMAL_STRING.fullmatch(value) is not None


def revealing(text):
    lowered = text.lower()
    return any(word in lowered for word in REVEALING_WORDS)


def sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def hmac_sha256(key, message):
    return hmac.new(key, message, hashlib.sha256).digest()


# ------------------------------------------------------------- timestamps

TIMESTAMP = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.([0-9]{1,9}))?Z")


def _days_from_civil(year, month, day):
    year -= month <= 2
    era = year // 400
    yoe = year - era * 400
    doy = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _days_in_month(year, month):
    if month == 2:
        leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
        return 29 if leap else 28
    return 30 if month in (4, 6, 9, 11) else 31


def parse_timestamp(value):
    """Return the instant (integer nanoseconds since the epoch) or None."""
    if not is_str(value):
        return None
    match = TIMESTAMP.fullmatch(value)
    if match is None:
        return None
    year, month, day, hour, minute, second = (int(g) for g in match.groups()[:6])
    if not 1 <= month <= 12 or not 1 <= day <= _days_in_month(year, month):
        return None
    if hour > 23 or minute > 59 or second > 59:
        return None
    fraction = match.group(7) or ""
    nanos = int((fraction + "000000000")[:9])
    seconds = (_days_from_civil(year, month, day) * 86400 + hour * 3600
               + minute * 60 + second)
    return seconds * 1_000_000_000 + nanos


NS = 1_000_000_000


# ------------------------------------------------------------------ paths

def is_path(value):
    if not is_str(value) or not value.startswith("/"):
        return False
    if value == "/":
        return True
    return all(seg not in ("", ".", "..") for seg in value[1:].split("/"))


def beneath(path, base):
    """True when path lies strictly beneath base on a segment boundary."""
    if base == "/":
        return path != "/"
    return path.startswith(base + "/")


def at_or_beneath(path, base):
    return path == base or beneath(path, base)


def nested(a, b):
    return at_or_beneath(a, b) or at_or_beneath(b, a)


def canonical_path(path, aliases):
    """Replace the longest alias prefix with its target. aliases is a list
    of (alias, target) pairs forming a valid alias set."""
    best = None
    for alias, target in aliases:
        if at_or_beneath(path, alias) and (best is None or len(alias) > len(best[0])):
            best = (alias, target)
    if best is None:
        return path
    alias, target = best
    rest = path[len(alias):] if alias != "/" else path
    if target == "/":
        return rest or "/"
    return target + rest


def normalize_path(text):
    """Collapse repeated '/', drop a trailing '/', and resolve '.' and '..'
    lexically. text starts with '/'."""
    stack = []
    for seg in text.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if stack:
                stack.pop()
            continue
        stack.append(seg)
    return "/" + "/".join(stack)


def parent_dir(path):
    if path == "/":
        return None
    head = path.rsplit("/", 1)[0]
    return head or "/"


def alias_conflict(entries):
    """Check an effective alias list [(alias, target), ...]. Return
    (index, "alias"|"target") of the first offending later entry, or None."""
    for j, (alias_b, target_b) in enumerate(entries):
        alias_hit = False
        target_hit = False
        # Self overlap: the entry's own target and alias nest.
        if at_or_beneath(target_b, alias_b) or at_or_beneath(alias_b, target_b):
            alias_hit = True
        for i in range(j):
            alias_a, target_a = entries[i]
            if (alias_b == alias_a or at_or_beneath(alias_b, target_a)
                    or at_or_beneath(target_a, alias_b)):
                alias_hit = True
            if at_or_beneath(target_b, alias_a) or at_or_beneath(alias_a, target_b):
                target_hit = True
        if alias_hit:
            return j, "alias"
        if target_hit:
            return j, "target"
    return None


# -------------------------------------------------------------- endpoints

IPV4_PART = re.compile(r"[0-9]{1,3}")
PORT = re.compile(r"[0-9]{1,5}")
PREFIX = re.compile(r"0|[1-9][0-9]{0,2}")
IPV6_CHARS = re.compile(r"[0-9A-Fa-f:.]+")


def parse_ipv4(text):
    parts = text.split(".")
    if len(parts) != 4:
        return None
    value = 0
    for part in parts:
        if IPV4_PART.fullmatch(part) is None or int(part) > 255:
            return None
        value = value * 256 + int(part)
    return value


def parse_ipv6(text):
    if IPV6_CHARS.fullmatch(text) is None:
        return None
    try:
        return int(ipaddress.IPv6Address(text))
    except ValueError:
        return None


def canonical_address(family, value):
    """Map an IPv4-mapped IPv6 address to IPv4."""
    if family == 6 and (value >> 32) == 0xFFFF:
        return 4, value & 0xFFFFFFFF
    return family, value


def parse_address(text, bracketed):
    """Parse an address (bracketed IPv6 when bracketed is True, bare IPv6
    otherwise) into a canonical (family, int) pair, or None."""
    if text.startswith("["):
        if not bracketed or not text.endswith("]"):
            return None
        value = parse_ipv6(text[1:-1])
        return None if value is None else canonical_address(6, value)
    v4 = parse_ipv4(text)
    if v4 is not None:
        return 4, v4
    if bracketed:
        return None
    value = parse_ipv6(text)
    return None if value is None else canonical_address(6, value)


def parse_port(text):
    if PORT.fullmatch(text) is None:
        return None
    port = int(text)
    return port if 1 <= port <= 65535 else None


def parse_endpoint(text):
    """Parse ADDRESS:PORT into ((family, int), port), or None."""
    if not is_str(text):
        return None
    if text.startswith("["):
        close = text.find("]")
        if close < 0 or text[close + 1:close + 2] != ":":
            return None
        address = parse_address(text[:close + 1], True)
        port = parse_port(text[close + 2:])
    else:
        head, sep, tail = text.rpartition(":")
        if not sep:
            return None
        address = parse_address(head, True)
        port = parse_port(tail)
    if address is None or port is None:
        return None
    return address, port


def format_address(address):
    family, value = address
    if family == 4:
        return str(ipaddress.IPv4Address(value))
    return "[" + ipaddress.IPv6Address(value).compressed + "]"


def format_endpoint(endpoint):
    address, port = endpoint
    return format_address(address) + ":" + str(port)


def is_unspecified(address):
    return address[1] == 0


def is_loopback(address):
    family, value = address
    if family == 4:
        return (value >> 24) == 127
    return value == 1


def target_endpoint(endpoint):
    """Rewrite unspecified addresses to the loopback Linux connects them to."""
    address, port = endpoint
    if is_unspecified(address):
        address = (4, 0x7F000001) if address[0] == 4 else (6, 1)
    return address, port


def parse_exposure_endpoint(text):
    """Parse SCOPE:PORTS. Returns (scope, ports) where scope is ("any",),
    ("addr", address), or ("cidr", family, network, prefix) and ports is an
    int or "*"; or None."""
    if not is_str(text):
        return None
    head, sep, tail = text.rpartition(":")
    if not sep:
        return None
    if tail == "*":
        ports = "*"
    else:
        ports = parse_port(tail)
        if ports is None:
            return None
    if head == "*":
        return ("any",), ports
    prefix = None
    if "/" in head:
        head, prefix_text = head.split("/", 1)
        if PREFIX.fullmatch(prefix_text) is None:
            return None
        prefix = int(prefix_text)
    if head.startswith("["):
        if not head.endswith("]"):
            return None
        raw = parse_ipv6(head[1:-1])
        if raw is None:
            return None
        family = 6
    else:
        raw = parse_ipv4(head)
        if raw is None:
            return None
        family = 4
    if prefix is None:
        return ("addr", canonical_address(family, raw)), ports
    bits = 32 if family == 4 else 128
    if prefix > bits:
        return None
    mask = ((1 << bits) - 1) ^ ((1 << (bits - prefix)) - 1)
    network = raw & mask
    if family == 6 and prefix >= 96 and (network >> 32) == 0xFFFF:
        family, prefix, network = 4, prefix - 96, network & 0xFFFFFFFF
    return ("cidr", family, network, prefix), ports


def exposure_covers(exposure, endpoint):
    scope, ports = exposure
    address, port = endpoint
    if ports != "*" and ports != port:
        return False
    if scope[0] == "any":
        return not is_loopback(address)
    if scope[0] == "addr":
        return scope[1] == address
    _, family, network, prefix = scope
    if family != address[0]:
        return False
    bits = 32 if family == 4 else 128
    if (address[1] >> (bits - prefix)) != (network >> (bits - prefix)):
        return False
    if not is_loopback(address):
        return True
    if family == 4:
        return prefix >= 8 and (network >> 24) == 127
    return prefix == 128 and network == 1


# ------------------------------------------------------------ RFC 8785 JCS

_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f",
            "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def jcs_string(text):
    out = ['"']
    for ch in text:
        mapped = _ESCAPES.get(ch)
        if mapped is not None:
            out.append(mapped)
        elif ord(ch) < 0x20 or "\ud800" <= ch <= "\udfff":
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def jcs_number(value):
    if isinstance(value, int):
        if -MAX_INT <= value <= MAX_INT:
            return str(value)
        value = float(value)
    if not math.isfinite(value):
        raise ValueError("non-finite number")
    if value == 0:
        return "0"
    if value < 0:
        return "-" + jcs_number(-value)
    sign, digits, exponent = Decimal(repr(value)).as_tuple()
    digits = list(digits)
    while len(digits) > 1 and digits[-1] == 0:
        digits.pop()
        exponent += 1
    text = "".join(str(d) for d in digits)
    k = len(text)
    n = exponent + k
    if k <= n <= 21:
        return text + "0" * (n - k)
    if 0 < n <= 21:
        return text[:n] + "." + text[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + text
    e = n - 1
    mark = "+" if e >= 0 else "-"
    if k == 1:
        return text + "e" + mark + str(abs(e))
    return text[0] + "." + text[1:] + "e" + mark + str(abs(e))


def _utf16_key(key):
    return key.encode("utf-16-be", "surrogatepass")


def jcs(value):
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return jcs_number(value)
    if isinstance(value, str):
        return jcs_string(value)
    if isinstance(value, list):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=_utf16_key)
        return "{" + ",".join(jcs_string(k) + ":" + jcs(value[k]) for k in keys) + "}"
    raise TypeError("not a JSON value")


def jcs_length(text):
    """Bytes of a string as JCS serializes it, without the quotes."""
    return len(jcs_string(text).encode("utf-8")) - 2


def to_output_json(value):
    """Compact JSON for standard output; lone surrogates are escaped."""
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False)
    if has_lone_surrogate(text):
        text = "".join("\\u%04x" % ord(ch) if "\ud800" <= ch <= "\udfff" else ch
                       for ch in text)
    return text
