"""Phase-one field validation helpers: each field is checked on its own, in
listed order, depth first; unknown fields follow in key order."""

import re

from .common import (Invalid, MAX_INT, as_int, is_decimal_string, is_duplicate,
                     is_hex64, is_path, is_str, parse_endpoint, parse_timestamp,
                     ptr, revealing)

TECHNIQUE = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?")
DECOY_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")


def check_object(value, pointer, fields):
    """fields: list of (name, checker, required). checker(value, pointer)."""
    if not isinstance(value, dict):
        raise Invalid(pointer)
    if is_duplicate(value):
        raise Invalid(pointer)
    names = set()
    for name, checker, required in fields:
        names.add(name)
        field_ptr = ptr(pointer, name)
        if name not in value:
            if required:
                raise Invalid(field_ptr)
            continue
        checker(value[name], field_ptr)
    unknown = sorted(key for key in value if key not in names)
    if unknown:
        raise Invalid(ptr(pointer, unknown[0]))


def fields(*specs):
    return [(spec[0], spec[1], spec[2] if len(spec) > 2 else True) for spec in specs]


def check_array(value, pointer, item_checker, min_items=0, max_items=None):
    if not isinstance(value, list):
        raise Invalid(pointer)
    if len(value) < min_items or (max_items is not None and len(value) > max_items):
        raise Invalid(pointer)
    for index, item in enumerate(value):
        item_checker(item, ptr(pointer, index))


def array_of(item_checker, min_items=0, max_items=None):
    return lambda v, p: check_array(v, p, item_checker, min_items, max_items)


def obj(*specs):
    spec_list = fields(*specs)
    return lambda v, p: check_object(v, p, spec_list)


def nullable(checker):
    def check(value, pointer):
        if value is not None:
            checker(value, pointer)
    return check


def string(value, pointer):
    if not is_str(value):
        raise Invalid(pointer)


def identifier(value, pointer):
    if not is_str(value) or value == "":
        raise Invalid(pointer)


def nonempty_string(value, pointer):
    identifier(value, pointer)


def boolean(value, pointer):
    if not isinstance(value, bool):
        raise Invalid(pointer)


def integer(low=0, high=MAX_INT):
    def check(value, pointer):
        if as_int(value, low, high) is None:
            raise Invalid(pointer)
    return check


def enum(*choices):
    def check(value, pointer):
        if not is_str(value) or value not in choices:
            raise Invalid(pointer)
    return check


def hex64(value, pointer):
    if not is_hex64(value):
        raise Invalid(pointer)


def path(value, pointer):
    if not is_path(value):
        raise Invalid(pointer)


def timestamp(value, pointer):
    if parse_timestamp(value) is None:
        raise Invalid(pointer)


def decimal_string(value, pointer):
    if not is_decimal_string(value):
        raise Invalid(pointer)


def technique(value, pointer):
    if not is_str(value) or TECHNIQUE.fullmatch(value) is None:
        raise Invalid(pointer)


def decoy_id_form(value, pointer):
    if not is_str(value) or len(value) > 64 or DECOY_ID.fullmatch(value) is None:
        raise Invalid(pointer)


def location(value, pointer):
    """A path, or an address endpoint that is not unspecified."""
    if is_path(value):
        return
    endpoint = parse_endpoint(value)
    if endpoint is None or endpoint[0][1] == 0:
        raise Invalid(pointer)


def not_revealing(checker):
    def check(value, pointer):
        checker(value, pointer)
        if isinstance(value, str) and revealing(value):
            raise Invalid(pointer)
    return check


def identity(value, pointer):
    check_object(value, pointer, fields(("pid", integer(1)),
                                        ("start_ticks", integer(0))))


def identity_key(value):
    return (as_int(value["pid"]), as_int(value["start_ticks"]))
