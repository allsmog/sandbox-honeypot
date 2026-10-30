"""Sandbox Escape Tripwire portable application entrypoint.

`main(request)` evaluates one request object and returns the JSON-compatible
result. Run as a program, argv[1] is a complete UTF-8 JSON array of arguments;
`--litai-test` and `--litai-smoke` are framework-owned verification modes.
"""

import os
import sys

from tripwire import run
from tripwire.common import parse_json, to_output_json


def main(request):
    return run(request, os.environ)


def _write(value):
    sys.stdout.buffer.write((to_output_json(value) + "\n").encode("utf-8"))
    sys.stdout.flush()


def _invalid():
    return {"error": {"code": "invalid-request", "field": ""}}


def _cli(argv):
    if len(argv) >= 2 and argv[1] == "--litai-test":
        from tests.litai_test import run_generated_cases
        report, ok = run_generated_cases(main)
        _write(report)
        return 0 if ok else 1
    if len(argv) >= 2 and argv[1] == "--litai-smoke":
        from tests.litai_test import smoke_arguments
        result = main(*smoke_arguments())
        _write(result)
        return 2 if "error" in result else 0
    if len(argv) != 2:
        _write(_invalid())
        return 2
    try:
        text = os.fsencode(argv[1]).decode("utf-8")
        arguments = parse_json(text)
    except (ValueError, UnicodeError):
        _write(_invalid())
        return 2
    if not isinstance(arguments, list) or len(arguments) != 1:
        _write(_invalid())
        return 2
    result = main(*arguments)
    _write(result)
    return 2 if isinstance(result, dict) and set(result) == {"error"} else 0


if __name__ == "__main__":
    sys.exit(_cli(sys.argv))
