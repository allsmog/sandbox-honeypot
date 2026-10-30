"""Assemble the single-file zipapp holding the application and its native tests."""

import argparse
import os
import sys
import zipfile
from pathlib import Path

MAIN = (
    "import runpy\n"
    "runpy.run_module('main', run_name='__main__', alter_sys=True)\n"
)


def members(source):
    yield source / "main.py", "main.py"
    for package in ("tripwire", "tests"):
        for path in sorted((source / package).rglob("*.py")):
            yield path, path.relative_to(source).as_posix()


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    source = Path(args.source).resolve()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(zipfile.ZipInfo("__main__.py", (1980, 1, 1, 0, 0, 0)), MAIN)
        for path, name in members(source):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            archive.writestr(info, path.read_bytes())
    data = temporary.read_bytes()
    temporary.write_bytes(b"#!/usr/bin/env python3\n" + data)
    os.chmod(temporary, 0o755)
    os.replace(temporary, output)
    if not output.is_file():
        raise SystemExit(f"export missing: {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
