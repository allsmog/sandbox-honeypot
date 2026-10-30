"""Generate source/tests/manifest.json from the native test cases.

The test module's CASES list is the single source of truth; this script only
serializes it as compact canonical JSON (sorted keys, no insignificant
whitespace, no floating-point numbers). Run with bytecode writes disabled:

    PYTHONDONTWRITEBYTECODE=1 python3 -B gen_manifest.py [RECIPE_IDENTITY]
"""

import json
import os
import sys

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.join(HERE, "source")
sys.path.insert(0, SOURCE)

from tests.litai_test import CASES  # noqa: E402

DOCUMENTS = {"component.md", "decoys/spec.md", "credentials/spec.md", "evaluation/spec.md",
             "attribution/spec.md", "telemetry/spec.md", "stealth/spec.md"}
CATEGORIES = {"example", "boundary", "invariant"}


def check_no_floats(value, where):
    if isinstance(value, float):
        raise SystemExit("floating-point number in %s" % where)
    if isinstance(value, dict):
        for key, item in value.items():
            check_no_floats(item, where)
    elif isinstance(value, list):
        for item in value:
            check_no_floats(item, where)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False)


def main():
    recipe = sys.argv[1] if len(sys.argv) > 1 else "sha256:RECIPE_PLACEHOLDER"
    if not 3 <= len(CASES) <= 256:
        raise SystemExit("case count %d out of range" % len(CASES))
    ids, argument_texts, categories = set(), set(), set()
    cases = []
    for entry in CASES:
        if set(entry) != {"case_id", "category", "specification_refs", "arguments",
                          "expected_result"}:
            raise SystemExit("bad case fields: %s" % entry.get("case_id"))
        if entry["case_id"] in ids:
            raise SystemExit("duplicate case_id " + entry["case_id"])
        ids.add(entry["case_id"])
        if entry["category"] not in CATEGORIES:
            raise SystemExit("bad category in " + entry["case_id"])
        categories.add(entry["category"])
        if not entry["specification_refs"] or not set(entry["specification_refs"]) <= DOCUMENTS:
            raise SystemExit("bad specification_refs in " + entry["case_id"])
        check_no_floats(entry["arguments"], entry["case_id"])
        check_no_floats(entry["expected_result"], entry["case_id"])
        text = canonical(entry["arguments"])
        if text in argument_texts:
            raise SystemExit("duplicate arguments in " + entry["case_id"])
        argument_texts.add(text)
        cases.append(json.loads(canonical(entry)))
    if categories != CATEGORIES:
        raise SystemExit("missing categories: %s" % sorted(CATEGORIES - categories))
    manifest = {"schema": "urn:literate-ai:schema:v1:generated-test-suite",
                "recipe_identity": recipe, "generation_mode": "major-rebuild",
                "cases": cases}
    path = os.path.join(SOURCE, "tests", "manifest.json")
    with open(path, "w", encoding="utf-8", newline="") as handle:
        handle.write(canonical(manifest))
    print("wrote %d cases to %s" % (len(cases), path))


if __name__ == "__main__":
    main()
