"""Run both framework modes against the exported zipapp."""

import json
import subprocess
import sys


def main(argv):
    export = argv[0]
    test = subprocess.run(
        [sys.executable, "-B", export, "--litai-test"],
        capture_output=True,
        text=True,
    )
    if test.returncode != 0:
        sys.stderr.write(test.stdout + test.stderr)
        return 1
    report = json.loads(test.stdout)
    if report.get("schema") != "literate-ai/generated-test-results@1" or not report.get("cases"):
        sys.stderr.write("unexpected --litai-test report\n")
        return 1
    if any(case.get("outcome") != "passed" for case in report["cases"]):
        sys.stderr.write("a generated case failed\n")
        return 1
    smoke = subprocess.run(
        [sys.executable, "-B", export, "--litai-smoke"],
        capture_output=True,
        text=True,
    )
    if smoke.returncode != 0:
        sys.stderr.write(smoke.stdout + smoke.stderr)
        return 1
    json.loads(smoke.stdout)
    print(f"export passed {len(report['cases'])} generated cases and smoke")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
