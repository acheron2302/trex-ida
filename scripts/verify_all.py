"""Run every verification stage of the trexida port and summarise the result.

Stages (each is also runnable on its own):
  1. build (icx-cl, the required configuration)   -> scripts/build-icx.bat
  2. core unit tests (transcribed upstream tests) -> build-icx/trex_unit_tests.exe
  3. differential gate vs the Rust oracle         -> scripts/diff_oracle.py
  4. IDA frontend lift regression (golden files)  -> tests/e2e/test_lift.py
  5. end-to-end in IDA on the fixture binary      -> tests/e2e/run.py
  6. write-back into the database                 -> tests/e2e/test_apply.py
  7. inter-procedural type propagation            -> tests/e2e/test_interproc.py

    python scripts/verify_all.py [--skip-build]
"""

import argparse
import subprocess
import sys
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(name, cmd, cwd=None, must_pass=True):
    print("\n" + "=" * 72)
    print("== " + name)
    print("=" * 72)
    r = subprocess.run(cmd, cwd=cwd or REPO, capture_output=True, text=True)
    sys.stdout.write(r.stdout[-6000:])
    if r.returncode != 0:
        sys.stdout.write(r.stderr[-4000:])
    ok = r.returncode == 0
    print("-> %s (exit %d)" % ("PASS" if ok else "FAIL", r.returncode))
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-build", action="store_true")
    args = ap.parse_args()

    results = []

    if not args.skip_build:
        results.append(("build (icx-cl)", run("build", ["cmd", "/c", os.path.join(REPO, "scripts", "build-icx.bat")])))

    results.append(("unit tests", run("unit tests",
                                      [os.path.join(REPO, "build-icx", "trex_unit_tests.exe")])))
    results.append(("differential gate", run("differential gate",
                                             [sys.executable, os.path.join(REPO, "scripts", "diff_oracle.py")])))
    results.append(("lift regression", run("lift regression",
                                           [sys.executable, os.path.join(REPO, "tests", "e2e", "test_lift.py")])))
    results.append(("end-to-end", run("end-to-end",
                                      [sys.executable, os.path.join(REPO, "tests", "e2e", "run.py")])))
    results.append(("write-back", run("write-back",
                                      [sys.executable, os.path.join(REPO, "tests", "e2e", "test_apply.py")])))
    results.append(("inter-procedural", run("inter-procedural",
                                            [sys.executable, os.path.join(REPO, "tests", "e2e", "test_interproc.py")])))

    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)
    failed = 0
    for name, ok in results:
        print("%-20s %s" % (name, "PASS" if ok else "FAIL"))
        failed += 0 if ok else 1
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
