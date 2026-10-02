"""Regression test for the IDA microcode frontend.

Runs the plugin's diagnostics lift action head-less over the fixture binary and compares the
emitted IL and variable report against the recorded golden files. This is the only automatable
coverage the microcode frontend can have without the full inference pipeline: it pins the exact
IL shape (including the `Load(Deref(IntAdd(base, const)))` pattern the co-location analysis
depends on), the fallback count and the IL validator result.

    python tests/e2e/test_lift.py            # build fixture if needed, run, compare
    python tests/e2e/test_lift.py --update   # re-record the golden files

Exit code 0 = the lift matches the golden files and validates cleanly.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
IDA = os.environ.get("IDADIR", r"D:\tools\IDA 9.4")
IDAT = os.path.join(IDA, "idat.exe")
FIXTURE = os.path.join(HERE, "fixture.exe")
GOLDEN = os.path.join(HERE, "golden")


def run_ida(out_dir):
    for suffix in (".i64", ".id0", ".id1", ".nam", ".til"):
        stale = FIXTURE + suffix
        if os.path.exists(stale):
            os.remove(stale)
    log = os.path.join(out_dir, "ida.log")
    env = dict(os.environ)
    env["TREXIDA_OUTPUT_DIR"] = out_dir
    env["TREXIDA_OP"] = "6"  # ARG_LIFT
    # Pin the root to get_last (the first function in the fixture, and the one the golden files
    # were recorded from). Headless IDA has no cursor, so without this the scope would fall back to
    # the entry point and pull in the whole CRT startup tree, which legitimately needs fallbacks.
    env["TREXIDA_PROBE_EA"] = "0x140001000"
    subprocess.run(
        [IDAT, "-A", "-L" + log, "-S" + os.path.join(HERE, "drive.py"), FIXTURE],
        env=env,
        cwd=out_dir,
        capture_output=True,
        text=True,
    )
    with open(log, "r", errors="replace") as f:
        return f.read()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--update", action="store_true", help="re-record the golden files")
    args = ap.parse_args()

    if not os.path.exists(FIXTURE):
        r = subprocess.run(["cmd", "/c", os.path.join(HERE, "build-fixture.bat")], cwd=HERE)
        if r.returncode != 0:
            sys.exit("fixture build failed")

    out_dir = tempfile.mkdtemp(prefix="trexida-lift-")
    log = run_ida(out_dir)
    print(log)

    failures = []

    def check(cond, what):
        print(("PASS  " if cond else "FAIL  ") + what)
        if not cond:
            failures.append(what)

    check("[trexida] loaded" in log, "plugin loaded")
    check(re.search(r"IL validation: 0 invalid instruction", log) is not None,
          "every emitted IL instruction passes try_confirm_valid")
    check(re.search(r"0 fallback\(s\)", log) is not None,
          "no instruction fell back to UnderspecifiedOutputModification for the fixture")

    produced = sorted(f for f in os.listdir(out_dir) if f.startswith("trex_lift_"))
    check(len(produced) == 2, "lift action wrote its dump files")

    os.makedirs(GOLDEN, exist_ok=True)
    for name in produced:
        new = open(os.path.join(out_dir, name), "r", errors="replace").read()
        path = os.path.join(GOLDEN, name)
        if args.update or not os.path.exists(path):
            with open(path, "w", newline="") as f:
                f.write(new)
            print("recorded %s" % name)
            continue
        old = open(path, "r", errors="replace").read()
        if old != new:
            failures.append(name + " differs from the golden file")
            print("FAIL  %s differs" % name)
            for i, (a, b) in enumerate(zip(old.splitlines(), new.splitlines())):
                if a != b:
                    print("  line %d:\n    golden: %s\n    actual: %s" % (i + 1, a, b))
                    break
        else:
            print("PASS  %s matches the golden file" % name)

    shutil.rmtree(out_dir, ignore_errors=True)
    if failures:
        print("\n%d check(s) failed" % len(failures))
        sys.exit(1)
    print("\nlift regression test passed")


if __name__ == "__main__":
    main()
