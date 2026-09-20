"""Verifies the write-back action (`trexida:apply`) actually changes the database.

Runs three actions in one IDA session: reconstruct types for all functions (2), apply them to the
database (4), then dump one function's microcode and lvars (0 = probe). The probe prints each
lvar's IDA type; if the write-back worked, at least one local variable must now carry a trex-defined
type (a `t<N>` struct or a pointer to one) instead of a plain `_QWORD`/`_DWORD`.

    python tests/e2e/test_apply.py            # build fixture if needed
    python tests/e2e/test_apply.py --no-build

Exit code 0 = the write-back is observable in the database.
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
IDA = os.environ.get("IDADIR", r"D:\tools\IDA 9.4")
IDAT = os.path.join(IDA, "idat.exe")
FIXTURE = os.path.join(HERE, "fixture.exe")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-build", action="store_true")
    args = ap.parse_args()

    if not args.no_build:
        subprocess.run(["cmd", "/c", os.path.join(HERE, "build-fixture.bat")], cwd=HERE)

    out_dir = tempfile.mkdtemp(prefix="trexida-apply-")
    for suffix in (".i64", ".id0", ".id1", ".id2", ".nam", ".til"):
        stale = FIXTURE + suffix
        if os.path.exists(stale):
            try:
                os.remove(stale)
            except OSError:
                pass

    log = os.path.join(out_dir, "ida.log")
    env = dict(os.environ)
    env["TREXIDA_OUTPUT_DIR"] = out_dir
    env["TREXIDA_OP"] = "2,4"  # infer all, then apply to the database
    subprocess.run([IDAT, "-A", "-L" + log, "-S" + os.path.join(HERE, "drive.py"), FIXTURE],
                   env=env, cwd=out_dir, capture_output=True, text=True)

    # Second session: enumerate the database's user lvar settings (the write-back target).
    check_log = os.path.join(out_dir, "written.log")
    subprocess.run(
        [IDAT, "-A", "-L" + check_log, "-S" + os.path.join(HERE, "verify_written.py"), FIXTURE],
        env=env, cwd=out_dir, capture_output=True, text=True)
    with open(check_log, "r", errors="replace") as f:
        written = f.read()

    with open(log, "r", errors="replace") as f:
        text = f.read()
    print(text[-4000:])

    failures = []

    def check(cond, what):
        print(("PASS  " if cond else "FAIL  ") + what)
        if not cond:
            failures.append(what)

    m = re.search(r"applied inferred types: (\d+) variable\(s\) updated", text)
    check(m is not None, "apply action reported its result")
    applied = int(m.group(1)) if m else 0
    check(applied > 0, "apply action updated %d variable(s)" % applied)

    # The database must now store types for variables that had none before.
    m2 = re.search(r"WRITTEN_TOTAL (\d+)", written)
    total = int(m2.group(1)) if m2 else 0
    check(total > 0, "the database stores types for %d variable(s)" % total)
    for line in written.splitlines():
        if line.startswith("WRITTEN "):
            print("  " + line)

    if failures:
        print("\n%d assertion(s) failed" % len(failures))
        sys.exit(1)
    print("\nwrite-back verification passed")


if __name__ == "__main__":
    main()
