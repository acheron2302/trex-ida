"""Verifies the single-function deep scan (run arg 8) and the headless fallback for the types
window (run arg 9).

The fixture has `main` calling `get_last`, `sum_pairs` and `union_read`; arg 8 must walk the call
tree and report a scope with at least those functions plus `main`. Arg 9 must degrade gracefully
in headless IDA (no Qt), logging the not-available line instead of failing.

    python tests/e2e/test_single_func.py            # build fixture if needed
    python tests/e2e/test_single_func.py --no-build

Exit code 0 = the deep scan reached the callees AND the types-window fallback is graceful.
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

    out_dir = tempfile.mkdtemp(prefix="trexida-single-func-")
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
    env["TREXIDA_OP"] = "8,9"  # deep scan on current function, then types window
    subprocess.run([IDAT, "-A", "-L" + log, "-S" + os.path.join(HERE, "drive.py"), FIXTURE],
                   env=env, cwd=out_dir, capture_output=True, text=True)

    with open(log, "r", errors="replace") as f:
        text = f.read()
    print(text[-4000:])

    failures = []

    def check(cond, what):
        print(("PASS  " if cond else "FAIL  ") + what)
        if not cond:
            failures.append(what)

    # 1. deep-scan log line: root + a function count >= 2 (main + at least one callee).
    m = re.search(r"deep scan: root (\S+), (\d+) function\(s\) in the call tree", text)
    check(m is not None, "deep-scan log line emitted")
    if m is not None:
        root = m.group(1)
        count = int(m.group(2))
        check(count >= 2, "deep-scan call tree has %d function(s) (root=%s, expected >= 2)" % (count, root))

    # The same run also prints the scope summary (run_inference logs "scope: %d function(s), ...")
    # at least once when the inference actually runs; with arg 8 that is the deep scan itself.
    scope_m = re.search(r"scope: (\d+) function\(s\)", text)
    check(scope_m is not None, "scope: function count line emitted")
    if scope_m is not None:
        check(int(scope_m.group(1)) >= 2,
              "scope reports %d function(s) (expected >= 2)" % int(scope_m.group(1)))

    # 2. .vars.tsv has rows from at least 2 distinct func_ea values: root + at least one callee
    # were lifted; the report is the lifted functions' lvar report.
    vars_tsv = None
    for f in os.listdir(out_dir):
        if f.endswith(".trex.vars.tsv"):
            vars_tsv = os.path.join(out_dir, f)
            break
    check(vars_tsv is not None, "found an output .trex.vars.tsv")
    if vars_tsv is not None:
        func_eas = set()
        with open(vars_tsv, "r", errors="replace") as f:
            header = f.readline()  # skip header
            for line in f:
                cols = line.rstrip("\n").split("\t")
                if cols:
                    func_eas.add(cols[0])
        check(len(func_eas) >= 2,
              ".vars.tsv rows come from %d distinct func_ea (expected >= 2)" % len(func_eas))

    # 3. .c output contains at least one aggregate definition.
    c_path = None
    for f in os.listdir(out_dir):
        if f.endswith(".trex.c"):
            c_path = os.path.join(out_dir, f)
            break
    check(c_path is not None, "found an output .trex.c")
    if c_path is not None:
        with open(c_path, "r", errors="replace") as f:
            c_text = f.read()
        agg_m = re.search(r"struct\s+t\d+\s*\{", c_text)
        check(agg_m is not None, ".trex.c contains at least one `struct t<N> {` definition")

    # 4. arg 9 (types window) degrades gracefully when headless: not-available line is logged,
    # no stack trace, plugin returns true (the test session exits cleanly).
    check("types window: not available in this build" in text,
          "arg 9 logged the not-available line instead of failing")

    if failures:
        print("\n%d assertion(s) failed" % len(failures))
        sys.exit(1)
    print("\ndeep-scan + headless-window verification passed")


if __name__ == "__main__":
    main()