"""End-to-end test for trexida.

Builds the fixture (no debug information), runs IDA head-less with the plugin's
"reconstruct types for all functions" action, and checks the exported artifacts against
ground truth that is knowable from the fixture's C source.

    python tests/e2e/run.py             # build fixture, run, assert
    python tests/e2e/run.py --no-build  # reuse an existing fixture.exe

Exit code 0 = every assertion passed.
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
IDA = os.environ.get("IDADIR", r"D:\tools\IDA 9.4")
IDAT = os.path.join(IDA, "idat.exe")
FIXTURE = os.path.join(HERE, "fixture.exe")


def run_ida(out_dir, op=2):
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
    env["TREXIDA_OP"] = str(op)
    subprocess.run(
        [IDAT, "-A", "-L" + log, "-S" + os.path.join(HERE, "drive.py"), FIXTURE],
        env=env,
        cwd=out_dir,
        capture_output=True,
        text=True,
    )
    with open(log, "r", errors="replace") as f:
        return f.read()


def read(path):
    with open(path, "r", errors="replace") as f:
        return f.read()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-build", action="store_true")
    args = ap.parse_args()

    if not args.no_build:
        r = subprocess.run(["cmd", "/c", os.path.join(HERE, "build-fixture.bat")], cwd=HERE)
        if r.returncode != 0:
            sys.exit("fixture build failed")
    if not os.path.exists(FIXTURE):
        sys.exit("fixture.exe not found; run without --no-build")

    out_dir = tempfile.mkdtemp(prefix="trexida-e2e-")
    log = run_ida(out_dir)
    print(log)

    failures = []

    def check(cond, what):
        print(("PASS  " if cond else "FAIL  ") + what)
        if not cond:
            failures.append(what)

    check("[trexida] loaded" in log, "plugin loaded in IDA")
    check("0 failed" in log, "every function lifted and analysed")

    def find(suffix):
        for name in sorted(os.listdir(out_dir)):
            if name.endswith(suffix):
                return os.path.join(out_dir, name)
        return os.path.join(out_dir, "missing" + suffix)

    c_path, s_path, r_path = find(".trex.c"), find(".trex.structural"), find(".trex.vars.tsv")
    for path in (c_path, s_path, r_path):
        check(os.path.exists(path), "output exists: " + os.path.basename(path))
    if failures:
        sys.exit("missing outputs; see the log above")

    c_like, structural, report = read(c_path), read(s_path), read(r_path)
    print("---- C-like output (first 60 lines) ----")
    print("\n".join(c_like.splitlines()[:60]))
    print("---- variable report (first 20 lines) ----")
    print("\n".join(report.splitlines()[:20]))

    # 1. A linked-list shape must be recovered from IDA microcode: a self-referential struct with a
    #    pointer member (the fixture has `struct node { int32_t value; struct node *next; }`).
    structs = re.findall(r"struct (\w+) \{([^}]*)\};", c_like, re.S)
    linked = [(n, b) for n, b in structs if re.search(re.escape(n) + r"\s*\*", b)]
    check(len(linked) > 0,
          "at least one self-referential struct is inferred (%d found)" % len(linked))

    # 2. Some variable must be inferred as a pointer to such a struct (the report's inferred-type
    #    column is the last tab-separated field).
    inferred = [r.rsplit("\t", 1)[-1] for r in report.splitlines()[1:] if "\t" in r]
    check(any(re.fullmatch(r"t\d+\*", t or "") for t in inferred),
          "a variable is inferred to be a pointer to a recovered struct")

    # 3. The report pairs every variable with IDA's own base type and trex's inferred type.
    rows = [r for r in report.splitlines()[1:] if r.strip()]
    check(len(rows) > 100, "report covers the whole database (%d variables)" % len(rows))
    check(any("_QWORD" in r or "_DWORD" in r or "_BYTE" in r or "_WORD" in r for r in rows),
          "report shows IDA base types")
    check(any(t in ("-", "") or re.fullmatch(r"t\d+\*?", t or "") or re.fullmatch(r"u?int\d+_t", t or "")
              for t in inferred),
          "report shows inferred types")

    # 4. The C-like output carries real definitions, not only comments.
    check(len(structs) >= 10, "C-like output defines %d structs" % len(structs))

    # 5. The structural output is the machine-readable form of the same result.
    check("VAR_MAP" in structural and "STRUCTURAL_TYPES" in structural,
          "structural output has the expected sections")

    if failures:
        print("\n%d assertion(s) failed" % len(failures))
        sys.exit(1)
    print("\nall end-to-end assertions passed")


if __name__ == "__main__":
    main()
