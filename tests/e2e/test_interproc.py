"""Verifies inter-procedural type propagation end to end.

Runs the same fixture twice in IDA, once with propagation on (the default) and once with
`TREXIDA_INTERPROC=0`, and compares the inferred types of the three exported functions' parameters
in `.trex.vars.tsv`:

  * on:  `pass`, `use_a` and `use_b` all take one aggregate pointer type, because `main` passes the
         result of `pass(&a)` to `use_a` and `pass(&b)` to `use_b`, so the two call sites of `pass`
         and the parameters that receive its results are joined into one type (the paper's "multiple
         paths through a single void* produce precise unions");
  * off: `use_a` and `use_b` keep their own per-function types, and neither matches the merged one.

    python tests/e2e/test_interproc.py            # build fixture if needed
    python tests/e2e/test_interproc.py --no-build

Exit code 0 = propagation is observable and switchable.
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
DRIVE = os.path.join(HERE, "drive.py")
FIXTURE = os.path.join(HERE, "interproc.exe")
TARGETS = ("pass", "use_a", "use_b")
DB_SUFFIXES = (".i64", ".id0", ".id1", ".id2", ".nam", ".til")


def run_ida(out_dir, interproc):
    """One IDA session reconstructing types for all functions; returns (log, arg types)."""
    for suffix in DB_SUFFIXES:
        stale = FIXTURE + suffix
        if os.path.exists(stale):
            try:
                os.remove(stale)
            except OSError:
                pass

    env = dict(os.environ)
    env["TREXIDA_OP"] = "2"
    env["TREXIDA_OUTPUT_DIR"] = out_dir
    env.pop("TREXIDA_INTERPROC", None)
    if interproc is not None:
        env["TREXIDA_INTERPROC"] = interproc

    log_path = os.path.join(out_dir, "trexida.log")
    subprocess.run([IDAT, "-A", "-L" + log_path, "-S" + DRIVE, FIXTURE], env=env, cwd=out_dir,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1800)

    log = ""
    if os.path.exists(log_path):
        with open(log_path, encoding="utf-8", errors="replace") as handle:
            log = handle.read()

    tsv = os.path.join(out_dir, os.path.basename(FIXTURE) + ".trex.vars.tsv")
    arg_types = {}
    if os.path.exists(tsv):
        with open(tsv, encoding="utf-8", errors="replace") as handle:
            rows = [line.rstrip("\n").split("\t") for line in handle][1:]
        for row in rows:
            if len(row) >= 7 and row[3] == "arg" and row[1] in TARGETS:
                arg_types[row[1]] = row[6]
    return log, arg_types


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-build", action="store_true")
    args = ap.parse_args()

    if not args.no_build:
        subprocess.run(["cmd", "/c", os.path.join(HERE, "build-interproc.bat")], cwd=HERE)

    failures = []

    on_dir = tempfile.mkdtemp(prefix="trexida-interproc-on-")
    off_dir = tempfile.mkdtemp(prefix="trexida-interproc-off-")
    log_on, types_on = run_ida(on_dir, None)
    log_off, types_off = run_ida(off_dir, "0")

    print("on : %s" % types_on)
    print("off: %s" % types_off)

    for name in TARGETS:
        if name not in types_on or name not in types_off:
            failures.append("no report row for parameter `%s` (on: %s, off: %s)"
                            % (name, name in types_on, name in types_off))
    if failures:
        print("\n".join(failures))
        return 1

    # The pass ran and reported bindings.
    match = re.search(r"\[trexida\] inter-procedural: (\d+) call site\(s\), (\d+) argument binding",
                      log_on)
    if match is None:
        failures.append("the inference log has no `inter-procedural:` line:\n%s"
                        % "\n".join(line for line in log_on.splitlines()
                                    if "inter-procedural" in line or "inferred" in line))
    elif int(match.group(2)) == 0:
        failures.append("inter-procedural reported 0 argument bindings")

    # On: every parameter that a call edge reaches shares one aggregate pointer type.
    merged = types_on["use_a"]
    for name in TARGETS:
        if types_on[name] != merged:
            failures.append("on: `%s` has type `%s` but `use_a` has `%s`"
                            % (name, types_on[name], merged))
    if merged == "-" or "*" not in merged or "t" not in merged:
        failures.append("on: the shared type `%s` is not an aggregate pointer" % merged)

    # Off: the per-function types are unrelated, and the merged type is not one of them.
    if types_off["use_a"] == types_off["use_b"]:
        failures.append("off: `use_a` and `use_b` already share the type `%s`, so the fixture "
                        "cannot distinguish the two runs" % types_off["use_a"])
    for name in ("use_a", "use_b"):
        if types_off[name] == "-":
            failures.append("off: `%s` has no inferred type" % name)
        if types_off[name] == merged:
            failures.append("off: `%s` already has the merged type `%s`" % (name, merged))

    if failures:
        print("\nFAIL")
        print("\n".join("  - " + f for f in failures))
        return 1

    print("PASS  inter-procedural propagation: `pass`, `use_a` and `use_b` share `%s` with it on, "
          "and `use_a`/`use_b` keep `%s`/`%s` with it off"
          % (merged, types_off["use_a"], types_off["use_b"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
