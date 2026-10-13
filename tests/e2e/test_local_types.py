"""Verifies the native local types `trexida:apply` installs.

Runs two IDA sessions: the first reconstructs types for all functions (2) and applies them to the
database (4); the second opens the resulting type library and dumps every aggregate and member
(verify_local_types.py). Nothing in the suite opened the type library before, so this is what
proves the aggregates really landed with the offsets the analysis recovered.

    python tests/e2e/test_local_types.py            # build fixture if needed
    python tests/e2e/test_local_types.py --no-build

Exit code 0 = the local types are present, correctly laid out, and used by at least one variable.
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

    out_dir = tempfile.mkdtemp(prefix="trexida-localtypes-")
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

    check_log = os.path.join(out_dir, "local_types.log")
    subprocess.run(
        [IDAT, "-A", "-L" + check_log, "-S" + os.path.join(HERE, "verify_local_types.py"), FIXTURE],
        env=env, cwd=out_dir, capture_output=True, text=True)
    with open(check_log, "r", errors="replace") as f:
        written = f.read()

    with open(log, "r", errors="replace") as f:
        text = f.read()

    failures = []

    def check(cond, what):
        print(("PASS  " if cond else "FAIL  ") + what)
        if not cond:
            failures.append(what)

    # ---- parse the verifier's output
    types = {}          # name -> {"kind", "size", "members": [(name, off, size, gap, type)]}
    var_types = []
    for line in written.splitlines():
        m = re.match(r"LOCAL_TYPE (\S+) (struct|union) size=(\d+) nmembers=(\d+)$", line)
        if m:
            types[m.group(1)] = {"kind": m.group(2), "size": int(m.group(3)), "members": []}
            continue
        m = re.match(r"LOCAL_MEMBER (\S+) (\S+) off=(\d+) size=(\d+) gap=([01]) type=(.*)$", line)
        if m:
            entry = types.get(m.group(1))
            if entry is None:
                failures.append("member of an unknown type: " + line)
                continue
            entry["members"].append(
                (m.group(2), int(m.group(3)), int(m.group(4)), int(m.group(5)), m.group(6)))
            continue
        m = re.match(r"LOCAL_VAR ([0-9A-Fa-f]+) (\S+) (.*)$", line)
        if m:
            var_types.append(m.group(3))

    # ---- 1. the apply action still writes variable types
    m = re.search(r"applied inferred types: (\d+) variable\(s\) updated", text)
    check(m is not None and int(m.group(1)) > 0,
          "apply action updated variable types (got %s)" % (m.group(1) if m else "nothing"))

    # ---- 2. at least one aggregate reached the type library
    structs = [n for n, t in types.items() if t["kind"] == "struct"]
    check(len(structs) > 0, "%d trex struct(s) in the local type library" % len(structs))

    # ---- 3. members are ordered and never overlap. Only structs can be checked for overlap:
    #        every union alternative starts at 0 by construction.
    overlapping = []
    out_of_order = []
    for name, entry in sorted(types.items()):
        members = sorted(entry["members"], key=lambda x: x[1])
        for a, b in zip(members, members[1:]):
            if a[1] > b[1]:
                out_of_order.append("%s: %s@%d before %s@%d" % (name, a[0], a[1], b[0], b[1]))
            elif entry["kind"] == "struct" and a[1] + a[2] > b[1]:
                overlapping.append("%s: %s [%d,%d) overlaps %s@%d"
                                   % (name, a[0], a[1], a[1] + a[2], b[0], b[1]))
    check(not out_of_order, "every aggregate's members are sorted by offset (%s)" % out_of_order[:3])
    check(not overlapping, "no aggregate has overlapping members (%s)" % overlapping[:3])

    # ---- 4. `field_<n>` really is at byte offset n. This is the regression the old hex-decoding
    #        text path could not pass for any n >= 10.
    bad_names = []
    for name, entry in sorted(types.items()):
        for mname, off, size, gap, printed in entry["members"]:
            fm = re.match(r"^field_(\d+)$", mname)
            if fm and off != 8 * int(fm.group(1), 10):
                bad_names.append("%s.%s at bit %d, expected %d" % (name, mname, off, 8 * int(fm.group(1), 10)))
    check(not bad_names, "field_<decimal> members sit at their decimal offset (%s)" % bad_names[:3])

    # ---- 5. gap members cover exactly the bytes between their neighbours
    bad_gaps = []
    gap_total = 0
    for name, entry in sorted(types.items()):
        members = sorted(entry["members"], key=lambda x: x[1])
        for i, (mname, off, size, gap, printed) in enumerate(members):
            if not gap:
                continue
            gap_total += 1
            if i + 1 < len(members):
                expect = members[i + 1][1] - off
            else:
                expect = entry["size"] * 8 - off
            if size != expect:
                bad_gaps.append("%s.%s size=%d expected %d" % (name, mname, size, expect))
    check(gap_total > 0, "%d gap member(s) installed" % gap_total)
    check(not bad_gaps, "gap members span exactly their uncovered bytes (%s)" % bad_gaps[:3])

    # ---- 6. a variable's type names an aggregate that is really in the library
    linked = [v for v in var_types if any(n in v for n in types)]
    check(len(linked) > 0, "%d variable(s) typed by a trex aggregate" % len(linked))

    for line in written.splitlines():
        if line.startswith("LOCAL_"):
            print("  " + line)

    if failures:
        print("\n%d assertion(s) failed" % len(failures))
        sys.exit(1)
    print("\nnative local type verification passed")


if __name__ == "__main__":
    main()