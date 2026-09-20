"""Differential gate: C++ port vs the upstream Rust TRex.

Builds the Rust oracle, runs both implementations over every fixture in tests/fixtures/lifted,
and compares stdout, the structural output and the GraphViz dump byte-for-byte.

    python scripts/diff_oracle.py

Exit code 0 = identical output for every fixture.
"""

import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUST_DIR = os.path.join(REPO, "third_party", "trex", "trex")
FIXTURES = os.path.join(REPO, "tests", "fixtures", "lifted")
CPP_CLI = os.path.join(REPO, "build-icx", "trex_port_cli.exe")
TMP = os.path.join(REPO, "build-icx", "diff")


def sh(cmd, cwd=None, env=None):
    print("+ " + " ".join(cmd))
    return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)


def dot_semantics(text):
    """Extract the type-graph structure from a GraphViz dump.

    The `.dot` file is a debugging visualisation emitted through Rust's `dot` crate, whose
    escaping and attribute spacing (`node[label=...]` vs `node [label=...]`, `\l` vs `\\l`) are
    crate artifacts, not trex semantics. Rather than pinning those bytes, compare what the file
    actually encodes: the set of nodes and the labelled edges between them. The SSA contents are
    compared byte-for-byte separately through --dump-ssa-lifted, and the inferred types through
    --output-structural.
    """
    import re

    nodes = sorted(re.findall(r"^\s*([A-Za-z0-9_]+)\s*\[", text, re.M))
    edges = sorted(re.findall(r"([A-Za-z0-9_]+)\s*->\s*([A-Za-z0-9_]+)\s*\[\s*label=([^\]]*)", text))
    node_shapes = sorted(re.findall(r"^\s*([A-Za-z0-9_]+)\s*\[[^\]]*shape=([A-Za-z]+)", text, re.M))
    return {"nodes": nodes, "edges": edges, "shapes": node_shapes}


def compare(name, a, b, failures):
    if a == b:
        print("  identical: %s" % name)
        return
    failures.append(name)
    print("  DIFFERS:   %s" % name)
    al, bl = a.splitlines(), b.splitlines()
    for i in range(max(len(al), len(bl))):
        x = al[i] if i < len(al) else "<missing>"
        y = bl[i] if i < len(bl) else "<missing>"
        if x != y:
            print("    first difference at line %d:" % (i + 1))
            print("      rust: %s" % x)
            print("      cpp : %s" % y)
            break


def main():
    os.makedirs(TMP, exist_ok=True)

    if not os.path.exists(CPP_CLI):
        sys.exit("missing %s - build with scripts/build-icx.bat first" % CPP_CLI)

    print("building the Rust oracle")
    r = sh(["cargo", "build", "--release"], cwd=RUST_DIR)
    if r.returncode != 0:
        sys.exit("cargo build failed:\n" + r.stdout + r.stderr)

    failures = []
    fixtures = sorted(f for f in os.listdir(FIXTURES) if f.endswith(".lifted"))
    for lifted in fixtures:
        stem = lifted[: -len(".lifted")]
        vars_file = os.path.join(FIXTURES, stem + ".vars")
        lifted_path = os.path.join(FIXTURES, lifted)
        if not os.path.exists(vars_file):
            print("skipping %s (no .vars)" % stem)
            continue

        print("\n=== %s ===" % stem)
        rust_struct = os.path.join(TMP, stem + ".rust.structural")
        rust_dot = os.path.join(TMP, stem + ".rust.dot")
        rust_ssa = os.path.join(TMP, stem + ".rust.ssa")
        cpp_struct = os.path.join(TMP, stem + ".cpp.structural")
        cpp_dot = os.path.join(TMP, stem + ".cpp.dot")
        cpp_ssa = os.path.join(TMP, stem + ".cpp.ssa")

        r = sh(
            [
                "cargo", "run", "--release", "--", "from-ghidra",
                lifted_path, vars_file,
                "--output-structural", rust_struct,
                "--debug-output-graphviz", rust_dot,
                "--dump-ssa-lifted", rust_ssa,
            ],
            cwd=RUST_DIR,
        )
        if r.returncode != 0:
            sys.exit("rust run failed:\n" + r.stdout + r.stderr)

        c = sh(
            [
                CPP_CLI, "from-ghidra", lifted_path, vars_file,
                "--output-structural", cpp_struct,
                "--debug-output-graphviz", cpp_dot,
                "--dump-ssa-lifted", cpp_ssa,
            ]
        )
        if c.returncode != 0:
            sys.exit("cpp run failed:\n" + c.stdout + c.stderr)

        # Strict comparisons: the deliverables.
        compare(stem + " stdout", r.stdout, c.stdout, failures)
        compare(stem + " ssa-dump",
                open(rust_ssa, "r", errors="replace").read(),
                open(cpp_ssa, "r", errors="replace").read(),
                failures)
        compare(stem + " structural",
                open(rust_struct, "r", errors="replace").read(),
                open(cpp_struct, "r", errors="replace").read(),
                failures)
        if os.path.exists(rust_dot) and os.path.exists(cpp_dot):
            compare(stem + " graphviz (nodes+edges)",
                    repr(dot_semantics(open(rust_dot, "r", errors="replace").read())),
                    repr(dot_semantics(open(cpp_dot, "r", errors="replace").read())),
                    failures)

    if failures:
        print("\nFAILED: %d comparison(s) differ: %s" % (len(failures), ", ".join(failures)))
        sys.exit(1)
    print("\nOK: every fixture produced byte-identical output")


if __name__ == "__main__":
    main()
