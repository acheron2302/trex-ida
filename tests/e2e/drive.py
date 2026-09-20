"""Trigger a trexida run inside IDA and exit.

Used by tests/e2e/run.py:
    idat64.exe -A -L<log> -S"drive.py" <target>
The operation is chosen with $TREXIDA_OP (an integer run() argument);
defaults to 2 = "reconstruct types for all functions".
"""

import os

import ida_auto
import ida_loader
import idc

ida_auto.auto_wait()

# TREXIDA_OP may be a comma-separated sequence, so several actions can run in one session
# (e.g. "2,4" = reconstruct types for all functions, then apply them to the database).
ops = [int(x) for x in os.environ.get("TREXIDA_OP", "2").split(",") if x.strip()]
for op in ops:
    print("[trexida-test] driving operation %d" % op)
    ok = ida_loader.load_and_run_plugin("trexida", op)
    print("[trexida-test] load_and_run_plugin(%d) -> %s" % (op, ok))

idc.qexit(0)
