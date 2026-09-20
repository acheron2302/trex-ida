"""IDA-side check for the write-back: are trex types stored in the database?

Driven by tests/e2e/test_apply.py with `idat -A -S verify_written.py`, after the plugin ran
"infer all" then "apply". Enumerates every function's *user* lvar settings and counts the
variables that now carry a type, printing the first few as `WRITTEN <func> <var> <type>`.

Exit code 0 = at least one function carries trex-written variable types.
"""

import ida_auto
import ida_funcs
import ida_hexrays
import idc

ida_auto.auto_wait()

total = 0
functions = 0
samples = []
qty = ida_funcs.get_func_qty()
for i in range(qty):
    fn = ida_funcs.getn_func(i)
    if fn is None:
        continue
    lvinf = ida_hexrays.lvar_uservec_t()
    if not ida_hexrays.restore_user_lvar_settings(lvinf, fn.start_ea):
        continue
    here = 0
    for entry in lvinf.lvvec:
        if entry.type.empty():
            continue
        here += 1
        if len(samples) < 8:
            samples.append((fn.start_ea, str(entry.name), str(entry.type)))
    if here:
        functions += 1
        total += here

for ea, name, typ in samples:
    print("WRITTEN %X %s %s" % (ea, name, typ))
print("WRITTEN_TOTAL %d" % total)
print("WRITTEN_FUNCTIONS %d" % functions)

idc.qexit(0 if total > 0 else 1)
