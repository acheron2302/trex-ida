"""IDA-side check for the native local types: does the type library hold the TRex aggregates?

Driven by tests/e2e/test_local_types.py with `idat -A -S verify_local_types.py`, after the
plugin ran "infer all" then "apply". Walks the local type library, prints one machine-parsable
line per aggregate and per member, and one line per variable that now carries a trex type.

    LOCAL_TYPE t1 struct size=12 nmembers=2
    LOCAL_MEMBER t1 field_0 off=0 size=64 gap=0 type=t1 *
    LOCAL_MEMBER t1 gap_field_8 off=64 size=8 gap=1 type=uint8_t[8]
    LOCAL_VAR <ea> <name> t1 *

`off` / `size` are the raw member bit offsets and sizes as IDA reports them. Exit code 0 = at
least one trex aggregate is installed.
"""

import ida_auto
import ida_funcs
import ida_hexrays
import ida_typeinf
import idc

ida_auto.auto_wait()

til = ida_typeinf.get_idati()


def tinfo_named(name):
    tif = ida_typeinf.tinfo_t()
    if tif.get_named_type(til, name):
        return tif
    return None


total_types = 0
for name in til.named_types():
    tif = tinfo_named(str(name))
    if tif is None or not tif.is_udt():
        continue
    kind = "union" if tif.is_union() else "struct"
    print("LOCAL_TYPE %s %s size=%d nmembers=%d"
          % (name, kind, tif.get_size(), tif.get_udt_nmembers()))
    total_types += 1
    for udm in tif.iter_udt():
        print("LOCAL_MEMBER %s %s off=%d size=%d gap=%d type=%s"
              % (name, str(udm.name), udm.offset, udm.size,
                 1 if udm.is_gap() else 0, str(udm.type)))
print("LOCAL_TYPE_TOTAL %d" % total_types)

# Which variables now point at a trex aggregate?
written = 0
named_types = set(str(n) for n in til.named_types())
qty = ida_funcs.get_func_qty()
for i in range(qty):
    fn = ida_funcs.getn_func(i)
    if fn is None:
        continue
    lvinf = ida_hexrays.lvar_uservec_t()
    if not ida_hexrays.restore_user_lvar_settings(lvinf, fn.start_ea):
        continue
    for entry in lvinf.lvvec:
        if entry.type.empty():
            continue
        printed = str(entry.type)
        hits = [t for t in named_types if t in printed]
        if not hits:
            continue
        written += 1
        if written <= 8:
            print("LOCAL_VAR %X %s %s" % (fn.start_ea, str(entry.name), printed))
print("LOCAL_VAR_TOTAL %d" % written)

idc.qexit(0 if total_types > 0 else 1)