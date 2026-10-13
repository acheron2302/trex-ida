// trexida - TRex type reconstruction for IDA Pro, driven by Hex-Rays microcode.
//
// S0: plugin skeleton plus the diagnostics probe that pins down the microcode maturity level
// used by the IDA frontend. Later steps add the inference actions, the report and the write-back.
//
// The plugin uses the classic (init/term/run) entry points rather than PLUGIN_MULTI on purpose:
// process_ui_action() does not dispatch in `-A` batch mode, so the automated tests drive
// everything through ida_idaapi.load_and_run_plugin("trexida", arg) -> run(arg). The registered
// actions call the same run() bodies, so GUI and headless behaviour cannot drift apart.

// C++/STL headers FIRST: the IDA SDK shadows C library names (fopen/fread/fwrite/snprintf/...) to
// push plugins towards its own wrappers, and the MSVC STL headers use those names internally.
#include <array>
#include <chrono>
#include <cstdlib>
#include <map>
#include <fstream>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>
#include <algorithm>

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <funcs.hpp>
#include <ua.hpp>
#include <xref.hpp>
#include <hexrays.hpp>

#include "trex/version.hpp"
#include "ida_lift_config.hpp"
#include "ida_lift.hpp"
#include "trex_window.hpp"

#include "ida_types.hpp"
#include "type_plan.hpp"


// The inference core (structural + aggregate analysis + output) is gated while it is being
// ported; the IDA frontend and its diagnostics work without it.
#ifndef TREX_HAVE_INFERENCE
#define TREX_HAVE_INFERENCE 1
#endif

#if TREX_HAVE_INFERENCE
#include "trex/pipeline.hpp"
#include "trex/c_type_printer.hpp"
#include "analysis/interproc.hpp"
#endif

/// Single entry point shared by the plugin menu, the registered actions and IDAPython.
bool idaapi trexida_run(size_t arg);

namespace {

// run() argument values (also used by ida_idaapi.load_and_run_plugin).
enum run_arg_t
{
  ARG_PROBE = 0,
  ARG_INFER_CURRENT = 1,
  ARG_INFER_ALL = 2,
  ARG_SHOW = 3,
  ARG_APPLY = 4,
  ARG_EXPORT = 5,
  ARG_LIFT = 6,
  ARG_INTERPROC = 7,
  ARG_INFER_CURRENT_DEEP = 8,
  ARG_TYPES_WINDOW = 9,
};
/// Inter-procedural type propagation: joins the types of variables linked by a direct call with
/// those of the callee's parameters/returned value, aggregating across call sites (upstream paper,
/// §3.3 footnote 9). On by default; `TREXIDA_INTERPROC=0` or the toggle action turns it off.
bool g_interproc = true;

bool interproc_enabled_by_env()
{
  qstring value;
  if ( qgetenv("TREXIDA_INTERPROC", &value) && !value.empty() )
    return value != "0";
  return true;
}

/// vd_printer_t that forwards microcode text to IDA's message window.
/// \param budget  maximum number of characters to emit (0 = unlimited)
struct msg_printer_t : public vd_printer_t
{
  size_t budget;
  size_t written;
  bool truncated;

  explicit msg_printer_t(size_t b = 0) : budget(b), written(0), truncated(false) {}

  int idaapi print(int indent, const char *format, ...) override
  {
    va_list va;
    va_start(va, format);
    qstring s;
    s.vsprnt(format, va);
    va_end(va);

    qstring pad;
    if ( indent > 0 )
      pad.fill(' ', (size_t)indent);

    size_t total = pad.length() + s.length();
    if ( budget != 0 && written + total > budget )
    {
      if ( !truncated )
      {
        msg("[trexida] ...probe output truncated...\n");
        truncated = true;
      }
      written += total;
      return (int)total;
    }
    written += total;
    msg("%s%s", pad.c_str(), s.c_str());
    return (int)total;
  }
};

/// Does the code reference at `ea` name a function outside `fn` that the call-graph walk should
/// descend into?
///
/// A `call` targets the callee's entry, and so does a *tail call* -- a `jmp` to another function's
/// entry, which is how a compiler ends a function and how the CRT hands control to the next stage
/// (`start` tail-jumps to `__scrt_common_main_seh`, which is in turn how `main` is reached). An
/// `is_call_insn` test misses every tail call and truncates the walk to the root's direct calls.
///
/// The reference itself is a better discriminator than the mnemonic: a callee's entry resolves to a
/// function that *starts* there and is not `fn`, whereas a loop back-edge or a switch case resolves
/// to an interior address of `fn` and is rejected. That also keeps the walk working on IDPs whose
/// mnemonics we would otherwise have to enumerate.
bool transfers_to_other_function(ea_t ea, const func_t *fn)
{
  for ( ea_t ref = get_first_fcref_from(ea); ref != BADADDR; ref = get_next_fcref_from(ea, ref) )
  {
    const func_t *callee = get_func(ref);
    if ( callee != nullptr && callee->start_ea == ref && callee->start_ea != fn->start_ea )
      return true;
  }
  return false;
}

/// The function the user is working on: $TREXIDA_PROBE_EA if set, else the function under the
/// cursor, else -- when there is no cursor -- the entry point, else the first function.
func_t *current_function()
{
  func_t *target = nullptr;

  qstring ea_env;
  if ( qgetenv("TREXIDA_PROBE_EA", &ea_env) && !ea_env.empty() )
    target = get_func((ea_t)strtoull(ea_env.c_str(), nullptr, 0));

  if ( target == nullptr )
    target = get_func(get_screen_ea());

  // Headless IDA (`idat -A`) has no cursor, so get_screen_ea() is BADADDR and the lookup above
  // finds nothing. Falling back to "the first function in the database" picks whatever the IDP
  // happened to create first -- typically a CRT leaf with no callees -- which makes a call-tree
  // walk report a one-function tree. The entry point is the root every program's call graph
  // hangs from, so prefer it and keep the positional scan only as a last resort.
  if ( target == nullptr )
    target = get_func(inf_get_start_ea());

  if ( target == nullptr )
  {
    for ( size_t i = 0, n = get_func_qty(); i < n; ++i )
    {
      func_t *f = getn_func(i);
      if ( f != nullptr && f->size() > 0 )
      {
        target = f;
        break;
      }
    }
  }
  return target;
}

void print_lvars(const mba_t *mba, int max_count)
{
  int total = (int)mba->vars.size();
  msg("[trexida] lvars: %d total, showing %d\n", total, max_count < total ? max_count : total);
  for ( int i = 0; i < total && i < max_count; ++i )
  {
    const lvar_t &v = mba->vars[i];
    qstring loc;
    if ( v.is_stk_var() )
    {
      loc.sprnt("stack+%lld", (long long)v.get_stkoff());
    }
    else if ( v.is_reg_var() )
    {
      qstring rname;
      get_mreg_name(&rname, v.get_reg1(), v.width);
      loc.sprnt("reg %s (preg %d)", rname.c_str(), mreg2reg(v.get_reg1(), v.width));
    }
    else
    {
      loc = "other";
    }

    msg("[trexida]   %-20s w=%d arg=%d res=%d stk=%d loc=%-24s type=%s\n",
        v.name.c_str(),
        v.width,
        (int)v.is_arg_var(),
        (int)v.is_result_var(),
        (int)v.is_stk_var(),
        loc.c_str(),
        dstr(&v.tif));
  }
}

void run_probe()
{
  msg("[trexida] probe (v%s)\n", trex::version());

  const char *hxver = get_hexrays_version();
  msg("[trexida] decompiler: %s\n", hxver != nullptr ? hxver : "<unavailable>");

  func_t *pfn = current_function();
  if ( pfn == nullptr )
  {
    msg("[trexida] no function available to probe\n");
    return;
  }

  qstring fname;
  get_func_name(&fname, pfn->start_ea);
  msg("[trexida] target %s @ %a (%a bytes)\n", fname.c_str(), pfn->start_ea, (ea_t)pfn->size());
  msg("[trexida] configured IDA_LIFT_MATURITY = %d\n", (int)trex::IDA_LIFT_MATURITY);

  static const struct
  {
    const char *name;
    mba_maturity_t level;
  } candidates[] = {
    { "MMAT_GLBOPT3", MMAT_GLBOPT3 },
    { "MMAT_LVARS", MMAT_LVARS },
  };

  for ( const auto &c : candidates )
  {
    hexrays_failure_t hf;
    mba_t *mba = gen_microcode(mba_ranges_t(pfn), &hf, nullptr, DECOMP_WARNINGS, c.level);
    if ( mba == nullptr )
    {
      msg("[trexida] reqmat=%-12s -> FAILED: %s (at %a)\n", c.name, hf.desc().c_str(), hf.errea);
      continue;
    }

    msg("[trexida] reqmat=%-12s -> maturity=%d qty=%d lvars=%d\n",
        c.name,
        (int)mba->maturity,
        mba->qty,
        (int)mba->vars.size());
    print_lvars(mba, 8);

    msg_printer_t vp(20000);
    mba->print(vp);

    delete mba;
  }
  msg("[trexida] probe done\n");
}

/// The functions in scope for a "current function" run: the cursor's function, else the first
/// function in the database (batch mode has no meaningful cursor). Its direct callees are included
/// so that inter-procedural propagation has parameters to bind this function's arguments against.
std::vector<func_t *> current_scope_functions()
{
  std::vector<func_t *> out;
  func_t *pfn = current_function();
  if ( pfn != nullptr )
    out.push_back(pfn);

  // Direct callees, walked from the function's instructions (an instruction-level code reference to
  // a function start). Bounded so a menu run stays as short as it was: the decompiler cost is per
  // function, and these are the functions a call from here can propagate through.
  const size_t kMaxScopeFunctions = 32;
  std::set<ea_t> seen;
  for ( func_t *f : out )
    seen.insert(f->start_ea);
  for ( size_t i = 0; i < out.size() && out.size() < kMaxScopeFunctions; ++i )
  {
    func_item_iterator_t it(out[i]);
    for ( bool ok = it.first(); ok && out.size() < kMaxScopeFunctions; ok = it.next_head() )
    {
      if ( !transfers_to_other_function(it.current(), out[i]) )
        continue;
      for ( ea_t ref = get_first_fcref_from(it.current()); ref != BADADDR;
            ref = get_next_fcref_from(it.current(), ref) )
      {
        func_t *callee = get_func(ref);
        if ( callee != nullptr && callee->size() > 0 && seen.insert(callee->start_ea).second )
          out.push_back(callee);
      }
    }
  }
  return out;
}

/// Root function + the transitive closure of its direct callees (BFS over instruction-level code
/// refs, the same func_item_iterator_t/fcref walk current_scope_functions() uses, but not limited
/// to depth 1). Capped: a deep scan of a huge call tree must not decompile the world.
std::vector<func_t *> deep_scope_functions(func_t *root)
{
  std::vector<func_t *> out;
  if ( root == nullptr || root->size() == 0 )
    return out;
  out.push_back(root);

  const size_t kMaxDeepScopeFunctions = 256;
  std::set<ea_t> seen;
  seen.insert(root->start_ea);

  // Cap enforced before each push_back so one high-fan-out function cannot blow past the limit;
  // once hit, we stop walking the current function's references and break out of the BFS.
  bool capped = false;
  for ( size_t i = 0; i < out.size() && !capped; ++i )
  {
    func_item_iterator_t it(out[i]);
    for ( bool ok = it.first(); ok; ok = it.next_head() )
    {
      if ( !transfers_to_other_function(it.current(), out[i]) )
        continue;
      for ( ea_t ref = get_first_fcref_from(it.current()); ref != BADADDR;
            ref = get_next_fcref_from(it.current(), ref) )
      {
        if (out.size() >= kMaxDeepScopeFunctions)
        {
          msg("[trexida] deep scan: call tree capped at %zu functions\n", kMaxDeepScopeFunctions);
          capped = true;
          break;
        }
        func_t *callee = get_func(ref);
        if ( callee != nullptr && callee->size() > 0 && seen.insert(callee->start_ea).second )
          out.push_back(callee);
      }
      if (capped)
        break;
    }
  }

  std::sort(out.begin(), out.end(), [](func_t *a, func_t *b) { return a->start_ea < b->start_ea; });

  qstring fname;
  get_func_name(&fname, root->start_ea);
  msg("[trexida] deep scan: root %s, %d function(s) in the call tree\n",
      fname.c_str(), (int)out.size());
  return out;
}


std::vector<func_t *> all_scope_functions()
{
  std::vector<func_t *> out;
  for ( size_t i = 0, n = get_func_qty(); i < n; ++i )
  {
    func_t *f = getn_func(i);
    if ( f != nullptr && f->size() > 0 )
      out.push_back(f);
  }
  return out;
}

/// Lift the given functions and print the IL plus the variable/base-type report. Also validates
/// every emitted instruction with the ported `try_confirm_valid`.
void run_lift(const std::vector<func_t *> &functions, bool print_il)
{
  if ( functions.empty() )
  {
    msg("[trexida] no function in scope\n");
    return;
  }

  trex::ida::IdaLiftOptions options;
  options.functions = functions;
  options.maturity = trex::IDA_LIFT_MATURITY;

  trex::ida::IdaLiftResult res = trex::ida::lift_microcode(options);

  // Golden-file support: $TREXIDA_OUTPUT_DIR makes this action write its dump to files.
  qstring out_dir;
  const bool to_files = qgetenv("TREXIDA_OUTPUT_DIR", &out_dir) && !out_dir.empty();
  std::string dump;
  std::string summary;
  {
    char line[512];
    qsnprintf(line,
              sizeof(line),
              "lifted %d function(s), %d failed, %d instruction(s), %d fallback(s), "
              "%d invalid\n",
              res.functions_lifted,
              res.functions_failed,
              (int)res.program->instructions.size(),
              res.fallback_instructions,
              0);
    summary += line;
    for ( const auto &kv : res.fallback_histogram )
    {
      qsnprintf(line, sizeof(line), "fallback: %s x%d\n", kv.first.c_str(), kv.second);
      summary += line;
    }
    for ( const trex::ida::VariableRow &r : res.report )
    {
      qsnprintf(line,
                sizeof(line),
                "var %s %s w=%d ida=%s il=%s\n",
                r.lvar_name.c_str(),
                r.kind.c_str(),
                r.width,
                r.ida_type.c_str(),
                r.il_variable.debug_string().c_str());
      summary += line;
    }
    for ( const trex::Instruction &ins : res.program->instructions )
    {
      dump += ins.debug_string();
      dump += "\n";
    }
  }

  if ( to_files )
  {
    std::string base = out_dir.c_str();
    if ( !base.empty() && base.back() != '/' && base.back() != '\\' )
      base += "/";
    std::string stem = "lift";
    if ( !functions.empty() )
    {
      char buf[32];
      qsnprintf(buf, sizeof(buf), "%llX", (unsigned long long)functions[0]->start_ea);
      stem = buf;
    }
    std::ofstream f1(base + "trex_lift_" + stem + ".il", std::ios::binary);
    f1 << dump;
    std::ofstream f2(base + "trex_lift_" + stem + ".summary", std::ios::binary);
    f2 << summary;
  }

  msg("[trexida] lifted %d function(s), %d failed, %d instruction(s), %d fallback(s)\n",
      res.functions_lifted,
      res.functions_failed,
      (int)res.program->instructions.size(),
      res.fallback_instructions);
  for ( const auto &kv : res.fallback_histogram )
    msg("[trexida]   fallback: %s x%d\n", kv.first.c_str(), kv.second);
  msg("[trexida] variables: %d external entries, %d report rows\n",
      (int)res.variables.varmap.size(),
      (int)res.report.size());

  // Validate every instruction with the ported IL validator.
  int invalid = 0;
  for ( const trex::Instruction &ins : res.program->instructions )
  {
    std::optional<std::string> err = ins.try_confirm_valid();
    if ( err.has_value() )
    {
      if ( invalid < 10 )
        msg("[trexida] INVALID IL: %s\n", err->c_str());
      ++invalid;
    }
  }
  msg("[trexida] IL validation: %d invalid instruction(s)\n", invalid);

  // Variable/base-type report.
  const size_t row_limit = 40;
  for ( size_t i = 0; i < res.report.size() && i < row_limit; ++i )
  {
    const trex::ida::VariableRow &r = res.report[i];
    msg("[trexida]   var %-16s %-6s w=%d ida=%-14s il=%s\n",
        r.lvar_name.c_str(),
        r.kind.c_str(),
        r.width,
        r.ida_type.c_str(),
        r.il_variable.debug_string().c_str());
  }
  if ( res.report.size() > row_limit )
    msg("[trexida]   ... %d more rows\n", (int)(res.report.size() - row_limit));

  if ( print_il )
  {
    const size_t limit = 400;
    const std::vector<trex::Instruction> &insns = res.program->instructions;
    for ( size_t i = 0; i < insns.size() && i < limit; ++i )
      msg("[trexida] il %4d: %s\n", (int)i, insns[i].debug_string().c_str());
    if ( insns.size() > limit )
      msg("[trexida] ... %d more IL instructions\n", (int)(insns.size() - limit));
  }
}

//--------------------------------------------------------------------------
// S9: inference, report and export
//--------------------------------------------------------------------------
#if TREX_HAVE_INFERENCE

/// Everything the last run produced, kept for the show/export/apply actions.
struct LastRun
{
  bool valid = false;
  std::string structural_text;
  std::string c_like_text;
  std::string report_tsv;
  std::vector<trex::ida::VariableRow> rows;  ///< per-variable widths and IDA base types

  std::optional<trex::SerializableStructuralTypes<trex::ExternalVariable>> types;
  std::shared_ptr<const trex::StructuralTypes> structured_types;
  int functions_lifted = 0;
  int functions_failed = 0;
  int fallbacks = 0;
};

LastRun &last_run()
{
  static LastRun run;
  return run;
}

/// Build a `trex::ui::WindowModel` from the last inference. Aggregates come from the same plan
/// `run_apply()` installs, so the window and the database can never disagree about an offset or a
/// member's width. The variable-uses list joins each variable's type name with the function/ea it
/// lives in (same shape `run_apply()` parses).
trex::ui::WindowModel build_window_model(const LastRun &run)
{
  trex::ui::WindowModel m;
  if ( !run.valid || !run.types.has_value() )
    return m;

  trex::PrintableCTypes<trex::ExternalVariable> printer(*run.types);
  const size_t pointer_size = run.structured_types && run.structured_types->ssa
                                ? run.structured_types->ssa->program->pointer_size
                                : 8;
  const trexida::plan::TypePlan plan = trexida::plan::build_plan(*run.types, printer, pointer_size);

  for ( const trexida::plan::PlannedAggregate &a : plan.aggregates )
  {
    trex::ui::StructInfo si;
    si.kind = a.is_union ? "union" : "struct";
    si.name = a.name;
    for ( const trexida::plan::PlannedMember &pm : a.members )
    {
      trex::ui::MemberRow row;
      row.type = pm.type_spelling;
      row.name = pm.name;
      row.offset = pm.offset;
      row.extent = pm.extent;
      row.is_gap = pm.is_gap;
      si.members.push_back(std::move(row));
    }
    si.member_count = si.members.size();
    if ( a.size_known )
      si.size = a.size;
    m.structs.push_back(std::move(si));
  }

  for ( const trexida::plan::PlannedVariable &pv : plan.variable_types )
  {
    trex::ui::VarUse vu;
    vu.type_name = pv.spelling;

    const std::string &var_name = pv.name;
    size_t at1 = var_name.find('@');
    if ( at1 == std::string::npos )
      continue;
    size_t at2 = var_name.find('@', at1 + 1);
    if ( at2 == std::string::npos )
      continue;
    vu.lvar = var_name.substr(0, at1);
    vu.func = var_name.substr(at1 + 1, at2 - at1 - 1);
    vu.ea_hex = var_name.substr(at2 + 1);
    m.uses.push_back(std::move(vu));
  }
  return m;
}

std::string hex8(ea_t ea)
{
  char buf[32];
  qsnprintf(buf, sizeof(buf), "%08llx", (unsigned long long)ea);
  return buf;
}

void ida_log_sink(trex::log::Level lvl, const std::string &message, const std::vector<trex::log::KV> &kv)
{
  static const char *names[] = { "TRACE", "DEBUG", "INFO", "WARN", "ERROR" };
  int idx = (int)lvl;
  if ( idx < 0 || idx > 4 )
    idx = 4;
  std::string line;
  for ( const trex::log::KV &k : kv )
  {
    line += " ";
    line += k.key;
    line += "=";
    line += k.value;
  }
  msg("[trex/%s] %s%s\n", names[idx], message.c_str(), line.c_str());
}

/// The variable/type report: IDA's variable and base type next to the inferred type.
std::string build_report_tsv(const std::vector<trex::ida::VariableRow> &rows,
                            const std::optional<trex::SerializableStructuralTypes<trex::ExternalVariable>> &types)
{
  std::string out = "func_ea\tfunc\tvariable\tkind\twidth\tida_base_type\tinferred_type\n";

  // Construct the printer once: building it per row would make this quadratic in the number of
  // types (the IDA frontend can produce thousands of both).
  std::optional<trex::PrintableCTypes<trex::ExternalVariable>> printer;
  if ( types.has_value() )
    printer.emplace(*types);

  for ( const trex::ida::VariableRow &row : rows )
  {
    std::string key = row.lvar_name + "@" + row.func_name + "@" + hex8(row.func_ea);
    std::string inferred = "-";
    if ( types.has_value() )
    {
      std::optional<trex::Index> idx = types->index_of_type_for(trex::ExternalVariable(key));
      if ( idx.has_value() && printer.has_value() )
      {
        // Report the *printed* type name (the same string the C-like output uses), not the
        // internal container index name.
        inferred = printer->ext_type_name_at(*idx);
      }
    }

    char ea_buf[32];
    qsnprintf(ea_buf, sizeof(ea_buf), "%llX", (unsigned long long)row.func_ea);
    out += ea_buf;
    out += "\t" + row.func_name;
    out += "\t" + row.lvar_name;
    out += "\t" + row.kind;
    out += "\t" + std::to_string(row.width);
    out += "\t" + row.ida_type;
    out += "\t" + inferred;
    out += "\n";
  }
  return out;
}

/// Directory that receives exported files: `$TREXIDA_OUTPUT_DIR` when set (headless runs), else
/// the directory holding the database.
std::string export_directory()
{
  qstring dir;
  if ( qgetenv("TREXIDA_OUTPUT_DIR", &dir) && !dir.empty() )
  {
    std::string d = dir.c_str();
    for ( char &c : d )
    {
      if ( c == '\\' )
        c = '/';
    }
    while ( d.size() > 1 && d.back() == '/' )
      d.pop_back();
    return d;
  }

  const char *idb = get_path(PATH_TYPE_IDB);
  std::string base = idb != nullptr ? idb : "trex";
  for ( char &c : base )
  {
    if ( c == '\\' )
      c = '/';
  }
  size_t slash = base.find_last_of('/');
  return slash == std::string::npos ? std::string(".") : base.substr(0, slash);
}

/// Base path for the exported files: "<dir>/<database name without extension>".
std::string export_base_path()
{
  const char *idb = get_path(PATH_TYPE_IDB);
  std::string name = idb != nullptr ? idb : "trex";
  for ( char &c : name )
  {
    if ( c == '\\' )
      c = '/';
  }
  size_t slash = name.find_last_of('/');
  name = slash == std::string::npos ? name : name.substr(slash + 1);
  size_t dot = name.find_last_of('.');
  if ( dot != std::string::npos && dot != 0 )
    name = name.substr(0, dot);

  return export_directory() + "/" + name;
}

void write_text_file(const std::string &path, const std::string &text)
{
  std::ofstream f(path, std::ios::binary);
  if ( !f )
  {
    warning("TRex: could not write %s", path.c_str());
    return;
  }
  f.write(text.data(), (std::streamsize)text.size());
  msg("[trexida] wrote %s\n", path.c_str());
}

void export_run(const LastRun &run)
{
  std::string base = export_base_path();
  write_text_file(base + ".trex.structural", run.structural_text);
  write_text_file(base + ".trex.c", run.c_like_text);
  write_text_file(base + ".trex.vars.tsv", run.report_tsv);
}

void run_inference(const std::vector<func_t *> &functions)
{
  if ( functions.empty() )
  {
    msg("[trexida] no function in scope\n");
    return;
  }

  qstring out_dir;
  const bool headless = qgetenv("TREXIDA_OUTPUT_DIR", &out_dir) && !out_dir.empty();
  const bool gui = !headless && is_idaq();

  // Cheap pre-flight so a long run is never a surprise: function count and code size come from
  // the database without decompiling anything.
  uint64_t code_bytes = 0;
  for ( func_t *pfn : functions )
    code_bytes += pfn->end_ea - pfn->start_ea;
  msg("[trexida] scope: %d function(s), %llu bytes of code\n",
      (int)functions.size(), (unsigned long long)code_bytes);

  if ( gui )
    show_wait_box("TRex: lifting %d function(s), %llu bytes of code...\n(press Cancel to abort)",
                  (int)functions.size(), (unsigned long long)code_bytes);

  trex::log::set_sink(&ida_log_sink);

  trex::ida::IdaLiftOptions options;
  options.functions = functions;
  options.maturity = trex::IDA_LIFT_MATURITY;

  // Progress/cancel: the wait box is repainted between functions and IDA's Cancel button is
  // honoured. Batch runs get a line every couple of seconds so a long log is not silent.
  auto last_report = std::chrono::steady_clock::now();
  options.progress = [&](size_t done, size_t total, const char *func_name) -> bool
  {
    const auto now = std::chrono::steady_clock::now();
    const bool periodic = std::chrono::duration<double>(now - last_report).count() >= 2.0;
    if ( gui )
    {
      replace_wait_box("TRex: lifting %d/%d function(s)...\n%s", (int)done, (int)total, func_name);
      if ( user_cancelled() )
      {
        msg("[trexida] lift cancelled by the user after %d function(s)\n", (int)done);
        return false;
      }
    }
    else if ( periodic )
    {
      msg("[trexida] lifting %d/%d (%s)\n", (int)done, (int)total, func_name);
    }
    if ( periodic )
      last_report = now;
    return true;
  };

  const auto t_start = std::chrono::steady_clock::now();
  trex::ida::IdaLiftResult lifted = trex::ida::lift_microcode(options);
  const double lift_total = std::chrono::duration<double>(
    std::chrono::steady_clock::now() - t_start).count();
  msg("[trexida] lifted %d/%d function(s) in %.1fs (microcode %.1fs + frontend %.1fs; "
      "%d instruction(s), %d fallback(s))\n",
      lifted.functions_lifted,
      lifted.functions_lifted + lifted.functions_failed,
      lift_total,
      lifted.microcode_seconds,
      lifted.lifting_seconds,
      (int)lifted.program->instructions.size(),
      lifted.fallback_instructions);

  if ( lifted.cancelled )
  {
    trex::log::reset_sink();
    if ( gui )
      hide_wait_box();
    warning("TRex: cancelled; nothing was inferred");
    return;
  }

  if ( gui )
    replace_wait_box("TRex: inferring types (%d function(s), %d instructions)...\n"
                     "This phase cannot be interrupted.",
                     lifted.functions_lifted,
                     (int)lifted.program->instructions.size());

  std::optional<trex::ILVariableMap> vars = lifted.variables;
  const auto t_infer = std::chrono::steady_clock::now();

  // Inter-procedural propagation (analysis/interproc.hpp): resolve each call site's callee address
  // to the function index the SSA uses, then let the module join the linked variables' types.
  trex::interproc::Stats ip_stats;
  bool ip_ran = false;
  std::vector<trex::interproc::CallSite> sites = lifted.calls;
  for ( trex::interproc::CallSite &s : sites )
  {
    if ( s.callee_ea == trex::interproc::kNoAddress )
      continue;
    std::map<ea_t, size_t>::const_iterator it = lifted.function_index.find((ea_t)s.callee_ea);
    if ( it != lifted.function_index.end() )
      s.callee_func = it->second;
  }

  const bool ip_enabled = g_interproc && !sites.empty();
  trex::TrexPipelineResult res;
  if ( ip_enabled )
  {
    trex::interproc::InterprocResult ir = trex::interproc::run_trex_pipeline_interproc(
      lifted.program, vars, lifted.interfaces, sites, /*aggregate_sites=*/true, ip_stats);
    res = std::move(ir.pipeline);
    ip_ran = ir.propagated;
  }
  else
  {
    res = trex::run_trex_pipeline(lifted.program, vars);
  }

  msg("[trexida] inferred + serialized in %.1fs\n",
      std::chrono::duration<double>(std::chrono::steady_clock::now() - t_infer).count());

  if ( ip_enabled )
  {
    if ( ip_ran )
      msg("[trexida] inter-procedural: %d call site(s), %d argument binding(s), %d return "
          "binding(s), %d cross-site join(s) (%d unresolved callee, %d value(s) without a type)\n",
          (int)ip_stats.sites,
          (int)ip_stats.param_binds,
          (int)ip_stats.result_binds,
          (int)ip_stats.site_groups,
          (int)ip_stats.unresolved,
          (int)ip_stats.missing_values);
    else
      msg("[trexida] inter-procedural pass aborted (join invariant); types are per-function\n");
  }

  trex::log::reset_sink();

  LastRun &run = last_run();
  run.valid = true;
  run.structural_text = std::move(res.structural_text);
  run.c_like_text = std::move(res.c_like_text);
  run.structured_types = res.structured_types;
  run.types = std::move(res.types);
  run.report_tsv = build_report_tsv(lifted.report, run.types);
  run.rows = lifted.report;
  run.functions_lifted = lifted.functions_lifted;
  run.functions_failed = lifted.functions_failed;
  run.fallbacks = lifted.fallback_instructions;

  msg("[trexida] inferred types for %d function(s) (%d failed, %d lifted instruction(s), "
      "%d fallback(s), %d variables)\n",
      run.functions_lifted,
      run.functions_failed,
      (int)lifted.program->instructions.size(),
      run.fallbacks,
      (int)lifted.report.size());

  export_run(run);

  {
    // The lift returns one (reason, count) pair per function; aggregate before printing.
    std::map<std::string, int> histogram;
    for ( const auto &kv : lifted.fallback_histogram )
      histogram[kv.first] += kv.second;
    for ( const auto &kv : histogram )
      msg("[trexida] fallback: %s x%d\n", kv.first.c_str(), kv.second);
  }

  if ( !headless )
    msg("%s\n", run.c_like_text.c_str());

  if ( !headless && is_idaq() )
    hide_wait_box();

  // Refresh the types window if it is open (or leave it untouched if it has not been shown).
  trex::ui::update_types_window(build_window_model(run));
}

/// Install the inferred types into the database: create them in the local type library and apply
/// them to the variables they were inferred for.
void run_apply()
{
  LastRun &run = last_run();
  if ( !run.valid || !run.types.has_value() )
  {
    warning("TRex: no inference has been run yet");
    return;
  }

  trex::PrintableCTypes<trex::ExternalVariable> printer(*run.types);
  const size_t pointer_size = run.structured_types && run.structured_types->ssa
                                ? run.structured_types->ssa->program->pointer_size
                                : 8;
  const trexida::plan::TypePlan plan = trexida::plan::build_plan(*run.types, printer, pointer_size);

  if ( plan.aggregates.empty() && plan.variable_types.empty() )
  {
    msg("[trexida] nothing to apply: the last run produced no type definitions\n");
    return;
  }

  const trexida::ida_types::EmitStats emitted
    = trexida::ida_types::emit_local_types(get_idati(), plan);
  msg("[trexida] local types: %d created, %d failed, %d gap member(s), %d member(s) dropped "
      "(unknown extent)\n",
      (int)emitted.created_types,
      (int)emitted.failed_types,
      (int)emitted.gap_members,
      (int)emitted.dropped_members + (int)emitted.normalized_alternatives);
  for ( const std::string &f : emitted.failures )
    msg("[trexida] type problem: %s\n", f.c_str());

  // Widths (and IDA's own type) per variable, from the report of the run being applied.
  std::map<std::pair<ea_t, std::string>, const trex::ida::VariableRow *> row_of;
  for ( const trex::ida::VariableRow &row : run.rows )
    row_of.emplace(std::make_pair(row.func_ea, row.lvar_name), &row);

  // Every variable the inference produced, in the order the planner lists them.
  int applied = 0;
  int skipped = 0;
  int no_type_info = 0;
  int unresolvable = 0;
  int unresolved = 0;
  int modify_failed = 0;
  int malformed_name = 0;
  int unknown_function = 0;
  std::vector<std::string> unresolved_examples;
  std::map<std::string, int> unresolvable_types;
  std::set<ea_t> touched_functions;

  for ( const trexida::plan::PlannedVariable &pv : plan.variable_types )
  {
    const std::string &var_name = pv.name;
    const std::string &type_str = pv.spelling;

    // TRex's placeholders for "no type information": an empty rounded type set prints as `void`,
    // and unconstrained fields/variables print as `undefined`/`undefinedN` or `padding`.
    //
    // They must not be applied: IDA has no `void` variable type, and `undefinedN` carries no
    // information beyond its width. Leaving the variable alone keeps IDA's own type for it, which
    // the report already shows in its `ida_base_type` column. Counted separately from real
    // failures. (The planner carries the decision so this loop and the planner cannot drift.)
    if ( !pv.has_type_info )
    {
      ++no_type_info;
      continue;
    }

    // `<lvar>@<func>@<entry-hex>` (the same shape the .vars frontend produces).
    size_t at1 = var_name.find('@');
    if ( at1 == std::string::npos )
    {
      ++skipped;
      ++malformed_name;
      continue;
    }
    size_t at2 = var_name.find('@', at1 + 1);
    if ( at2 == std::string::npos )
    {
      ++skipped;
      ++malformed_name;
      continue;
    }

    const std::string lvar_name = var_name.substr(0, at1);
    const std::string entry_hex = var_name.substr(at2 + 1);

    ea_t func_ea = (ea_t)strtoull(entry_hex.c_str(), nullptr, 16);
    func_t *pfn = get_func(func_ea);
    if ( pfn == nullptr )
    {
      ++skipped;
      ++unknown_function;
      continue;
    }

    // Turn the printed type ("t1*", "uint32_t", ...) into a tinfo_t straight from the plan. Types
    // the spelling alone cannot express for a variable (an array of unknown length, a width IDA
    // has no type for) become an array or byte blob of the variable's own width, so the variable
    // still gets a type instead of being skipped.
    tinfo_t tif;
    {
      auto row_it = row_of.find(std::make_pair(func_ea, lvar_name));
      const size_t width = row_it != row_of.end() ? (size_t)row_it->second->width : 0;
      if ( !trexida::ida_types::build_variable_type(get_idati(), plan, type_str, width, &tif) )
      {
        // Aggregate instead of printing one line per variable: on a whole database the same
        // untypable spelling can show up thousands of times.
        ++unresolvable_types[type_str];
        ++skipped;
        ++unresolvable;
        continue;
      }
    }

    // Prefer the locator recorded during the lift: IDA's auto-generated names (`_28`) do not
    // always resolve by name afterwards, which silently dropped most variables of a database.
    lvar_locator_t ll;
    bool have_locator = false;
    {
      auto row_it = row_of.find(std::make_pair(func_ea, lvar_name));
      if ( row_it != row_of.end() && row_it->second->ll.defea != BADADDR )
      {
        ll = row_it->second->ll;
        have_locator = true;
      }
    }
    if ( !have_locator && !locate_lvar(&ll, pfn->start_ea, lvar_name.c_str()) )
    {
      ++skipped;
      ++unresolved;
      if ( unresolved_examples.size() < 5 )
        unresolved_examples.push_back(lvar_name + "@" + hex8(pfn->start_ea));
      continue;
    }

    lvar_saved_info_t info;
    info.ll = ll;
    info.type = tif;
    info.size = tif.get_size();
    if ( modify_user_lvar_info(pfn->start_ea, MLI_TYPE, info) )
    {
      ++applied;
      touched_functions.insert(pfn->start_ea);
    }
    else
    {
      ++skipped;
      ++modify_failed;
    }
  }

  for ( ea_t ea : touched_functions )
    mark_cfunc_dirty(ea, false);

  msg("[trexida] applied inferred types: %d variable(s) updated, %d skipped, %d function(s) "
      "refreshed\n",
      applied,
      skipped,
      (int)touched_functions.size());
  if ( no_type_info != 0 )
    msg("[trexida] %d variable(s) carry no type information (`void`/`undefined`/`padding` in the "
        "report) and were left with IDA's own type\n",
        no_type_info);
  for ( const auto &kv : unresolvable_types )
    msg("[trexida] could not build a type for inferred `%s` (%d variable(s))\n", kv.first.c_str(),
        kv.second);
  if ( skipped != 0 )
    msg("[trexida] skipped %d variable(s): %d unresolvable type(s), %d no longer resolvable, "
        "%d rejected by IDA, %d malformed name, %d unknown function\n",
        skipped, unresolvable, unresolved, modify_failed, malformed_name, unknown_function);
  for ( const std::string &ex : unresolved_examples )
    msg("[trexida]   unresolved example: %s\n", ex.c_str());
}

void show_last_run()
{
  const LastRun &run = last_run();
  if ( !run.valid )
  {
    warning("TRex: no inference has been run yet");
    return;
  }
  msg("==== TRex variable / type report ====\n%s\n", run.report_tsv.c_str());
  msg("==== TRex C-like types ====\n%s\n", run.c_like_text.c_str());
  msg("==== TRex structural types ====\n%s\n", run.structural_text.c_str());
}

#endif // TREX_HAVE_INFERENCE


/// Modal chooser shown when the user picks the plugin's own "Edit/Plugins" entry. Lists every
/// `kTrexOps` row: action name + description, both columns wide enough for the tooltip text.

struct trex_action_handler_t : public action_handler_t
{
  size_t arg;

  explicit trex_action_handler_t(size_t a) : arg(a) {}

  int idaapi activate(action_activation_ctx_t * /*ctx*/) override
  {
    return trexida_run(arg) ? 1 : 0;
  }

  action_state_t idaapi update(action_update_ctx_t * /*ctx*/) override
  {
    return AST_ENABLE_ALWAYS;
  }
};

enum { NUM_ACTIONS = 10 };

/// The operations the plugin offers, in the order they are listed in the menu/chooser. Single
/// source of truth: `init()` registers one action per entry, and the modal chooser (shown when
/// the plugin's own "Edit/Plugins" entry is used) lists the very same entries.
struct trex_op_t
{
  const char *name;   ///< action name, e.g. "trexida:infer_all"
  const char *label;  ///< label of the corresponding menu action
  const char *brief;  ///< short name for the dialog's first column
  const char *tooltip;///< dialog's second column / action tooltip
  size_t arg;         ///< `run()` argument implementing the operation
};

const std::array<trex_op_t, NUM_ACTIONS> kTrexOps = { {
  { "trexida:infer_current", "TRex: reconstruct types (current function)",
    "Reconstruct types (current function)",
    "Run TRex type reconstruction on the function under the cursor", ARG_INFER_CURRENT },
  { "trexida:infer_current_deep", "TRex: reconstruct types (current function + call tree)",
    "Reconstruct types (function + call tree)",
    "Run TRex on the function under the cursor and every function it transitively calls, so types "
    "propagate through nested calls", ARG_INFER_CURRENT_DEEP },
  { "trexida:infer_all", "TRex: reconstruct types (all functions)",
    "Reconstruct types (all functions)",
    "Run TRex type reconstruction on every function in the database", ARG_INFER_ALL },
  { "trexida:apply", "TRex: apply inferred types to database",
    "Apply inferred types to database",
    "Create the inferred types in the local type library and apply them to variables", ARG_APPLY },
  { "trexida:show", "TRex: show last type reconstruction",
    "Show last type reconstruction",
    "Show the last reconstruction result (structural, C-like, variable report)", ARG_SHOW },
  { "trexida:export", "TRex: export last results to files",
    "Export last results to files",
    "Write the last results to <base>.trex.structural, .trex.c and .trex.vars.tsv", ARG_EXPORT },
  { "trexida:window", "TRex: open types window",
    "Open types window",
    "Qt window: list of reconstructed structs, their definition, the variables of each type, plus "
    "copy/apply/export", ARG_TYPES_WINDOW },
  { "trexida:interproc", "TRex: toggle inter-procedural propagation",
    "Toggle inter-procedural propagation",
    "Join types across call sites (callee parameters and returned values) or restore per-function "
    "inference", ARG_INTERPROC },
  { "trexida:lift", "TRex: dump IL (diagnostics)",
    "Dump IL of current function (diagnostics)",
    "Lift the current function to the TRex IL and print it", ARG_LIFT },
  { "trexida:probe", "TRex: probe microcode (diagnostics)",
    "Probe microcode (diagnostics)",
    "Print microcode maturity and lvar diagnostics for one function", ARG_PROBE },
} };

/// Modal chooser shown when the user picks the plugin's own "Edit/Plugins" entry. Lists every
/// `kTrexOps` row: action name + description, both columns wide enough for the tooltip text.
struct ops_chooser_t final : chooser_t
{
  static const int kOpsChooserWidths[2];
  static const char *const kOpsChooserHeader[2];

  ops_chooser_t()
    : chooser_t(CH_MODAL | CH_KEEP, 2, kOpsChooserWidths, kOpsChooserHeader, "TRex operations") {}

  size_t idaapi get_count() const override { return kTrexOps.size(); }
  void idaapi get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const override
  {
    (*cols)[0] = kTrexOps[n].brief;
    (*cols)[1] = kTrexOps[n].tooltip;
  }
};

const int ops_chooser_t::kOpsChooserWidths[2] = { 30, 64 };
const char *const ops_chooser_t::kOpsChooserHeader[2] = { "Operation", "Description" };



/// Name of the plugin's submenu (the id must be unique; the label is what the user sees).
const char *const kTrexMenuName = "trexida_submenu";
const char *const kTrexMenuLabel = "TRex";

trex_action_handler_t &handler_for(size_t arg);

trex_action_handler_t &handler_for(size_t arg)
{
  static trex_action_handler_t handlers[NUM_ACTIONS] = {
    trex_action_handler_t(ARG_PROBE),
    trex_action_handler_t(ARG_INFER_CURRENT),
    trex_action_handler_t(ARG_INFER_ALL),
    trex_action_handler_t(ARG_SHOW),
    trex_action_handler_t(ARG_APPLY),
    trex_action_handler_t(ARG_EXPORT),
    trex_action_handler_t(ARG_LIFT),
    trex_action_handler_t(ARG_INTERPROC),
    trex_action_handler_t(ARG_INFER_CURRENT_DEEP),
    trex_action_handler_t(ARG_TYPES_WINDOW),
  };
  return arg < NUM_ACTIONS ? handlers[arg] : handlers[ARG_PROBE];
}

/// The decompiler context menu: attach every operation under a "TRex" submenu of the pseudocode
/// view's popup, diagnostics one level deeper (HRDevHelper's finish-populating-widget-popup
/// pattern: attach_action_to_popup() from a UI event listener).
struct popup_listener_t : public event_listener_t
{
  ssize_t idaapi on_event(ssize_t code, va_list va) override
  {
    if ( code != ui_finish_populating_widget_popup )
      return 0;
    TWidget *widget = va_arg(va, TWidget *);
    TPopupMenu *popup = va_arg(va, TPopupMenu *);
    if ( get_widget_type(widget) != BWN_PSEUDOCODE )
      return 0;
    for ( const trex_op_t &op : kTrexOps )
    {
      const bool diagnostics = op.arg == ARG_LIFT || op.arg == ARG_PROBE;
      attach_action_to_popup(widget, popup, op.name, diagnostics ? "TRex/Diagnostics/" : "TRex/");
    }
    return 0;
  }
};

// One listener for the plugin's lifetime. owner = nullptr because this is a classic plugin_t
// (no plugmod_t), so the 3-argument free function is the only form available; without an owner
// the kernel leaves removal to us and term() unhooks it.
popup_listener_t g_popup_listener;

} // namespace
#if !TREX_HAVE_QT
// Qt-less builds (default in CI): the types window is not compiled. The stubs keep the menu /
// action wiring callable from `run(arg)` and let the headless arg-9 path print a graceful
// "not available" line instead of failing.
namespace trex::ui
{
bool qt_available() { return false; }
void show_types_window(const WindowModel & /*model*/, const WindowCallbacks & /*cbs*/)
{
  msg("[trexida] types window: not available in this build (built without Qt)\n");
}
void update_types_window(const WindowModel & /*model*/) {}
void release_types_window() {}
} // namespace trex::ui
#endif


bool idaapi trexida_run(size_t arg)
{
  try
  {
    switch ( arg )
    {
      case ARG_PROBE:
        run_probe();
        return true;
      case ARG_LIFT:

        run_lift(current_scope_functions(), true);
        return true;
#if TREX_HAVE_INFERENCE
      case ARG_INFER_CURRENT:
        run_inference(current_scope_functions());
        return true;
      case ARG_INFER_CURRENT_DEEP:
      {
        func_t *root = current_function();
        if ( root == nullptr )
        {
          msg("[trexida] no function in scope\n");
          return true;
        }
        run_inference(deep_scope_functions(root));
        return true;
      }
      case ARG_INFER_ALL:
        run_inference(all_scope_functions());
        return true;
      case ARG_SHOW:
        show_last_run();
        return true;
      case ARG_EXPORT:
        if ( !last_run().valid )
        {
          warning("TRex: no inference has been run yet");
          return false;
        }
        export_run(last_run());
        return true;
      case ARG_APPLY:
        run_apply();
        return true;
      case ARG_INTERPROC:
        g_interproc = !g_interproc;
        msg("[trexida] inter-procedural propagation: %s (takes effect on the next reconstruction)\n",
            g_interproc ? "on" : "off");
        return true;
      case ARG_TYPES_WINDOW:
      {
        if ( !trex::ui::qt_available() )
        {
          msg("[trexida] types window: not available in this build (built without Qt)\n");
          return true;
        }
        trex::ui::WindowModel model = build_window_model(last_run());
        trex::ui::WindowCallbacks cbs;
        cbs.rescan_current_deep = []() { trexida_run(ARG_INFER_CURRENT_DEEP); };
        cbs.rescan_all          = []() { trexida_run(ARG_INFER_ALL); };
        cbs.apply               = []() { trexida_run(ARG_APPLY); };
        cbs.export_files        = []() { trexida_run(ARG_EXPORT); };
        trex::ui::show_types_window(model, cbs);
        return true;
      }
#endif
      default:
        msg("[trexida] run(arg=%d) is not implemented yet\n", (int)arg);
        return false;
    }
  }
  catch ( const trex::InvariantError &e )
  {
    trex::log::reset_sink();
    msg("[trexida] FAILED: %s\n", e.what());
    warning("TRex failed: %s", e.what());
    return false;
  }
  catch ( const std::exception &e )
  {
    trex::log::reset_sink();
    msg("[trexida] FAILED: %s\n", e.what());
    warning("TRex failed: %s", e.what());
    return false;
  }
}

/// The decompiler handshake is `init_hexrays_plugin()` (a ::ui_broadcast carrying the compile-time
/// HEXRAYS_API_MAGIC), so a failure has two very different causes: the decompiler is not installed
/// at all, or the running IDA speaks a different magic than the SDK we were compiled against.
/// A bare "no decompiler" sends people hunting for a license that is actually fine, so ask IDA
/// whether a decompiler plugin is present before blaming the build.
static bool decompiler_available(qstring &diagnosis)
{
  if ( init_hexrays_plugin() )
    return true;

  // Decompiler plugins are named "hex<arch>" (hexx64, hexarm, ...) and ship with the decompiler,
  // not with IDA itself; without a license none of them load. get_plugins() is a linked list.
  bool any_decompiler = false;
  for ( const plugin_info_t *pi = get_plugins(); pi != nullptr; pi = pi->next )
  {
    const char *path = pi->path != nullptr ? pi->path : "";
    const char *base = strrchr(path, '\\');
    base = base != nullptr ? base + 1 : path;
    if ( strncmp(base, "hex", 3) == 0 )
    {
      any_decompiler = true;
      break;
    }
  }

  if ( !any_decompiler )
  {
    diagnosis = "no Hex-Rays decompiler plugin is installed (expected one of hexx64/hexarm/... "
                "in the plugins directory) and a license is required";
    return false;
  }

  // The decompiler is loaded and ours still failed: the magic must differ, i.e. this build does
  // not match the running IDA. Report both sides so the rebuild is a no-brainer.
  char kernel[64] = { 0 };
  get_kernel_version(kernel, sizeof(kernel));
  diagnosis.sprnt("IDA %s is running a decompiler, but this build speaks hexrays magic 0x%llX and "
                  "the installed one answers with a different magic -- the plugin must be rebuilt "
                  "against the ida-sdk tag matching IDA %s",
                  kernel, (unsigned long long)HEXRAYS_API_MAGIC, kernel);
  return false;
}

static plugmod_t *idaapi init()
{
  g_interproc = interproc_enabled_by_env();

  qstring diagnosis;
  if ( !decompiler_available(diagnosis) )
  {
    msg("[trexida] no decompiler available; plugin not loaded: %s\n", diagnosis.c_str());
    return PLUGIN_SKIP;
  }

  const bool menu_created = create_menu(kTrexMenuName, kTrexMenuLabel, "Edit/Plugins/");
  const char *menu_path = menu_created ? "Edit/Plugins/TRex/" : "Edit/Plugins/";
  if ( !menu_created )
    msg("[trexida] could not create the TRex submenu; attaching the operations to Edit/Plugins "
        "directly\n");

  int registered = 0;
  int attached = 0;
  for ( const trex_op_t &op : kTrexOps )
  {
    if ( register_action(ACTION_DESC_LITERAL(op.name,
                                             op.label,
                                             &handler_for(op.arg),
                                             nullptr,
                                             op.tooltip,
                                             -1)) )
    {
      ++registered;
      // One "TRex" submenu under Edit/Plugins that expands into the individual operations.
      // The submenu must exist before actions can be attached *into* it, hence `create_menu`
      // (SDK: "the new 'My menu' submenu will appear at the end of the 'Edit/Plugins'
      // submenu"). If it could not be created, fall back to plain items in Edit/Plugins so the
      // operations stay reachable.
      if ( attach_action_to_menu(menu_path, op.name, SETMENU_APP) )
        ++attached;
    }
    else
    {
      msg("[trexida] warning: could not register action %s\n", op.name);
    }
  }

  if ( registered > 0 )
    hook_event_listener(HT_UI, &g_popup_listener, nullptr);

  msg("[trexida] loaded v%s (built %s %s), decompiler %s (%d/%d actions registered, %d attached "
      "to %s)\n",
      trex::version(), __DATE__, __TIME__, get_hexrays_version(),
      registered, (int)kTrexOps.size(), attached, menu_path);
  return PLUGIN_KEEP;
}

static void idaapi term()
{
  unhook_event_listener(HT_UI, &g_popup_listener);
  trex::ui::release_types_window();
  delete_menu(kTrexMenuName);
  term_hexrays_plugin();
}

static bool idaapi run(size_t arg)
{
  // The plugin's own "Edit/Plugins" entry can only pass 0. Show the operation chooser so the
  // user gets every action (reconstruction, apply, copy, export, diagnostics) at the same
  // surface, not just one. Batch mode keeps the raw meaning of `run(0)` = probe, since no
  // dialog or menu is available there.
  if ( arg == ARG_PROBE && is_idaq() )
  {
    ops_chooser_t ch;
    ssize_t n = ch.choose();
    if ( n >= 0 && n < (ssize_t)kTrexOps.size() )
      return trexida_run(kTrexOps[n].arg);
    return true;
  }

  return trexida_run(arg);
}

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,  // version
  0,                      // flags
  init,                   // init
  term,                   // term
  run,                    // run
  "TRex type reconstruction (Hex-Rays microcode frontend)",
  "TRex: reconstruct C types from stripped binaries.\n"
  "C++ port of https://github.com/secure-foundations/trex, driven by IDA microcode.",
  "TRex Type Reconstruction",
  nullptr,                // hotkey
};
