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
#include <regex>
#include <fstream>
#include <memory>
#include <optional>
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

#include "decl_blocks.hpp"


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

/// The function to probe: $TREXIDA_PROBE_EA if set, else the cursor, else the first function.
func_t *probe_target()
{
  func_t *target = nullptr;

  qstring ea_env;
  if ( qgetenv("TREXIDA_PROBE_EA", &ea_env) && !ea_env.empty() )
    target = get_func((ea_t)strtoull(ea_env.c_str(), nullptr, 0));

  if ( target == nullptr )
    target = get_func(get_screen_ea());

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

  func_t *pfn = probe_target();
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
  func_t *pfn = get_func(get_screen_ea());
  if ( pfn == nullptr )
  {
    for ( size_t i = 0, n = get_func_qty(); i < n; ++i )
    {
      func_t *f = getn_func(i);
      if ( f != nullptr && f->size() > 0 )
      {
        pfn = f;
        break;
      }
    }
  }
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
      insn_t insn;
      const ea_t ea = it.current();
      if ( decode_insn(&insn, ea) <= 0 || !is_call_insn(insn) )
        continue;
      for ( ea_t ref = get_first_fcref_from(ea); ref != BADADDR; ref = get_next_fcref_from(ea, ref) )
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
      insn_t insn;
      const ea_t ea = it.current();
      if ( decode_insn(&insn, ea) <= 0 || !is_call_insn(insn) )
        continue;
      for ( ea_t ref = get_first_fcref_from(ea); ref != BADADDR; ref = get_next_fcref_from(ea, ref) )
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
std::string declarations_only(const std::string &c_like_text);

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

/// Build a `trex::ui::WindowModel` from the last inference. Aggregates are taken straight from
/// the printer's C-like text; the variable-uses list joins each variable's type name with the
/// function/ea it lives in (same shape `run_apply()` parses).
trex::ui::WindowModel build_window_model(const LastRun &run)
{
  trex::ui::WindowModel m;
  if ( !run.valid || !run.types.has_value() )
    return m;

  const std::string decls = declarations_only(run.c_like_text);
  std::vector<trex::decl::Block> blocks = trex::decl::parse_decl_blocks(decls);
  const std::map<std::string, std::size_t> sizes = trex::decl::compute_block_sizes(blocks);

  for ( const trex::decl::Block &b : blocks )
  {
    trex::ui::StructInfo si;
    si.kind = b.kind;
    si.name = b.name;
    si.declaration = trex::decl::block_text(b);
    auto it = sizes.find(b.name);
    if ( it != sizes.end() )
      si.size = it->second;
    si.member_count = b.members.size();
    m.structs.push_back(std::move(si));
  }

  trex::PrintableCTypes<trex::ExternalVariable> printer(*run.types);
  for ( const auto &entry : run.types->var_type_iter() )
  {
    const std::string &var_name = entry.first.name;
    trex::ui::VarUse vu;
    vu.type_name = printer.ext_type_name_at(entry.second);

    // var_name is `<lvar>@<func>@<ea-hex>` (the shape run_apply() parses).
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


/// Fixed-width typedefs the printer emits; IDA's local TIL is not guaranteed to have them.
const char *kTypePreamble =
  "typedef signed char int8_t;\n"
  "typedef unsigned char uint8_t;\n"
  "typedef short int16_t;\n"
  "typedef unsigned short uint16_t;\n"
  "typedef int int32_t;\n"
  "typedef unsigned int uint32_t;\n"
  "typedef long long int64_t;\n"
  "typedef unsigned long long uint64_t;\n"
  "typedef __int128 int128_t;\n"
  "typedef unsigned __int128 uint128_t;\n"
  // TRex's names for pieces of data it has no information about: `undefinedN` is an N-byte blob,
  // `padding` a byte of struct padding. IDA's C parser does not know them (Ghidra's names), so
  // without these aliases *every* aggregate containing one failed to parse — which silently
  // dropped all variables whose type was such an aggregate (observed: 20 failed declarations and
  // 3,966 skipped variables on a 507-function binary). Widths match `BuiltIn::UndefinedN`.
  // (`undefined` itself is a built-in IDA type and must not be redefined.)
  "typedef unsigned char undefined1;\n"
  "typedef unsigned short undefined2;\n"
  "typedef unsigned int undefined4;\n"
  "typedef unsigned long long undefined8;\n"
  "typedef unsigned char padding;\n";

/// Strip the `// var : type` comment lines the printer emits, leaving plain C declarations.
std::string declarations_only(const std::string &c_like_text)
{
  std::string out;
  size_t i = 0;
  while ( i < c_like_text.size() )
  {
    size_t j = c_like_text.find('\n', i);
    if ( j == std::string::npos )
      j = c_like_text.size();
    std::string line = c_like_text.substr(i, j - i);
    i = j + 1;

    size_t a = 0;
    while ( a < line.size() && (line[a] == ' ' || line[a] == '\t') )
      ++a;
    if ( a + 1 < line.size() && line[a] == '/' && line[a + 1] == '/' )
      continue; // comment line
    out += line;
    out += "\n";
  }
  return out;
}

/// Collects the messages `parse_decls` emits; they name the declaration that failed, which makes
/// a write-back failure on a real database actionable instead of only a count.
std::vector<std::string> &parse_messages()
{
  static std::vector<std::string> messages;
  return messages;
}

int trex_parse_printer(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  qstring s;
  s.vsprnt(format, va);
  va_end(va);
  if ( parse_messages().size() < 8 )
    parse_messages().push_back(s.c_str());
  return (int)s.length();
}

std::string width_suffix(size_t width)
{
  if ( width == 1 )
    return "";
  return "[" + std::to_string(width) + "]";
}


/// Everything the write-back needs to know about the printer's declaration text, in front of the
/// two places that consume it (`parse_decls` and the message window).
///
/// The printer emits *Ghidra-flavoured* C: aggregate members can be `void`, `T[]` (unsized arrays)
/// or a type name that is referenced but never defined, none of which IDA's parser accepts — each
/// such declaration made every variable of that aggregate untypable. Where the structural type
/// says how many bytes a member occupies, the member is replaced by an explicit padding blob
/// ("gap") of exactly that size, which keeps the aggregate's layout intact and lets it parse.
struct PreparedDeclarations
{
  std::string text;         ///< preamble + typedefs + repaired, dependency-ordered aggregates
  int normalized_members = 0;  ///< `T[]*` rewritten to `T*` (layout-preserving)
  int gap_members = 0;         ///< members replaced by an exact-size padding blob
  int dropped_members = 0;     ///< members dropped because even their size is unknown
  std::map<std::string, size_t> sizes;  ///< aggregate name -> size, as computed for the layout
};



/// Size of a printed type, when it is statically known from the text plus the aggregate sizes
/// computed so far. `char`/`unsigned char`/`undefinedN`/fixed-width typedefs and pointers cover
/// everything the printer emits for placeable fields.
std::optional<size_t> printed_type_size(const std::string &type,
                                        const std::map<std::string, size_t> &aggregate_sizes)
{
  static const std::map<std::string, size_t> scalars = {
    { "char", 1 },            { "signed char", 1 },     { "unsigned char", 1 },
    { "undefined", 1 },       { "undefined1", 1 },      { "padding", 1 },      { "int8_t", 1 },
    { "uint8_t", 1 },         { "short", 2 },           { "unsigned short", 2 },
    { "undefined2", 2 },      { "int16_t", 2 },         { "uint16_t", 2 },
    { "int", 4 },             { "unsigned int", 4 },    { "undefined4", 4 },
    { "int32_t", 4 },         { "uint32_t", 4 },        { "long", 4 },         { "unsigned long", 4 },
    { "long long", 8 },       { "unsigned long long", 8 }, { "undefined8", 8 },
    { "int64_t", 8 },         { "uint64_t", 8 },        { "__int64", 8 },
    { "int128_t", 16 },       { "uint128_t", 16 },      { "__int128", 16 },
  };

  if ( type.find('*') != std::string::npos )
    return 8;  // 64-bit database
  auto it = scalars.find(type);
  if ( it != scalars.end() )
    return it->second;
  auto ag = aggregate_sizes.find(type);
  if ( ag != aggregate_sizes.end() )
    return ag->second;
  return std::nullopt;
}

/// Can IDA's C parser accept this member type? False for `void`, for an unsized array used by
/// value, for a `tN` that is never defined and for types wider than the parser knows.
bool member_is_representable(const std::string &type, const std::set<std::string> &defined,
                             const std::map<std::string, size_t> &aggregate_sizes)
{
  if ( type == "void" || type.rfind("void", 0) == 0 )
    return type.find('*') != std::string::npos;  // `void*` is fine, `void`/`void[]` is not
  if ( type.find("[]") != std::string::npos && type.find('*') == std::string::npos )
    return false;  // unsized array by value
  if ( !printed_type_size(type, aggregate_sizes).has_value() )
    return false;
  if ( !defined.count(type) && type.size() > 1 && type[0] == 't' && isdigit((unsigned char)type[1]) )
    return false;  // a referenced-but-never-defined aggregate
  return true;
}

/// TRex prints types C cannot declare for a *variable*: an incomplete array (`char[]` has no
/// length), a pointer to one (`char[]*`), or a width IDA has no type for (`int256_t`). The
/// variable's width is known, so the type is rewritten into something IDA can store that still
/// describes the same number of bytes — an array of the element type when the width is divisible
/// by it, otherwise a byte blob (a "gap"). Returns std::nullopt when nothing can be salvaged.
/// `T[N] x;` — an array type needs the declarator *inside* the brackets (`T[N] x;` is invalid C),
/// which is how the probe declaration for an array-typed variable has to be built.
std::string declaration_for(const std::string &type, const char *name)
{
  const size_t bracket = type.rfind('[');
  if ( bracket != std::string::npos && !type.empty() && type.back() == ']' )
    return type.substr(0, bracket) + " " + name + type.substr(bracket);
  return type + " " + name;
}

std::string width_suffix(size_t width);

std::string representable_variable_type(const std::string &printed, size_t width,
                                       const std::map<std::string, size_t> &sizes)
{
  if ( printed.empty() || width == 0 )
    return std::string();

  const size_t brackets = printed.find("[]");
  if ( brackets == std::string::npos )
  {
    // A scalar IDA's parser does not know, e.g. `int256_t`.
    if ( printed_type_size(printed, sizes).has_value() )
      return printed;
    return "unsigned char" + width_suffix(width);
  }

  std::string base = printed.substr(0, brackets);
  while ( !base.empty() && base.back() == ' ' )
    base.pop_back();

  // `T[]*`: pointer to an array of T, i.e. an ordinary pointer.
  if ( printed.find('*', brackets) != std::string::npos )
    return base + "*";

  std::optional<size_t> elem = printed_type_size(base, sizes);
  if ( elem.has_value() && *elem != 0 && width % *elem == 0 )
    return base + "[" + std::to_string(width / *elem) + "]";
  return "unsigned char" + width_suffix(width);
}

/// Split the printer's text into aggregate blocks (everything else is kept verbatim), work out the
/// aggregates' sizes, then emit the blocks in dependency order with unrepresentable members
/// replaced by exact-size gaps.
PreparedDeclarations prepare_declarations(const std::string &decls,
                                          const trex::PrintableCTypes<trex::ExternalVariable> &printer,
                                          const trex::Container<trex::StructuralType> &types)
{
  PreparedDeclarations out;

  // Non-block lines (typedefs, the Ghidra-shaped scalar aliases, any preamble) are kept as
  // `leftover` and re-prepended verbatim before the emitted aggregates.
  std::string leftover;
  {
    const std::regex block_open("^(struct|union)[ \t]+(t[0-9]+)[ \t]*\\{[ \t]*\\r?$");
    std::string line;
    std::istringstream in(decls);
    while ( std::getline(in, line) )
    {
      if ( !std::regex_match(line, block_open) )
        leftover += line + "\n";
    }
  }

  std::vector<trex::decl::Block> blocks = trex::decl::parse_decl_blocks(decls);
  const std::map<std::string, std::size_t> sizes = trex::decl::compute_block_sizes(blocks);

  std::map<std::string, const trex::decl::Block *> block_of;
  std::set<std::string> defined;
  for ( const trex::decl::Block &b : blocks )
  {
    block_of.emplace(b.name, &b);
    defined.insert(b.name);
  }

  // ---- emit, in dependency order, replacing what IDA cannot represent
  std::set<std::string> emitted;
  std::function<void(const trex::decl::Block &)> emit_block = [&](const trex::decl::Block &b)
  {
    if ( !emitted.insert(b.name).second )
      return;

    // by-value members must be complete before this aggregate is parsed
    for ( const trex::decl::Member &dm : b.members )
    {
      if ( dm.type.find('*') == std::string::npos && block_of.count(dm.type) != 0 )
        emit_block(*block_of[dm.type]);
    }

    for ( const std::string &l : b.head )
      out.text += l + "\n";

    for ( size_t i = 0; i < b.members.size(); ++i )
    {
      const trex::decl::Member &dm = b.members[i];
      const std::string indent = dm.indent.empty() ? "  " : dm.indent;

      std::string type = dm.type;
      // `T[]*` is a pointer to an array: same width as `T*`, and layout-preserving.
      size_t brackets = type.find("[]");
      if ( brackets != std::string::npos && type.find('*', brackets) != std::string::npos )
      {
        std::string base = type.substr(0, brackets);
        std::string stars;
        for ( size_t k = brackets + 2; k < type.size(); ++k )
          if ( type[k] == '*' )
            stars.push_back('*');
        while ( !base.empty() && base.back() == ' ' )
          base.pop_back();
        type = base + stars;
        ++out.normalized_members;
      }

      // A pointer stays a pointer whatever it points at: when the pointee is a name IDA's parser
      // does not know (`code` is Ghidra's executable-code type, `int256_t` has no IDA equivalent,
      // a `tN` may never be defined), keep the width and use `void*`.
      size_t star = type.find('*');
      if ( star != std::string::npos )
      {
        std::string base = type.substr(0, star);
        while ( !base.empty() && base.back() == ' ' )
          base.pop_back();
        if ( !base.empty() && base != "void"
          && !printed_type_size(base, sizes).has_value() )
        {
          type = "void" + type.substr(star);
          ++out.normalized_members;
        }
      }

      if ( member_is_representable(type, defined, sizes) )
      {
        out.text += indent + type + " " + dm.name + ";\n";
        continue;
      }

      // Unrepresentable: keep its bytes as padding. The extent is the distance to the next
      // member (structs) or the whole aggregate (unions, whose members all start at offset 0).
      std::optional<size_t> extent;
      if ( b.kind == "union" )
      {
        auto total = sizes.find(b.name);
        if ( total != sizes.end() )
          extent = total->second;
      }
      else
      {
        for ( size_t j = i + 1; j < b.members.size(); ++j )
        {
          if ( b.members[j].offset > dm.offset )
          {
            extent = b.members[j].offset - dm.offset;
            break;
          }
        }
        if ( !extent.has_value() )
        {
          auto total = sizes.find(b.name);
          if ( total != sizes.end() && total->second > dm.offset )
            extent = total->second - dm.offset;
        }
      }

      if ( !extent.has_value() || *extent == 0 )
      {
        ++out.dropped_members;
        continue;
      }

      ++out.gap_members;
      if ( *extent == 1 )
        out.text += indent + "unsigned char gap_" + dm.name + ";\n";
      else
        out.text += indent + "unsigned char gap_" + dm.name + "[" + std::to_string(*extent)
                  + "];\n";
    }

    for ( const std::string &l : b.tail )
      out.text += l + "\n";
  };

  for ( const trex::decl::Block &b : blocks )
    emit_block(b);

  // typedefs for every aggregate, so bare `tN` references resolve
  std::string typedefs;
  for ( const trex::decl::Block &b : blocks )
    typedefs += "typedef " + b.kind + " " + b.name + " " + b.name + ";\n";

  out.text = kTypePreamble + std::string("\n") + typedefs + "\n" + leftover + out.text;
  out.sizes = sizes;
  return out;
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

  std::string decls = declarations_only(run.c_like_text);
  if ( decls.find('{') == std::string::npos && decls.find("*") == std::string::npos )
  {
    msg("[trexida] nothing to apply: the last run produced no type definitions\n");
    return;
  }

  trex::PrintableCTypes<trex::ExternalVariable> printer(*run.types);
  const PreparedDeclarations prepared = prepare_declarations(decls, printer, run.types->types());
  msg("[trexida] declarations: %d member(s) replaced by explicit padding, %d "
      "pointer-to-array member(s) normalized, %d member(s) dropped (unknown size)\n",
      prepared.gap_members, prepared.normalized_members, prepared.dropped_members);

  parse_messages().clear();
  int errors = parse_decls(get_idati(), prepared.text.c_str(), trex_parse_printer, 0);
  msg("[trexida] type declarations parsed with %d error(s)\n", errors);
  for ( const std::string &m : parse_messages() )
    msg("[trexida] declaration problem: %s\n", m.c_str());

  // Widths (and IDA's own type) per variable, from the report of the run being applied.
  std::map<std::pair<ea_t, std::string>, const trex::ida::VariableRow *> row_of;
  for ( const trex::ida::VariableRow &row : run.rows )
    row_of.emplace(std::make_pair(row.func_ea, row.lvar_name), &row);

  int applied = 0;
  int skipped = 0;
  int no_type_info = 0;
  int gaps = 0;
  int unparsable = 0;
  int unresolved = 0;
  int modify_failed = 0;
  int malformed_name = 0;
  int unknown_function = 0;
  int unknown_width = 0;
  std::vector<std::string> unresolved_examples;
  std::map<std::string, int> unparsable_types;
  std::set<ea_t> touched_functions;

  for ( const auto &entry : run.types->var_type_iter() )
  {
    const std::string &var_name = entry.first.name;
    std::string type_str = printer.ext_type_name_at(entry.second);

    // TRex's placeholders for "no type information": an empty rounded type set prints as `void`,
    // and unconstrained fields/variables print as `undefined`/`undefinedN` or `padding`.
    //
    // They must not be applied: IDA has no `void` variable type (`parse_decl` on `void x;` fails
    // and leaves a BADSIZE type), and `undefinedN` carries no information beyond its width.
    // Leaving the variable alone keeps IDA's own type for it, which the report already shows in
    // its `ida_base_type` column. Counted separately from real failures.
    if ( type_str.empty() || type_str == "void" || type_str.rfind("undefined", 0) == 0
         || type_str.rfind("padding", 0) == 0 )
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

    // Types C refuses to declare for a variable (an array of unknown length, a pointer to one, a
    // width IDA has no type for) become an array or byte blob of the same width, so the variable
    // still gets a type instead of being skipped.
    {
      auto row_it = row_of.find(std::make_pair(func_ea, lvar_name));
      const size_t width = row_it != row_of.end() ? (size_t)row_it->second->width : 0;
      const std::string rewritten = representable_variable_type(type_str, width, prepared.sizes);
      if ( rewritten.empty() )
      {
        ++skipped;
        ++unknown_width;
        continue;
      }
      if ( rewritten != type_str )
      {
        ++gaps;
        type_str = rewritten;
      }
    }

    // Turn the printed type ("t1*", "uint32_t", ...) into a tinfo_t by parsing a dummy variable
    // declaration of that type.
    tinfo_t tif;
    qstring dummy_name;
    const std::string probe = declaration_for(type_str, "trex_probe_var") + ";";
    if ( !parse_decl(&tif, &dummy_name, get_idati(), probe.c_str(), PT_VAR | PT_SIL) || tif.empty() )
    {
      // Aggregate instead of printing one line per variable: on a whole database the same
      // unparsable type can show up thousands of times.
      ++unparsable_types[type_str];
      ++skipped;
      ++unparsable;
      continue;
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
  for ( const auto &kv : unparsable_types )
    msg("[trexida] could not parse inferred type `%s` (%d variable(s))\n", kv.first.c_str(),
        kv.second);
  if ( skipped != 0 )
    msg("[trexida] skipped %d variable(s): %d unparsable type(s), %d no longer resolvable, "
        "%d rejected by IDA, %d malformed name, %d unknown function, %d without a usable width\n",
        skipped, unparsable, unresolved, modify_failed, malformed_name, unknown_function,
        unknown_width);
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
  { "trexida:lift", "TRex: dump IL (diagnostics)",
    "Dump IL of current function (diagnostics)",
    "Lift the current function to the TRex IL and print it", ARG_LIFT },
  { "trexida:probe", "TRex: probe microcode (diagnostics)",
    "Probe microcode (diagnostics)",
    "Print microcode maturity and lvar diagnostics for one function", ARG_PROBE },
  { "trexida:interproc", "TRex: toggle inter-procedural propagation",
    "Toggle inter-procedural propagation",
    "Join types across call sites (callee parameters and returned values) or restore per-function "
    "inference", ARG_INTERPROC },
  { "trexida:infer_current_deep", "TRex: reconstruct types (current function + call tree)",
    "Reconstruct types (function + call tree)",
    "Run TRex on the function under the cursor and every function it transitively calls, so types "
    "propagate through nested calls", ARG_INFER_CURRENT_DEEP },
  { "trexida:window", "TRex: open types window",
    "Open types window",
    "Qt window: list of reconstructed structs, their definition, the variables of each type, plus "
    "copy/apply/export", ARG_TYPES_WINDOW },
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
        func_t *root = probe_target();
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

static plugmod_t *idaapi init()
{
  g_interproc = interproc_enabled_by_env();

  if ( !init_hexrays_plugin() )
  {
    msg("[trexida] no decompiler available; plugin not loaded\n");
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

  msg("[trexida] loaded v%s (built %s %s), decompiler %s (%d/%d actions registered, %d attached "
      "to %s)\n",
      trex::version(), __DATE__, __TIME__, get_hexrays_version(),
      registered, (int)kTrexOps.size(), attached, menu_path);
  return PLUGIN_KEEP;
}

static void idaapi term()
{
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
