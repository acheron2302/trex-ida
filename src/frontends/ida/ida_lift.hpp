#pragma once

// IDA (Hex-Rays microcode) frontend for TRex.
//
// Lives in its own translation unit because the emitter state (basic-address grouping, temporary
// allocation, fallback statistics) is shared between operand, opcode and variable handling;
// splitting them would only expose that state as an interface.

#include <ida.hpp>
#include <funcs.hpp>
#include <hexrays.hpp>

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <analysis/interproc.hpp>
#include <trex/il.hpp>

namespace trex::ida {

/// Indexes into the address space table this frontend always builds (order is load-bearing:
/// `Program::create` derives the pointer size from the space named "ram").
enum space_index_t
{
  SPACE_REGISTER = 0,
  SPACE_RAM = 1,
  SPACE_STACK = 2,
  SPACE_UNIQUE = 3,
  NUM_SPACES = 4,
};

/// One row of the variable/base-type report: the IDA-assigned variable and base type for an IL
/// variable, alongside (after inference) the type TRex recovered for it.
struct VariableRow
{
  ea_t func_ea = BADADDR;
  std::string func_name;
  std::string lvar_name;
  /// "arg" | "result" | "local" | "stack"
  std::string kind;
  int width = 0;
  /// IDA's base type for this variable (`tinfo_t` printed), e.g. `_QWORD` or `int *`.
  std::string ida_type;
  /// IDA's own locator for this variable. Names like `_28` are decompiler-generated and are not
  /// always resolvable through `locate_lvar` later, so the write-back uses this when it is set.
  lvar_locator_t ll;
  /// The IL location this variable maps onto.
  Variable il_variable;
  /// Index into Program::functions.
  size_t func_index = 0;
  /// Filled in by the plugin after inference.
  std::string inferred_type;
};

struct IdaLiftOptions
{
  /// Functions to lift, in ascending `start_ea` order.
  std::vector<func_t *> functions;
  /// Also register direct call targets that are not in `functions` (so that the caller's
  /// unaffected/callee-saved sets are as precise as IDA allows).
  bool include_external_callees = true;
  /// Restrict the external-variable table to arguments and the result variable.
  bool variables_only_args = false;
  /// Microcode maturity to request (validated by the `trexida:probe` action).
  mba_maturity_t maturity = MMAT_LVARS;
  /// Called before each function is decompiled and mapped, with the progress so far. Returning
  /// false aborts the lift (used by the plugin to honour IDA's "Cancel" button and to keep the
  /// wait box alive); the partial result is then marked `cancelled`.
  std::function<bool(size_t done, size_t total, const char *func_name)> progress;
};

struct IdaLiftResult
{
  std::shared_ptr<Program> program;
  ILVariableMap variables;
  std::vector<VariableRow> report;
  /// Call interfaces (parameter/return IL variables) of every lifted function, and every call site
  /// with its caller-side argument/result variables. Consumed by `trex::interproc::propagate`.
  std::vector<trex::interproc::FunctionInterface> interfaces;
  std::vector<trex::interproc::CallSite> calls;
  /// Machine entry address of every function in `program->functions` (including the external-callee
  /// stubs), so a call site's `callee_ea` can be resolved to a function index.
  std::map<ea_t, size_t> function_index;
  int functions_lifted = 0;
  int functions_failed = 0;
  /// Number of instructions that fell back to UnderspecifiedOutputModification/Nop.
  int fallback_instructions = 0;
  /// Histogram of fallback causes, for the log.
  std::vector<std::pair<std::string, int>> fallback_histogram;
  std::string log_text;
  /// Set when `options.progress` aborted the lift.
  bool cancelled = false;
  /// Time spent inside IDA's decompiler (`gen_microcode`) versus inside this frontend. Makes a
  /// slow run attributable: a single huge function is dominated by the former.
  double microcode_seconds = 0.0;
  double lifting_seconds = 0.0;
};

/// Lift the requested functions (plus their direct callees) from Hex-Rays microcode into the TRex
/// IL. Must be called on IDA's main thread. Throws `trex::InvariantError` only for internal
/// inconsistencies; per-function decompiler failures are reported through `IdaLiftResult`.
IdaLiftResult lift_microcode(const IdaLiftOptions &options);

} // namespace trex::ida
