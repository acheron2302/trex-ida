// SSA-form construction for the TRex IL.
//
// 1:1 port of `third_party/trex/trex/src/ssa.rs` (946 lines) into C++20.
//
// The SSA form here is an Aycock–Horspool-style reaching-definitions-driven variant: each
// IL input gets a `Variable` (either an SSA variable, a "constant value" with a
// prog-point and a value, or a value-irrelevant constant used for addresses); each IL
// output gets one SSA variable; phi nodes are inserted where the reaching definitions of
// an input come from multiple program points.
//
// `ssa::Variable` is the SSA-side variable type used everywhere in the analysis pipeline
// (it shadows the `::trex::Variable` name intentionally — `::trex::Variable` is the raw IL
// operand, `ssa::Variable` is the SSA version of it).
//
// `SSAVariable` is a thin wrapper around a `size_t`; it formats as `vN`.
//
// `SSAVarDefinition` is the definition behind an `SSAVariable`. Three variants in
// upstream order: `PhiNode`, `ILInstruction`, `ValueAtFunctionStart`. The custom hash
// and ordering from upstream lines 140-198 are transcribed identically — they are the
// ordering used by the deterministic containers that produce the compared output.
//
// `SSA` holds the SSA form plus a read-only reference to the underlying program.
// `DebugProgram` is a small RAII-ish view that prints the SSA form with optional
// machine-address annotations and an optional highlight.

#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <trex/aslocation.hpp>
#include <trex/containers.hpp>
#include <trex/dataflow.hpp>
#include <trex/il.hpp>

namespace trex {

// Forward declaration so `ssa::Variable::normalize_program_point_for_const` can take a
// `const Program &` parameter (the program itself uses SSA only via this header).
class Program;

namespace ssa {

// ---------------------------------------------------------------------------
// SSAVariable
//
// Thin wrapper around a `size_t` index into `SSA::ssa_vars`. Formatted as `vN` for
// debug output. Indexed identity (the integer `idx`) is the SSA identity, matching
// upstream's `SSAVariable(usize)`.
class SSAVariable
{
public:
  size_t idx = 0;

  SSAVariable() = default;
  explicit SSAVariable(size_t i) : idx(i) {}

  std::string debug_string() const;
  std::string to_string() const;

  friend bool operator==(const SSAVariable &a, const SSAVariable &b) { return a.idx == b.idx; }
  friend bool operator!=(const SSAVariable &a, const SSAVariable &b) { return !(a == b); }
  friend bool operator<(const SSAVariable &a, const SSAVariable &b) { return a.idx < b.idx; }
  friend bool operator<=(const SSAVariable &a, const SSAVariable &b) { return a.idx <= b.idx; }
  friend bool operator>(const SSAVariable &a, const SSAVariable &b) { return a.idx > b.idx; }
  friend bool operator>=(const SSAVariable &a, const SSAVariable &b) { return a.idx >= b.idx; }
};

// ---------------------------------------------------------------------------
// SSAVarDefinition
//
// Definition behind an `SSAVariable`. Three variants, in upstream order.
//
// `Hash` and `Ord` from upstream (lines 140-198) are transcribed exactly:
//   - The `Hash` is a `u8` discriminant followed by the payload:
//     - `PhiNode`: hash the `usize` sum of the inner `SSAVariable`s (so the hash is
//       independent of ordering).
//     - `ILInstruction` and `ValueAtFunctionStart`: hash the IL PC then the ASLocation.
//   - The `Ord` compares discriminants first (`PhiNode` < `ILInstruction` <
//     `ValueAtFunctionStart`), then payloads:
//     - `PhiNode`: length, then BTree-ordered element set.
//     - The non-phi variants: IL PC then ASLocation.
class SSAVarDefinition
{
public:
  enum class Kind : uint8_t
  {
    PhiNode = 0,
    ILInstruction,
    ValueAtFunctionStart,
  };

  Kind kind = Kind::PhiNode;

  // PhiNode
  unordered::UnorderedSet<SSAVariable> phi;

  // ILInstruction / ValueAtFunctionStart
  size_t il_pc = 0;
  ASLocation asloc;

  SSAVarDefinition() = default;

  static SSAVarDefinition make_phi(unordered::UnorderedSet<SSAVariable> vs)
  {
    SSAVarDefinition d;
    d.kind = Kind::PhiNode;
    d.phi = std::move(vs);
    return d;
  }
  static SSAVarDefinition make_il_instruction(size_t il_pc, ASLocation loc)
  {
    SSAVarDefinition d;
    d.kind = Kind::ILInstruction;
    d.il_pc = il_pc;
    d.asloc = loc;
    return d;
  }
  static SSAVarDefinition make_value_at_function_start(size_t il_pc, ASLocation loc)
  {
    SSAVarDefinition d;
    d.kind = Kind::ValueAtFunctionStart;
    d.il_pc = il_pc;
    d.asloc = loc;
    return d;
  }

  std::string debug_string() const;

  friend bool operator==(const SSAVarDefinition &a, const SSAVarDefinition &b)
  {
    if ( a.kind != b.kind )
      return false;
    switch ( a.kind )
    {
      case Kind::PhiNode:
        return a.phi.set() == b.phi.set();
      case Kind::ILInstruction:
        return a.il_pc == b.il_pc && a.asloc == b.asloc;
      case Kind::ValueAtFunctionStart:
        return a.il_pc == b.il_pc && a.asloc == b.asloc;
    }
    return false;
  }
  friend bool operator!=(const SSAVarDefinition &a, const SSAVarDefinition &b)
  {
    return !(a == b);
  }
  friend bool operator<(const SSAVarDefinition &a, const SSAVarDefinition &b);
};

// ---------------------------------------------------------------------------
// Variable (SSA-side)
//
// Mirrors the upstream enum `ssa::Variable`. The three variants unify the way we reason
// about SSA variables and IL constants:
//
//   - `Variable` is the SSA variable.
//
//   - `ConstantValue` is an IL-level constant, used for inputs only (the output of an
//     instruction is never a constant value — that would have been constant-folded).
//     `input_posn_in_il_insn` distinguishes two constants in the same instruction.
//
//   - `ValueIrrelevantConstant` represents addresses (machine / IL / IL-offset) which
//     carry no useful type information.
class Variable
{
public:
  enum class Kind : uint8_t
  {
    Variable = 0,
    ConstantValue,
    ValueIrrelevantConstant,
  };

  Kind kind = Kind::ValueIrrelevantConstant;

  // Variable (SSA)
  // `var.idx` is the SSA variable index; the definition lives at
  // `SSA::ssa_vars[var.idx]` of the SSA object that owns this Variable.
  SSAVariable var{};

  // ConstantValue
  ProgPoint progpoint;
  size_t input_posn_in_il_insn = 0;
  uint64_t value = 0;

  Variable() = default;

  static Variable variable(SSAVariable v)
  {
    Variable out;
    out.kind = Kind::Variable;
    out.var = v;
    return out;
  }
  static Variable constant_value(ProgPoint pp, size_t pos, uint64_t v)
  {
    Variable out;
    out.kind = Kind::ConstantValue;
    out.progpoint = pp;
    out.input_posn_in_il_insn = pos;
    out.value = v;
    return out;
  }
  static Variable value_irrelevant_constant()
  {
    Variable out;
    out.kind = Kind::ValueIrrelevantConstant;
    return out;
  }

  /// Normalize constants to become position-independent (per-function, used for GVN).
  /// Mirrors `Variable::normalize_program_point_for_const`.
  Variable normalize_program_point_for_const(const Program &program) const;

  std::string debug_string() const;

  friend bool operator==(const Variable &a, const Variable &b)
  {
    if ( a.kind != b.kind )
      return false;
    switch ( a.kind )
    {
      case Kind::Variable:
        return a.var == b.var;
      case Kind::ConstantValue:
        return a.progpoint == b.progpoint
               && a.input_posn_in_il_insn == b.input_posn_in_il_insn && a.value == b.value;
      case Kind::ValueIrrelevantConstant:
        return true;
    }
    return false;
  }
  friend bool operator!=(const Variable &a, const Variable &b) { return !(a == b); }
  friend bool operator<(const Variable &a, const Variable &b)
  {
    if ( a.kind != b.kind )
      return (uint8_t)a.kind < (uint8_t)b.kind;
    switch ( a.kind )
    {
      case Kind::Variable:
        return a.var < b.var;
      case Kind::ConstantValue:
        if ( a.progpoint != b.progpoint )
          return a.progpoint < b.progpoint;
        if ( a.input_posn_in_il_insn != b.input_posn_in_il_insn )
          return a.input_posn_in_il_insn < b.input_posn_in_il_insn;
        return a.value < b.value;
      case Kind::ValueIrrelevantConstant:
        return false;
    }
    return false;
  }
  friend bool operator<=(const Variable &a, const Variable &b) { return !(b < a); }
};

// ---------------------------------------------------------------------------
// SSA
//
// The SSA form computed for the whole program. `ssa_vars` is the vector of definitions;
// SSA variable `vN` refers to definition `ssa_vars[N]`.
class SSA
{
public:
  /// The SSA variable definitions, in insertion order (mirrors `InsertionOrderedSet`).
  std::vector<SSAVarDefinition> ssa_vars;
  /// The input SSA variables for each instruction (Variable::Unused → empty).
  std::vector<std::vector<Variable>> ins_inputs;
  /// The output SSA variable for each instruction (`None` if the instruction produces
  /// no output). Note: the analysis assumes at most one output per instruction.
  std::vector<std::optional<Variable>> ins_output;
  /// Read-only reference to the program.
  std::shared_ptr<const Program> program;

  /// Compute the SSA IR for `program`. Mirrors `SSA::compute_from`.
  static SSA compute_from(std::shared_ptr<const Program> program);

  /// Iterate over all phi-node SSA variables, yielding `(var, &phi_set)`.
  std::vector<std::pair<SSAVariable, const unordered::UnorderedSet<SSAVariable> *>>
  phi_nodes_iter() const;

  /// Get the function inputs at IL instruction address `il_pc`. Asserts that
  /// `instructions[il_pc].op == FunctionStart`.
  std::vector<Variable> get_function_inputs(size_t il_pc) const;

  /// Get the input variable at index `i` at IL instruction address `il_pc`.
  Variable get_input_variable(size_t il_pc, size_t i) const;

  /// Get the variable impacted by the output at IL instruction address `il_pc`
  /// (`None` if no output). Mirrors `get_output_impacted_variable`.
  std::optional<Variable> get_output_impacted_variable(size_t il_pc) const;

  /// Convenience: `get_output_impacted_variable(...).unwrap()`.
  Variable get_output_variable(size_t il_pc) const;

  /// Check if variable `v` is an effective constant.
  bool is_effectively_constant(Variable v) const;

  /// Get all instructions (as IL PCs) that immediately affect the value of `v`.
  /// Returns empty for non-SSA variables.
  std::vector<size_t> get_all_immediately_affecting_instructions(Variable v) const;

  /// Get the first matching `(collection of) SSA variable(s)` for an IL variable
  /// `il_var` in function `func_id`, or `std::nullopt`.
  std::optional<std::vector<Variable>>
  get_first_matching_variables_for(const ::trex::Variable &il_var, size_t func_id) const;

  /// Get all matching SSA variables for `il_var` in `func_id`, or `std::nullopt`.
  std::optional<std::vector<Variable>>
  get_all_matching_variables_for(const ::trex::Variable &il_var, size_t func_id) const;

  /// Get all (normal, non-phi) variables seen as input or output in function
  /// `func_id`, as `(il_variable, ssa_variable)` pairs.
  std::vector<std::pair<::trex::Variable, Variable>>
  get_all_normal_vars_of_function(size_t func_id) const;

  /// Check if `v` is effectively equal to `sp + offset`. Bounded at 100 iterations
  /// to avoid pathological loops.
  bool is_variable_effectively_equal_to_sp_offset(Variable v, Variable sp,
                                                  int64_t offset) const;

  /// Get SSA variables involved in a load/store to the stack at the given offset.
  std::vector<Variable> get_stack_involved_ssa_variables(size_t func_id,
                                                         Variable initial_sp,
                                                         int64_t offset) const;

private:
  /// Implementation of `get_first_matching_variables_for` / `get_all_matching_variables_for`.
  std::optional<std::vector<Variable>>
  get_matching_variables_for(const ::trex::Variable &il_var, size_t func_id,
                              bool first_only) const;
};

/// Debug view on the program after SSA computation.
class DebugProgram
{
public:
  const SSA &ssa;
  bool show_machine_addr = false;
  std::optional<size_t> highlight_il_addr;

  DebugProgram(const SSA &s, bool show_ma, std::optional<size_t> hl)
      : ssa(s), show_machine_addr(show_ma), highlight_il_addr(hl)
  {}
};

} // namespace ssa

// ---------------------------------------------------------------------------
// Debug printing for `ssa::DebugProgram`. We deliberately do NOT route the SSA
// debug print through `std::ostream` (the upstream uses `write!` with manual
// formatting that is hard to replicate with operator<<). The output is reachable
// via the `format` helper below.
//
// Note: this is a minimal port — it covers the common "dump SSA form to a string"
// usage that the unit tests need.
std::string format_debug_program(const ssa::DebugProgram &dp);

} // namespace trex

// ---------------------------------------------------------------------------
// `std::hash<SSAVariable>` so `std::unordered_set<SSAVariable>` works if needed by
// downstream code (ssa.rs declares `Hash` on SSAVariable and SSAVarDefinition).
namespace std {
template <>
struct hash<trex::ssa::SSAVariable>
{
  size_t operator()(const trex::ssa::SSAVariable &v) const noexcept { return v.idx; }
};
template <>
struct hash<trex::ssa::SSAVarDefinition>
{
  // Mirrors `impl Hash for SSAVarDefinition` from upstream ssa.rs lines 140-161.
  size_t operator()(const trex::ssa::SSAVarDefinition &d) const noexcept
  {
    auto mix = [](size_t seed, size_t v) -> size_t {
      return seed ^ (v + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2));
    };
    size_t seed = static_cast<size_t>(d.kind);
    switch ( d.kind )
    {
      case trex::ssa::SSAVarDefinition::Kind::PhiNode:
      {
        size_t h = 0;
        for ( const auto &v : d.phi.iter() )
          h += v.idx;
        return mix(seed, h);
      }
      case trex::ssa::SSAVarDefinition::Kind::ILInstruction:
      case trex::ssa::SSAVarDefinition::Kind::ValueAtFunctionStart:
      {
        seed = mix(seed, static_cast<size_t>(d.il_pc));
        seed = mix(seed, d.asloc.address_space_idx);
        seed = mix(seed, static_cast<size_t>(d.asloc.offset));
        return seed;
      }
    }
    return 0;
  }
};
} // namespace std