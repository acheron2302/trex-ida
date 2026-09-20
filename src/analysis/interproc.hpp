#pragma once

// Inter-procedural type propagation across call edges.
//
// The core is intra-procedural: `infer_structural_types` treats every `Call*` op as `⊤` (no
// constraint), so an argument never constrains its callee's parameter and a returned value never
// constrains its caller. The upstream paper (USENIX Security '25, §3.3 footnote 9) notes that
// extending *Type Reconstruction* to inter-procedural is straightforward: "Direct calls propagate
// types; indirect calls introduce controllable non-conservativeness ... Multiple paths through a
// single void* (e.g., malloc) in source produce precise unions."
//
// This module implements exactly that, without touching `src/trex/*`: after structural inference,
// the types of the variables linked by a call edge are joined in the program-wide
// `Container<StructuralType>` (the same lattice join the inference itself uses, which merges two
// types into the union of their observed behaviors and cascades through pointees). Every later
// phase — colocation, aggregate analysis, rounding, nominal reconstruction — then reads the merged
// container, so a value seen as two different struct pointers at two call sites ends up with the
// precise union of those behaviors instead of `void*`.

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <vector>

#include <trex/il.hpp>
#include <trex/pipeline.hpp>
#include <trex/structural.hpp>

namespace trex::interproc {

/// Machine address of an unknown callee (an indirect call IDA could not resolve).
inline constexpr uint64_t kNoAddress = ~uint64_t{ 0 };

/// A function's call interface: the IL variable of each parameter, in parameter order, and of the
/// returned value. `nullopt` where no IL variable exists (an unused or unsupported lvar).
struct FunctionInterface
{
  size_t func = 0;
  std::vector<std::optional<trex::Variable>> params;
  std::optional<trex::Variable> result;
};

/// One call site. `callee_func` is filled in by the caller of this module (the index into
/// `Program::functions` for `callee_ea`, when the callee exists in the program).
struct CallSite
{
  size_t caller = 0;
  uint64_t callee_ea = kNoAddress;
  std::optional<size_t> callee_func;
  /// Caller-side value per argument index; `nullopt` when the argument is not a simple location.
  std::vector<std::optional<trex::Variable>> args;
  /// Arguments passed *by address* (`&local`): same indexing as `args`, holding the addressed
  /// variable. The callee's parameter is a pointer whose pointee is that variable, so the
  /// constraint is a dereference, not a plain join.
  std::vector<std::optional<trex::Variable>> arg_pointees;
  /// Caller-side variable receiving the returned value.
  std::optional<trex::Variable> result;
};

/// What a propagation run did, for the log line.
struct Stats
{
  size_t sites = 0;          ///< call sites with a callee identity
  size_t param_binds = 0;    ///< argument <-> parameter joins performed
  size_t result_binds = 0;   ///< result <-> returned-value joins performed
  size_t site_groups = 0;    ///< joins between values of different sites of the same callee
  size_t unresolved = 0;     ///< sites skipped: no callee identity (unresolved indirect call)
  size_t missing_values = 0; ///< values skipped: no IL variable, no SSA variable, or no type yet
};

/// Join the types of all variables linked by call edges in `types`.
void propagate(trex::StructuralTypes &types,
               const std::vector<FunctionInterface> &interfaces,
               const std::vector<CallSite> &sites,
               bool aggregate_sites,
               Stats &stats);

/// The result of the pipeline with the inter-procedural pass between inference and the aggregate
/// analysis. Kept separate from `TrexPipelineResult` so that no core header has to change.
struct InterprocResult
{
  trex::TrexPipelineResult pipeline; ///< exactly what `run_trex_pipeline` would have produced
  bool propagated = false;           ///< false: the pass was disabled or aborted (stats zeroed)
  Stats stats;
};

/// Run inference + inter-procedural propagation + serialization for a lifted program.
InterprocResult run_trex_pipeline_interproc(
    const std::shared_ptr<const trex::Program> &program,
    const std::optional<trex::ILVariableMap> &vars,
    const std::vector<FunctionInterface> &interfaces,
    const std::vector<CallSite> &sites,
    bool aggregate_sites,
    Stats &stats);

} // namespace trex::interproc
