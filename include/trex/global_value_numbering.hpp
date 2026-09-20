// Global value numbering analysis.
//
// 1:1 port of `third_party/trex/trex/src/global_value_numbering.rs` (199 lines) into C++20.
//
// `Value` is the internal representation used by the disjoint-set: an SSA `Variable`, or
// a one/two-operand `Op` applied to (normalised) SSA variables. `OpSummary` classifies
// each `Op` into one of seven categories that decide how the value is merged into the
// congruence relation.
//
// The analysis itself is `analyze_from(&SSA)`, and the result exposes
// `congruent_sets_iter` returning the congruence classes that contain at least two SSA
// `Variable`s.

#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <utility>
#include <vector>

#include <trex/containers.hpp>
#include <trex/il.hpp>
#include <trex/ssa.hpp>

namespace trex {

/// Per-`Op` classification (upstream `enum OpSummary`).
enum class OpSummary
{
  HasNoOutput = 0,
  MustNotMerge,
  MightBeMergedInFutureButDoNotMergeNow,
  MergeResultButNoCommutativity,
  MergeResultWithCommutativity,
  MergeCopy,
  MergeResultSingleArgument,
};

/// Map `Op` → its summary class. Mirrors `OpSummary::of` from upstream.
OpSummary op_summary_of(const trex::Op &op);

/// The result of a global value numbering analysis. Mirrors `struct GlobalValueNumbering`.
class GlobalValueNumbering
{
public:
  /// The SSA IR upon which the analysis was done.
  std::shared_ptr<const ssa::SSA> ssa;
  /// Congruence relations discovered through analysis. Keyed by the smallest SSA
  /// variable index in each class; iteration is in key order (deterministic).
  /// The congruence classes that contain at least two SSA variables, in the order the disjoint-set
  /// iteration produced them. Upstream keeps exactly this order (its `disjoint_sets_iter()` yields
  /// classes ordered by the representative's storage position), and the order is observable: the
  /// structural types are joined class by class, and joins allocate type indices, so re-sorting the
  /// classes changes the inferred type graph.
  std::vector<unordered::UnorderedSet<ssa::Variable>> congruent;

  /// Analyze `ssa` for global value numbering. Mirrors `analyze_from`.
  static GlobalValueNumbering analyze_from(std::shared_ptr<const ssa::SSA> ssa);

  /// Produce the discovered sets of congruent SSA variables. Each returned
  /// `unordered::UnorderedSet<ssa::Variable>` contains SSA `Variable`s whose values
  /// the analysis found equivalent; sets of size < 2 are filtered out (mirrors upstream
  /// `.filter(|m| m.len() >= 2)`).
  std::vector<unordered::UnorderedSet<ssa::Variable>> congruent_sets_iter() const;
};

} // namespace trex