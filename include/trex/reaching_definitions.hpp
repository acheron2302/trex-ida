// Reaching definitions dataflow analysis.
//
// 1:1 port of `third_party/trex/trex/src/reaching_definitions.rs` (109 lines) into C++20.
//
// The reaching-definitions element is a map from each ASLocation to the set of program
// points that define that location and reach the current program point. Upstream uses
// `Rc<UnorderedSet<ProgPoint>>` so the join can share the input sets with the result; in
// this single-threaded port we keep the same shape with `std::shared_ptr`.
//
// Note on the container: upstream's `UnorderedSet` is BTree-backed under the
// `deterministic_containers` feature, so iteration order is sorted by `ProgPoint`. We
// use `trex::unordered::UnorderedSet<ProgPoint>` to match that order without having to
// add a `std::hash<ProgPoint>` specialisation.
//
// The element implements `DataFlowElement`:
//   - `init`: empty map (every definition point is a fresh start).
//   - `join_from`: union on every shared key (other-only keys are added too).
//   - `init_func_start`: at function start every variable in the function is defined by
//     the function's entry point.
//   - `transfer_function`: OUT[n] = (IN[n] -KILL[n]) ∪ GEN[n]. KILL is derived from the
//     call shape (`CallWithFallthroughIndirect` kills everything; `CallWithFallthrough`
//     kills every variable NOT in the callee's unaffected set).

#pragma once

#include <cstddef>
#include <map>
#include <memory>

#include <trex/containers.hpp>
#include <trex/dataflow.hpp>
#include <trex/il.hpp>

namespace trex {

/// Reaching definitions at a specific IL instruction.
/// (Mirrors `struct ReachingDefinitionsElement` from upstream.)
class ReachingDefinitionsElement : public DataFlowElement
{
public:
  /// Each entry: a location and the set of program points that define it. We use
  /// `std::shared_ptr<UnorderedSet<ProgPoint>>` so the join can `union_with` cheaply and
  /// the result is owned by the map. (Upstream's `Rc<UnorderedSet<...>>`.)
  std::map<ASLocation, std::shared_ptr<unordered::UnorderedSet<ProgPoint>>> defs;

  ReachingDefinitionsElement() = default;
  ReachingDefinitionsElement(const ReachingDefinitionsElement &) = default;
  ReachingDefinitionsElement(ReachingDefinitionsElement &&) = default;
  ReachingDefinitionsElement &operator=(const ReachingDefinitionsElement &) = default;
  ReachingDefinitionsElement &operator=(ReachingDefinitionsElement &&) = default;

  std::unique_ptr<DataFlowElement> make_init() const override;
  void join_from(const DataFlowElement &other) override;
  std::unique_ptr<DataFlowElement> make_init_func_start(const ProgramSummary &summary,
                                                        size_t fn_start) const override;
  std::unique_ptr<DataFlowElement> make_transfer_function(size_t il_pc,
                                                          const ProgramSummary &summary) const override;
  std::unique_ptr<DataFlowElement> clone() const override;
  bool equals(const DataFlowElement &other) const override;

  /// Equality predicate used by the worklist. The definition sets are held behind shared
  /// pointers, so this must compare their *contents*: comparing the pointers would make every
  /// worklist iteration look like a change and the analysis would never converge.
  bool operator==(const ReachingDefinitionsElement &other) const
  {
    if ( defs.size() != other.defs.size() )
      return false;
    for ( const auto &entry : defs )
    {
      auto it = other.defs.find(entry.first);
      if ( it == other.defs.end() )
        return false;
      if ( entry.second == nullptr || it->second == nullptr )
      {
        if ( entry.second != it->second )
          return false;
        continue;
      }
      if ( *entry.second != *it->second )
        return false;
    }
    return true;
  }
  bool operator!=(const ReachingDefinitionsElement &other) const { return !(*this == other); }

private:
  static std::shared_ptr<unordered::UnorderedSet<ProgPoint>> singleton_ppset(size_t il_pc);
};

} // namespace trex