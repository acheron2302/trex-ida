// Aggregate type reconstruction - port of upstream `trex/src/aggregate_types.rs`.
//
// `AggrType` describes a single recovered aggregate (a C `struct` or an
// array). `SquishySize` is the analysis-internal accumulator of observed
// `(offset, length)` constraints; it gets coerced into an `AggrType` once
// the analysis is done. `AggregateTypes::analyze` walks the co-location
// constraints from `CoLocated` to compute, for each base pointer, the
// aggregate that lives behind it; `to_structural_types` then mutates the
// `StructuralTypes` to reflect those aggregates.
//
// `Padding` lives in `structural.hpp` (where `StructuralTypes::convert_to_struct`
// consumes it) — we re-export it here for source parity with the upstream
// file.

#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <trex/containers.hpp>
#include <trex/ssa.hpp>
#include <trex/structural.hpp>

namespace trex {

// Forward declarations
class StructuralTypes;
class CoLocated;

// ---------------------------------------------------------------------------
// AggrType
//
// An aggregate type recovered by `AggregateTypes`. Two variants in upstream
// order: `Struct` and `Array`. The port keeps `kind` plus all payload fields
// in one struct.
// ---------------------------------------------------------------------------
struct AggrType
{
  enum class Kind : uint8_t
  {
    Struct = 0,
    Array,
  };

  Kind kind = Kind::Struct;

  // Struct
  std::vector<std::pair<size_t, Padding>> member_sizes;
  bool has_unsized_array_at_end = false;

  // Array
  size_t member_size = 0;

  AggrType() = default;

  static AggrType make_struct(std::vector<std::pair<size_t, Padding>> member_sizes,
                              bool has_unsized_array_at_end)
  {
    AggrType a;
    a.kind = Kind::Struct;
    a.member_sizes = std::move(member_sizes);
    a.has_unsized_array_at_end = has_unsized_array_at_end;
    return a;
  }

  static AggrType make_array(size_t member_size)
  {
    AggrType a;
    a.kind = Kind::Array;
    a.member_size = member_size;
    return a;
  }

  friend bool operator==(const AggrType &a, const AggrType &b)
  {
    if (a.kind != b.kind)
      return false;
    if (a.kind == Kind::Struct) {
      return a.member_sizes == b.member_sizes
             && a.has_unsized_array_at_end == b.has_unsized_array_at_end;
    }
    return a.member_size == b.member_size;
  }
  friend bool operator!=(const AggrType &a, const AggrType &b) { return !(a == b); }
  friend bool operator<(const AggrType &a, const AggrType &b)
  {
    if (a.kind != b.kind)
      return (uint8_t)a.kind < (uint8_t)b.kind;
    if (a.kind == Kind::Struct) {
      if (a.member_sizes != b.member_sizes)
        return a.member_sizes < b.member_sizes;
      return a.has_unsized_array_at_end < b.has_unsized_array_at_end;
    }
    return a.member_size < b.member_size;
  }

  std::string debug_string() const;
};

// ---------------------------------------------------------------------------
// AggregateTypes
//
// The result of running `AggregateTypes::analyze`. Mirrors upstream's
// `AggregateTypes` exactly.
// ---------------------------------------------------------------------------
class AggregateTypes
{
public:
  /// A map of base pointers to aggregate type constraints.
  unordered::UnorderedMap<ssa::Variable, AggrType> constraints;
  /// The co-location constraints from which these size-of constraints have
  /// been discovered. Mirrors `Rc<CoLocated>`.
  std::shared_ptr<CoLocated> colocated;

  /// Analyze the given `colocated` constraints and recover aggregate type
  /// information. Mirrors `AggregateTypes::analyze`.
  static AggregateTypes analyze(const std::shared_ptr<CoLocated> &colocated);

  /// Use the recovered aggregate type information to produce structural types
  /// that include aggregate types. Mirrors `to_structural_types`.
  StructuralTypes to_structural_types() const;

  std::string debug_string() const;
};

} // namespace trex