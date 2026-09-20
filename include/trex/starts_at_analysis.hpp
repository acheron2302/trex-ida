// Co-location analysis - port of upstream `trex/src/starts_at_analysis.rs`.
//
// `Constraint` enumerates the ways a dereference can be observed to happen:
// a fixed offset from a base pointer (`OffsetDeref`) or a non-constant
// offset from a base pointer (`NonConstantOffsetDeref`). `CoLocated` is
// the analysis result: a map from `Constraint` to the set of IL PCs that
// imply it.
//
// The analysis walks Load/Store instructions back through `IntAdd`/`IntSub`
// using a worklist. A per-variable `(il_pcs, reasons)` dedup table prevents
// the same work from being repeated when an instruction is reachable from
// multiple chains. This dedup is the load-bearing contract for the
// downstream `aggregate_types` and `type_rounding` passes.

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include <trex/containers.hpp>
#include <trex/ssa.hpp>

namespace trex {

// Forward declarations so the headers can refer to the in-progress types
// without dragging their full definitions into every TU that uses this
// header.
class StructuralTypes;
class ConstFolded;

// ---------------------------------------------------------------------------
// Constraint
//
// Discriminated union; declaration order matches upstream. The variants carry
// payload fields, so the port keeps `kind` plus all payload fields in one
// struct and orders by `(kind, fields...)` exactly the way Rust's derived
// `Ord` does for the enum's variants and their fields in declaration order.
// ---------------------------------------------------------------------------
struct Constraint
{
  enum class Kind : uint8_t
  {
    OffsetDeref = 0,
    NonConstantOffsetDeref,
  };

  Kind kind = Kind::OffsetDeref;

  // OffsetDeref + NonConstantOffsetDeref share these fields.
  ssa::Variable t;
  ssa::Variable base_ptr;

  // OffsetDeref only
  int64_t offset = 0;

  // NonConstantOffsetDeref only
  ssa::Variable offset_var;

  Constraint() = default;

  static Constraint offset_deref(ssa::Variable t, int64_t offset, ssa::Variable base_ptr)
  {
    Constraint c;
    c.kind = Kind::OffsetDeref;
    c.t = std::move(t);
    c.offset = offset;
    c.base_ptr = std::move(base_ptr);
    return c;
  }

  static Constraint non_constant_offset_deref(ssa::Variable t, ssa::Variable offset_var,
                                              ssa::Variable base_ptr)
  {
    Constraint c;
    c.kind = Kind::NonConstantOffsetDeref;
    c.t = std::move(t);
    c.offset_var = std::move(offset_var);
    c.base_ptr = std::move(base_ptr);
    return c;
  }

  friend bool operator==(const Constraint &a, const Constraint &b)
  {
    if (a.kind != b.kind)
      return false;
    if (a.kind == Kind::OffsetDeref) {
      return a.t == b.t && a.offset == b.offset && a.base_ptr == b.base_ptr;
    }
    return a.t == b.t && a.offset_var == b.offset_var && a.base_ptr == b.base_ptr;
  }
  friend bool operator!=(const Constraint &a, const Constraint &b) { return !(a == b); }
  // Order matches Rust's derived Ord: kind discriminant first, then payload
  // fields in declaration order. `t` then `offset`/`offset_var` (the active
  // payload), then `base_ptr`.
  friend bool operator<(const Constraint &a, const Constraint &b)
  {
    if (a.kind != b.kind)
      return (uint8_t)a.kind < (uint8_t)b.kind;
    if (a.t != b.t)
      return a.t < b.t;
    if (a.kind == Kind::OffsetDeref) {
      if (a.offset != b.offset)
        return a.offset < b.offset;
    } else {
      if (a.offset_var != b.offset_var)
        return a.offset_var < b.offset_var;
    }
    return a.base_ptr < b.base_ptr;
  }

  std::string debug_string() const;
};

// ---------------------------------------------------------------------------
// CoLocated
//
// The result of running `CoLocated::analyze` over a `StructuralTypes`. Holds
// the discovered `Constraint`s and the IL PCs that imply each one.
// ---------------------------------------------------------------------------
class CoLocated
{
public:
  /// A map of constraints to instructions that imply this constraint. Mirrors
  /// upstream's `UnorderedMap<Constraint, UnorderedSet<usize>>` (BTreeMap /
  /// BTreeSet in our deterministic build).
  unordered::UnorderedMap<Constraint, unordered::UnorderedSet<size_t>> constraints;

  /// The structural types from which the co-location constraints have been
  /// discovered. Mirrors `Rc<StructuralTypes>` in upstream.
  std::shared_ptr<StructuralTypes> structural_types;

  /// On-demand constant-folding. Mirrors `Rc<ConstFolded>` in upstream.
  std::shared_ptr<ConstFolded> constant_folding;

  /// Analyze the given `structural_types` and recover co-location constraints.
  static CoLocated analyze(const std::shared_ptr<StructuralTypes> &structural_types);

  /// Get the base variables to discovered aggregate types. Mirrors
  /// `get_aggregate_base_variables`.
  std::vector<ssa::Variable> get_aggregate_base_variables() const;

  std::string debug_string() const;
};

} // namespace trex