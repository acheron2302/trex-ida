// Implementation of `aggregate_types` (port of upstream
// `trex/src/aggregate_types.rs`).
//
// The algorithm:
//   1. For every base variable in `CoLocated::get_aggregate_base_variables`,
//      create an empty `SquishySize` accumulator.
//   2. For every constraint:
//        - `OffsetDeref` with `offset >= 0`: constrain `base_ptr` to
//          `observed_size(t)` bytes at offset `offset`. If offset < 0,
//          mark the accumulator as observing negative offsets.
//        - `NonConstantOffsetDeref`: mark the accumulator as observing
//          non-constant access and constrain offset 0 to the size of `t`.
//   3. Coerce every `SquishySize` into an `AggrType` (struct with
//      padding entries between the values, or single-element array if only
//      one member and non-constant access was observed).
//   4. `to_structural_types()` deep-clones the underlying `StructuralTypes`,
//      then for every recovered aggregate, calls `convert_to_struct` /
//      `convert_to_array` on the pointee of the base pointer and
//      `mark_types_as_equal` for every colocated field reference.

#include <trex/aggregate_types.hpp>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <trex/containers.hpp>
#include <trex/il.hpp>
#include <trex/log.hpp>
#include <trex/ssa.hpp>
#include <trex/starts_at_analysis.hpp>
#include <trex/structural.hpp>

namespace trex {

namespace {

/// Analysis-internal accumulator. Mirrors the Rust `SquishySize` struct.
struct SquishySize
{
  /// A map from starting locations to sizes. Invariant maintained: the sizes
  /// will not overlap.
  std::map<size_t, size_t> sizes;
  /// Whether non-constant accesses have been discovered yet.
  bool non_constant_access = false;
  /// Whether negative offsets have been seen.
  bool negative_offsets_observed = false;

  SquishySize() = default;

  /// Constrain size at `loc` to a max of `len` bytes. Mirrors upstream
  /// `SquishySize::constrain`. The behavior is exactly the same as Rust:
  /// if there's already a constraint at `loc`, the longer one wins (the
  /// shorter one is split out); otherwise it may split an existing
  /// neighbouring constraint that the new range overlaps.
  void constrain(size_t loc, size_t len)
  {
    TREX_CHECK(len != 0, "SquishySize::constrain: len must be non-zero");

    // Check clashes on left, and insert as needed.
    {
      auto it = sizes.upper_bound(loc);
      if (it == sizes.begin()) {
        // No value found before or at `loc`.
        sizes.emplace(loc, len);
      } else {
        --it;
        size_t k = it->first;
        size_t v = it->second;
        if (k == loc) {
          if (v < len) {
            log::info("Differing sizes, ignoring longer new size",
                      {{"old", v}, {"new", len}});
          } else if (v == len) {
            // Nothing to be done.
          } else {
            // v > len: split.
            log::info("Differing sizes, performing splitting",
                      {{"old", v}, {"new", len}});
            sizes[k] = len;
            sizes.emplace(k + len, v - len);
          }
        } else {
          sizes.emplace(loc, len);
          if (k + v <= loc) {
            // No clash.
          } else {
            // Clash, perform split.
            log::debug("Clash found, performing splitting",
                       {{"old_loc", k}, {"v_off", v}, {"new_loc", loc}, {"new_len", len}});
            sizes[k] = loc - k;
          }
        }
      }
    }

    // Check clashes on right, and split as necessary.
    {
      auto it = sizes.upper_bound(loc);
      if (it == sizes.end()) {
        // Nothing it can clash with.
      } else {
        size_t k = it->first;
        size_t v = it->second;
        if (loc + len <= k) {
          // No clash.
        } else {
          // Clash, perform split.
          log::debug("Clash found on right, performing splitting",
                     {{"new_loc", loc}, {"new_len", len}, {"old_loc", k}, {"v_off", v}});
          sizes[loc] = k - loc;
        }
      }
    }
  }

  /// Convert to a C-like type. Mirrors upstream `to_c_like_type`.
  /// Returns std::nullopt when negative offsets were observed.
  std::optional<AggrType> to_c_like_type() &&
  {
    if (negative_offsets_observed) {
      return std::nullopt;
    }
    if (non_constant_access && sizes.size() == 1) {
      TREX_CHECK(sizes.begin()->first == 0,
                 "SquishySize::to_c_like_type: non-constant access array requires offset 0");
      return AggrType::make_array(sizes.begin()->second);
    }
    std::vector<std::pair<size_t, Padding>> member_sizes;
    size_t start = 0;
    for (const auto &[k, v] : sizes) {
      TREX_CHECK(k >= start, "SquishySize::to_c_like_type: sizes out of order");
      if (k > start) {
        member_sizes.emplace_back(k - start, Padding::IsPadding);
      }
      member_sizes.emplace_back(v, Padding::IsValue);
      start += v;
    }
    return AggrType::make_struct(std::move(member_sizes), non_constant_access);
  }
};

} // namespace

std::string AggrType::debug_string() const
{
  if (kind == Kind::Struct) {
    std::string out = "Struct { ";
    size_t start = 0;
    for (const auto &[s, p] : member_sizes) {
      if (p == Padding::IsPadding) {
        out += "pad__" + std::to_string(start) + ": " + std::to_string(s) + ", ";
      } else {
        out += "val__" + std::to_string(start) + ": " + std::to_string(s) + ", ";
      }
      start += s;
    }
    if (has_unsized_array_at_end) {
      out += "unsized_array_at_end: true, ";
    }
    out += "}";
    return out;
  }
  return "Array { member_size: " + std::to_string(member_size) + " }";
}

std::string AggregateTypes::debug_string() const
{
  std::string out = "AggregateTypes { constraints: {";
  bool first = true;
  for (const auto &[v, aggr] : constraints.iter()) {
    if (!first) out += ", ";
    first = false;
    out += v.debug_string() + " -> " + aggr.debug_string();
  }
  out += "} }";
  return out;
}

// ---------------------------------------------------------------------------
// AggregateTypes::analyze
//
// Walks the co-location constraints, applying them to per-base-pointer
// `SquishySize` accumulators. Returns the resulting aggregate constraints
// (with the accumulators coerced into `AggrType`s).
// ---------------------------------------------------------------------------
AggregateTypes AggregateTypes::analyze(const std::shared_ptr<CoLocated> &colocated)
{
  unordered::UnorderedMap<ssa::Variable, SquishySize> constraints;

  for (const ssa::Variable &v : colocated->get_aggregate_base_variables()) {
    constraints.insert(v, SquishySize{});
  }

  const size_t size_t_size = colocated->structural_types->ssa->program->pointer_size;

  for (const auto &[constraint, _reason] : colocated->constraints.iter()) {
    if (constraint.kind == Constraint::Kind::OffsetDeref) {
      const ssa::Variable &t = constraint.t;
      const int64_t offset = constraint.offset;
      const ssa::Variable &base_ptr = constraint.base_ptr;

      if (offset < 0) {
        SquishySize *sq = constraints.get_mut(base_ptr);
        if (sq != nullptr) {
          sq->negative_offsets_observed = true;
        }
      } else {
        const StructuralType *t_type = colocated->structural_types->get_type_of(t);
        TREX_CHECK(t_type != nullptr,
                   "AggregateTypes::analyze: missing structural type for OffsetDeref t");
        std::optional<size_t> size = t_type->observed_size();
        if (size.has_value()) {
          SquishySize *sq = constraints.get_mut(base_ptr);
          if (sq != nullptr) {
            sq->constrain(static_cast<size_t>(offset), *size);
          }
        } else if (t.kind != ssa::Variable::Kind::ValueIrrelevantConstant) {
          log::debug(
              "No size found for type of dereferenced value at static offset from base pointer",
              {{"offset", offset}, {"base_ptr", base_ptr.debug_string()}});
        }
      }
    } else {
      // NonConstantOffsetDeref
      const ssa::Variable &t = constraint.t;
      const ssa::Variable &offset_var = constraint.offset_var;
      const ssa::Variable &base_ptr = constraint.base_ptr;

      const StructuralType *offset_type = colocated->structural_types->get_type_of(offset_var);
      TREX_CHECK(offset_type != nullptr,
                 "AggregateTypes::analyze: missing structural type for NonConstantOffsetDeref offset");
      std::optional<size_t> offset_observed_size = offset_type->observed_size();
      if (offset_observed_size.has_value() && *offset_observed_size != size_t_size) {
        log::debug("Non size_t offset found",
                   {{"size_t", size_t_size},
                    {"offset_observed_size", offset_observed_size.has_value() ? (int64_t)*offset_observed_size : (int64_t)-1}});
      }
      SquishySize *sq = constraints.get_mut(base_ptr);
      if (sq != nullptr) {
        sq->non_constant_access = true;
      }
      const StructuralType *t_type = colocated->structural_types->get_type_of(t);
      TREX_CHECK(t_type != nullptr,
                 "AggregateTypes::analyze: missing structural type for NonConstantOffsetDeref t");
      std::optional<size_t> size = t_type->observed_size();
      if (size.has_value()) {
        if (sq != nullptr) {
          sq->constrain(0, *size);
        }
      } else if (t.kind != ssa::Variable::Kind::ValueIrrelevantConstant) {
        log::debug("No size found for type of dereferenced value at dynamic offset from base pointer",
                   {{"base_ptr", base_ptr.debug_string()}});
      }
    }
  }

  unordered::UnorderedMap<ssa::Variable, AggrType> result;
  for (auto &[v, sq] : constraints.iter_mut()) {
    std::optional<AggrType> aggr = std::move(sq).to_c_like_type();
    if (aggr.has_value()) {
      result.insert(v, std::move(*aggr));
    }
  }

  AggregateTypes out;
  out.constraints = std::move(result);
  out.colocated = colocated;
  return out;
}

// ---------------------------------------------------------------------------
// AggregateTypes::to_structural_types
//
// Deep-clones the underlying `StructuralTypes`, then for every recovered
// aggregate, calls `convert_to_struct` / `convert_to_array` on the pointee
// of the base pointer and `mark_types_as_equal` for every colocated field
// reference.
// ---------------------------------------------------------------------------
StructuralTypes AggregateTypes::to_structural_types() const
{
  StructuralTypes r = colocated->structural_types->deep_clone();

  // First pass: convert each base pointer's pointee into a struct/array.
  for (const auto &[ptr, aggrtype] : constraints.iter()) {
    if (ptr.kind == ssa::Variable::Kind::ConstantValue) {
      log::info("TODO: Constant as pointer", {{"ptr", ptr.debug_string()}});
      continue;
    }
    const StructuralType *ptr_type = r.get_type_of(ptr);
    TREX_CHECK(ptr_type != nullptr,
               "AggregateTypes::to_structural_types: missing structural type for base pointer");
    if (!ptr_type->pointer_to.has_value()) {
      // Upstream uses unwrap() here too; we surface a clear error.
      TREX_CHECK(false,
                 "AggregateTypes::to_structural_types: base pointer has no pointee (was the base not a pointer?)");
    }
    Index b_tyidx = *ptr_type->pointer_to;

    if (aggrtype.kind == AggrType::Kind::Struct) {
      if (aggrtype.member_sizes.empty()) {
        log::info("TODO: Invalid member_sizes. Is empty.",
                  {{"ptr", ptr.debug_string()}});
                      } else {
                    r.convert_to_struct(b_tyidx, aggrtype.member_sizes,
                                        aggrtype.has_unsized_array_at_end);
                }
    } else {
      r.convert_to_array(b_tyidx, aggrtype.member_size);
    }
  }

  // Second pass: mark types as equal for every constraint that points into a
  // recovered aggregate.
  for (const auto &[constraint, _reason] : colocated->constraints.iter()) {
    if (constraint.kind == Constraint::Kind::OffsetDeref) {
      const ssa::Variable &t = constraint.t;
      const int64_t offset = constraint.offset;
      const ssa::Variable &base_ptr = constraint.base_ptr;

      if (!constraints.contains_key(base_ptr)) {
        continue;
      }
      if (base_ptr.kind == ssa::Variable::Kind::ConstantValue) {
        log::info("TODO: Constant as base pointer for offset deref",
                  {{"base_ptr", base_ptr.debug_string()}});
        continue;
      }
      TREX_CHECK(offset >= 0, "AggregateTypes::to_structural_types: non-negative offset expected");
      if (offset == 0) {
        // XXX: Is this reasonable?
        continue;
      }

      const uint64_t offset_u64 = static_cast<uint64_t>(offset);
      std::optional<Index> t_tyidx = r.get_type_index(t);
      if (!t_tyidx.has_value()) {
        continue;
      }
      const StructuralType *b_type = r.get_type_of(base_ptr);
      TREX_CHECK(b_type != nullptr && b_type->pointer_to.has_value(),
                 "AggregateTypes::to_structural_types: missing base ptr pointee for offset deref");
      Index b_tyidx = *b_type->pointer_to;
      const StructuralType *b_ty = r.get_type_from_index(b_tyidx);
      TREX_CHECK(b_ty != nullptr,
                 "AggregateTypes::to_structural_types: pointee type not found in container");
      auto cs_it = b_ty->colocated_struct_fields.find(offset_u64);
      if (cs_it != b_ty->colocated_struct_fields.end()) {
        r.mark_types_as_equal(*t_tyidx, cs_it->second);
      } else {
        log::debug("Could not find colocated struct field with offset in type of base-pointer",
                   {{"offset", offset_u64},
                    {"base_ptr", base_ptr.debug_string()}});
      }
    } else {
      // NonConstantOffsetDeref
      const ssa::Variable &t = constraint.t;
      const ssa::Variable &base_ptr = constraint.base_ptr;

      if (!constraints.contains_key(base_ptr)) {
        continue;
      }
      if (base_ptr.kind == ssa::Variable::Kind::ConstantValue) {
        log::info("TODO: Constant as base pointer for non-constant offset deref",
                  {{"base_ptr", base_ptr.debug_string()}});
        continue;
      }

      std::optional<Index> t_tyidx = r.get_type_index(t);
      if (!t_tyidx.has_value()) {
        continue;
      }
      const StructuralType *b_type = r.get_type_of(base_ptr);
      TREX_CHECK(b_type != nullptr && b_type->pointer_to.has_value(),
                 "AggregateTypes::to_structural_types: missing base ptr pointee for non-constant deref");
      Index b_tyidx = *b_type->pointer_to;
      const StructuralType *b_ty = r.get_type_from_index(b_tyidx);
      TREX_CHECK(b_ty != nullptr,
                 "AggregateTypes::to_structural_types: pointee type not found in container");

      // Mirror upstream's match on `(b_ty.observed_array, b_ty.colocated_struct_fields.iter().rev().next())`.
      // Note that `std::map` iterates in ascending key order; `.iter().rev().next()` therefore
      // gives the largest offset, which is the last field of the struct (the one with the
      // trailing array member, if any).
      Index o_tyidx;
      bool got = false;
      if (!b_ty->observed_array) {
        if (!b_ty->colocated_struct_fields.empty()) {
          // Largest offset in the std::map (= last in iteration order) is the last field.
          auto it_last = b_ty->colocated_struct_fields.rbegin();
          o_tyidx = it_last->second;
          got = true;
        } else {
          log::debug("TODO: Non array being used as array? Unclear implications.",
                     {{"base_ptr", base_ptr.debug_string()}});
          o_tyidx = b_tyidx;
          got = true;
        }
      } else {
        if (b_ty->colocated_struct_fields.empty()) {
          o_tyidx = b_tyidx;
          got = true;
        } else {
          log::debug(
              "NonConstantOffsetDeref constraint on base that is array and struct. Unclear implications. Using last field as array.",
              {{"base_ptr", base_ptr.debug_string()}});
          auto it_last = b_ty->colocated_struct_fields.rbegin();
          o_tyidx = it_last->second;
          got = true;
        }
      }
      (void)got;
      r.mark_types_as_equal(*t_tyidx, o_tyidx);
    }
  }

  r.canonicalize_indexes();
  return r;
}

} // namespace trex