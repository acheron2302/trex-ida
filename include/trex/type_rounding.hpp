// Type rounding - port of upstream `trex/src/type_rounding.rs`.
//
// The pass "rounds up" a `Container<StructuralType>` to a set of allowed
// primitive types. The output for each type is the union of allowed
// primitives that together cover all of its capabilities, plus any
// `Padding` entries required to cover copy/upper-bound sizes that no
// primitive matches.
//
// `RoundedIdx` is the index of one selected primitive (or one padding
// entry) in the rounded result. `round_up` performs the rounding; the
// public wrapper `round_up_to_c_types` uses the standard C primitive set
// and applies the two CONFIG-driven rewrites:
//   - `round_up_undefined_n_to_integer`: an undefined-N-rounded type is
//     replaced with the most likely integer at that size.
//   - `collapse_union_of_signed_and_unsigned_ints`: a union of an
//     exact signed/unsigned pair collapses to the canonical one.

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <trex/containers.hpp>
#include <trex/joinable_container.hpp>
#include <trex/ssa.hpp>
#include <trex/structural.hpp>

namespace trex {

// ---------------------------------------------------------------------------
// RoundedIdx
//
// One entry in the per-type rounded result: either a reference to one of
// the `allowed_primitives` (`Primitive`) or a padding byte count used when
// the primitive set can't cover all observed copy/upper-bound sizes
// (`Padding`). The display form is `"<name>"` for primitive and
// `"padding[N]"` for padding.
//
// Upstream uses an enum with two variants carrying payloads; the port
// keeps `kind` plus the payload fields.
// ---------------------------------------------------------------------------
struct RoundedIdx
{
  enum class Kind : uint8_t
  {
    Primitive = 0,
    Padding,
  };

  Kind kind = Kind::Padding;

  // Primitive
  size_t primitive_idx = 0;
  std::string name;

  // Padding
  size_t padding_bytes = 0;

  RoundedIdx() = default;

  static RoundedIdx primitive(size_t idx, std::string n)
  {
    RoundedIdx r;
    r.kind = Kind::Primitive;
    r.primitive_idx = idx;
    r.name = std::move(n);
    return r;
  }
  static RoundedIdx padding(size_t bytes)
  {
    RoundedIdx r;
    r.kind = Kind::Padding;
    r.padding_bytes = bytes;
    return r;
  }

  /// Mirrors upstream `impl Display for RoundedIdx`.
  std::string to_string() const;

  friend bool operator==(const RoundedIdx &a, const RoundedIdx &b)
  {
    if (a.kind != b.kind)
      return false;
    if (a.kind == Kind::Primitive) {
      return a.primitive_idx == b.primitive_idx && a.name == b.name;
    }
    return a.padding_bytes == b.padding_bytes;
  }
  friend bool operator!=(const RoundedIdx &a, const RoundedIdx &b) { return !(a == b); }
  friend bool operator<(const RoundedIdx &a, const RoundedIdx &b)
  {
    if (a.kind != b.kind)
      return (uint8_t)a.kind < (uint8_t)b.kind;
    if (a.kind == Kind::Primitive) {
      if (a.primitive_idx != b.primitive_idx)
        return a.primitive_idx < b.primitive_idx;
      return a.name < b.name;
    }
    return a.padding_bytes < b.padding_bytes;
  }
};

// ---------------------------------------------------------------------------
// Public functions
// ---------------------------------------------------------------------------

/// Perform a rounding up on structural types to C types. Convenience wrapper
/// around `round_up` which gives more control.
void round_up_to_c_types(Container<StructuralType> &stypes);

/// Round single union-of-C-primitives structural type up to C types.
/// Returns a BTreeSet (`std::set`) of name strings (`Primitive` → name,
/// `Padding` → `"padding[N]"`).
std::set<std::string> recognize_union_of_c_primitives(const StructuralType &stype);

/// Perform minimal "rounding up" of the structural types in `stypes`, such
/// that all primitives in it are either those provided in
/// `allowed_primitives`, or are unions of them.
///
/// The return type is a map from indexes in `stypes` to a rounded-up
/// structural type and sets of indexes into `allowed_primitives`, which
/// specify which primitives need to be union'd together to get the
/// necessary primitive.
IndexMap<std::pair<StructuralType, unordered::UnorderedSet<RoundedIdx>>>
round_up(const Container<StructuralType> &stypes,
         const std::vector<StructuralType> &allowed_primitives,
         const std::vector<std::string> &allowed_primitives_names);

} // namespace trex