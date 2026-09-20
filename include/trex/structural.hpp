#pragma once

// Structural types - port of upstream `trex/src/structural.rs`.
//
// Notes on module placement:
//  * `Padding` lives here (upstream defines it in aggregate_types.rs) because
//    `StructuralTypes::convert_to_struct` consumes it and C++ has no module cycles.
//  * `StructuralTypes::serialize` and `generate_dot`/`write_dot` are free functions in
//    serialize_structural.hpp / here respectively (upstream defines them in an inherent impl).

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <trex/il.hpp>
#include <trex/joinable_container.hpp>
#include <trex/ssa.hpp>
#include <trex/dynamic_variable.hpp>

namespace trex {

//--------------------------------------------------------------------------
// Operation tags observed on types
//--------------------------------------------------------------------------
/// Integer operations. Declaration order matches upstream.
enum class IntegerOp : uint8_t
{
  Add = 0,
  Sub,
  Mult,
  UDiv,
  SDiv,
  URem,
  SRem,
  And,
  Or,
  Xor,
  Eq,
  Neq,
  ULt,
  SLt,
  UCarry,
  SCarry,
  SBorrow,
  OnesComplement,
  TwosComplement,
  Popcount,
  ZeroExtendSrc,
  SignExtendSrc,
  ZeroExtendTgt,
  SignExtendTgt,
  LeftShift,
  URightShift,
  SRightShift,
  ShiftAmount,
  ConvertToFloat,
  ConvertFromFloatTrunc,
};

/// Boolean operations. Declaration order matches upstream.
enum class BooleanOp : uint8_t
{
  Negate = 0,
  And,
  Or,
  Xor,
};

/// Floating-point operations. Declaration order matches upstream.
enum class FloatOp : uint8_t
{
  Add = 0,
  Sub,
  Mult,
  Div,
  Eq,
  Neq,
  Lt,
  LEq,
  Sqrt,
  Abs,
  Neg,
  Ceil,
  Floor,
  Round,
  ConvertFromInt,
  ConvertToIntTrunc,
  ConvertFromDifferentSizedFloat,
  ConvertToDifferentSizedFloat,
};

const std::vector<IntegerOp> &all_integer_ops();
const std::vector<IntegerOp> &signed_integer_ops();
const std::vector<IntegerOp> &unsigned_integer_ops();
const std::vector<IntegerOp> &all_pointer_integer_ops();
/// Upstream `IntegerOp::char_ops(signed)`.
std::vector<IntegerOp> char_integer_ops(bool is_signed);
/// None: both signed and unsigned; Some(true): signed only; Some(false): unsigned only.
std::optional<bool> is_signed_op(IntegerOp op);

const std::vector<BooleanOp> &all_boolean_ops();
const std::vector<FloatOp> &all_float_ops();

/// Whether an aggregate member is a real value or padding.
enum class Padding : uint8_t
{
  IsValue = 0,
  IsPadding,
};

//--------------------------------------------------------------------------
//StructuralType
//--------------------------------------------------------------------------

/// Forward declaration so `StructuralType::aggregate_size()` can name its return type.
struct AggregateSize;

/// A recovered structural type describing how a particular Variable has been observed to behave.
struct StructuralType
{
  /// The fixed upper bound to the size of the type.
  std::optional<size_t> upper_bound_size;
  /// Observed (interpretation-oblivious) copying operations of these sizes in bytes.
  std::set<size_t> copy_sizes;
  /// Observed to be compared against zero.
  bool zero_comparable = false;
  /// Observed to dereference to a known type.
  std::optional<Index> pointer_to;
  /// Observed to be a boolean.
  bool observed_boolean = false;
  /// Observed integer operations and their sizes.
  std::set<std::pair<IntegerOp, size_t>> integer_ops;
  /// Observed boolean operations and their sizes.
  std::set<std::pair<BooleanOp, size_t>> boolean_ops;
  /// Observed floating operations and their sizes.
  std::set<std::pair<FloatOp, size_t>> float_ops;
  /// Observed to be code.
  bool observed_code = false;
  /// Observed to have co-located struct fields (this type refers to the field at offset 0).
  /// Keys are non-zero offsets, values are type indexes.
  std::map<uint64_t, Index> colocated_struct_fields;
  /// Observed to be an array (this type refers to members).
  bool observed_array = false;
  /// The rest of the structural type must be ignored if set (IL-constant variable type).
  bool is_type_for_il_constant_variable = false;

  /// Get the observed size of this type, if one can be determined.
  std::optional<size_t> observed_size() const;

  /// Set the upper bound size. Returns false if the type already had a smaller/larger bound that
  /// conflicts (see upstream for the exact rule).
  bool set_upper_bound_size(size_t size);

  /// Get the currently observed aggregate size (in bytes); for a type with colocated fields this
  /// combines all field sizes. `fuel` guards against infinitely-recursive types: pass nullopt for
  /// the default (10).
  std::optional<AggregateSize> aggregate_size(const Container<StructuralType> &types,
                                              std::optional<size_t> fuel) const;

  /// Upstream `Joinable::join`: nullopt == Ok (other was consumed), a value == Err(Self) (the
  /// caller puts the returned object back).
  std::optional<StructuralType> join(StructuralType other, DelayedJoiner &delayed_joiner);

  /// Upstream `Joinable::refers_to`.
  std::vector<Index> refers_to() const;
  /// Upstream `Joinable::refers_to_mut`.
  std::vector<Index *> refers_to_mut();

  friend bool operator==(const StructuralType &a, const StructuralType &b);

  std::string debug_string() const;
};

/// The aggregate size of a type.
struct AggregateSize
{
  enum class Kind : uint8_t
  {
    Definite = 0,
    IndefiniteStructLowerBoundedBy,
    IndefiniteArrayWithElementSize,
    IndefiniteOutOfFuel,
  };

  Kind kind = Kind::Definite;
  size_t value = 0;

  static AggregateSize definite(size_t n);
  static AggregateSize indefinite_struct_lower_bounded_by(size_t n);
  static AggregateSize indefinite_array_with_element_size(size_t n);
  static AggregateSize indefinite_out_of_fuel();

  friend bool operator==(const AggregateSize &a, const AggregateSize &b)
  {
    return a.kind == b.kind && a.value == b.value;
  }
  friend bool operator!=(const AggregateSize &a, const AggregateSize &b) { return !(a == b); }

  /// Compare two aggregate sizes; nullopt if either ran out of fuel.
  std::optional<int> cmp_with_indefinite_as_infinity(const AggregateSize &other) const;

  std::string debug_string() const;
};

//--------------------------------------------------------------------------
// StructuralTypes
//--------------------------------------------------------------------------

/// A collection of structural types, keyed by SSA variable.
class StructuralTypes
{
public:
  /// A map from locations to type indices.
  std::map<ssa::Variable, Index> type_map;
  /// A collection of the actual structural types.
  Container<StructuralType> types;
  /// The SSA IR used to find the structural types.
  std::shared_ptr<const ssa::SSA> ssa;

  /// Create a new, empty collection of structural types.
  explicit StructuralTypes(std::shared_ptr<const ssa::SSA> ssa_);

  Container<StructuralType> &types_ref() { return types; }
  const Container<StructuralType> &types_ref() const { return types; }

  // ---------------------------------------------------------------- capability_*

  /// A dereference is seen at `v`.
  void capability_deref(ssa::Variable v, size_t pointer_size, ssa::Variable deref_v, size_t deref_size);
  /// A comparison of `size` bytes against zero is seen at `v`.
  void capability_compared_against_zero(ssa::Variable v, size_t size);
  /// A phi-node merge for `from_v` into `v` was observed.
  void capability_phi_node(ssa::Variable v, ssa::Variable from_v);
  /// A copy of value from `from_v` is seen into `v`.
  void capability_copied_from(ssa::Variable v, ssa::Variable from_v, size_t size);
  /// All variables in `gvn_set` belong to the same type.
  void capability_gvn_congruent(const std::vector<ssa::Variable> &gvn_set);
  /// `v` has been seen to behave like a boolean.
  void capability_known_boolean(ssa::Variable v);
  /// `v` has been seen to have a boolean operation `op`.
  void capability_boolean_op(ssa::Variable v, BooleanOp op, size_t size);
  /// `v` has been seen to have an integer operation `op`.
  void capability_integer_op(ssa::Variable v, IntegerOp op, size_t size);
  /// `v` has been seen to have a float operation `op`.
  void capability_float_op(ssa::Variable v, FloatOp op, size_t size);
  /// `v` is observed to be a pointer to code.
  void capability_pointer_to_code(ssa::Variable v);
  /// `v1` and `v2` are observed to be the same type.
  void capability_have_same_type(ssa::Variable v1, ssa::Variable v2);

  // ---------------------------------------------------------------- bulk passes

  void propagate_pointerness_through_arithmetic_constraints();
  void canonicalize_indexes();

  // ---------------------------------------------------------------- queries

  std::optional<Index> get_type_index(const ssa::Variable &location) const;
  const StructuralType *get_type_from_index(Index idx) const;
  const StructuralType *get_type_of(const ssa::Variable &v) const;

  /// Upstream `StructuralTypes::deep_clone`.
  StructuralTypes deep_clone() const;

  // ---------------------------------------------------------------- conversions

  void convert_to_struct(Index idx,
                         const std::vector<std::pair<size_t, Padding>> &member_sizes,
                         bool has_unsized_array_at_end);
  void convert_to_array(Index idx, size_t member_element_size);
  void mark_types_as_equal(Index idx1, Index idx2);

  /// Whether the types at the two indexes are the same object (upstream `are_equal_at_indexes`,
  /// which is compiled only for tests upstream; kept here because the tests and the report use it).
  bool are_equal_at_indexes(Index a, Index b) const;

  std::string debug_string() const;

private:
  /// Helper: type index for `v`, creating a default type if necessary.
  Index get_typ_idx_or_default(const ssa::Variable &v);
  /// Helper: the `pointer_to` index of `typ_idx`, creating a default type if necessary.
  Index get_pointer_to_or_default(Index typ_idx);
  /// (Internal only) The two variables were observed to have the same type.
  void observed_same_type(ssa::Variable v1, ssa::Variable v2);
};

/// Upstream `StructuralTypes::generate_dot` (writes a GraphViz description of the types).
std::string generate_dot(const StructuralTypes &types, std::optional<size_t> only_il_addr);
/// Upstream `StructuralTypes::write_dot`.
void write_dot(const StructuralTypes &types, const std::string &path, std::optional<size_t> only_il_addr);

/// Upstream `get_equivalent_index_with_restricted_aggregate_size`: returns an index whose type's
/// aggregate size is bounded by `upper_bound_size`, inserting a chopped copy when necessary.
/// Implemented in `src/trex/structural_serialize.cpp` (only serialization uses it).
Index get_equivalent_index_with_restricted_aggregate_size(
    IndexMap<std::map<size_t, Index>> &restriction_map_cache,
    Container<StructuralType> &types,
    Index idx,
    size_t upper_bound_size,
    const Program &program);

/// Debug/display helpers used by error messages and the plugin report.
std::string to_string(IntegerOp op);
std::string to_string(BooleanOp op);
std::string to_string(FloatOp op);
std::string to_string(Padding pad);

// --------------------------------------------------------------------------
// The two `dynamic_variable!` flags that upstream `structural.rs` declares.
//
// They are process-global flags (single-threaded port of upstream's
// `thread_local!`); the structural-type join step checks them to decide
// whether to use direct joining or clone-and-join, and whether the upper
// bound is the min or max of the two. The instances themselves live in
// `structural.cpp`; only the extern declarations and the RAII helpers
// belong in the header.
// --------------------------------------------------------------------------

/// Upstream `FORCE_CLONE_AND_JOIN_INSTEAD_OF_DIRECT_SCHEDULE` (the flag itself).
extern ::trex::dynamic_variable::DynamicVariable
    FORCE_CLONE_AND_JOIN_INSTEAD_OF_DIRECT_SCHEDULE;
/// Upstream `FORCE_UPPER_BOUND_TO_BE_MAX_INSTEAD_OF_MIN_WHEN_JOINING`.
extern ::trex::dynamic_variable::DynamicVariable
    FORCE_UPPER_BOUND_TO_BE_MAX_INSTEAD_OF_MIN_WHEN_JOINING;

/// Upstream `with_FORCE_CLONE_AND_JOIN_INSTEAD_OF_DIRECT_SCHEDULE_set` — run `f`
/// with the flag flipped on for the duration of the call.
template <typename F>
auto with_FORCE_CLONE_AND_JOIN_INSTEAD_OF_DIRECT_SCHEDULE_set(F &&f)
{
  return ::trex::dynamic_variable::with_var_set(
      FORCE_CLONE_AND_JOIN_INSTEAD_OF_DIRECT_SCHEDULE, std::forward<F>(f));
}
/// Upstream `with_FORCE_UPPER_BOUND_TO_BE_MAX_INSTEAD_OF_MIN_WHEN_JOINING_set` —
/// run `f` with the flag flipped on for the duration of the call.
template <typename F>
auto with_FORCE_UPPER_BOUND_TO_BE_MAX_INSTEAD_OF_MIN_WHEN_JOINING_set(F &&f)
{
  return ::trex::dynamic_variable::with_var_set(
      FORCE_UPPER_BOUND_TO_BE_MAX_INSTEAD_OF_MIN_WHEN_JOINING, std::forward<F>(f));
}

} // namespace trex
