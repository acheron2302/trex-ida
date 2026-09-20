// C types — port of upstream `third_party/trex/trex/src/c_types.rs`.
//
// Faithfulness:
//   * `BuiltIn` variants in upstream declaration order; declaration order = discriminant
//     order, since the port's hashing/equality/comparison logic across the analysis
//     pipeline relies on this matching the Rust `derive(PartialOrd, Ord, ...)` output
//     exactly.
//   * `CType` is a plain struct with a `kind` discriminant plus all payload fields, so
//     structural-equality (`operator==`) compares `kind` then every payload field in
//     upstream declaration order — matching Rust's derived impl.
//   * `STypes`, `CTypes`, and the helpers are transcribed verbatim. The three helpers
//     `structural_types_for_all_primitive_c_types`, `undefineds_to_integers_map`, and
//     `signed_unsigned_collapse_target` are at file scope in the `trex::c_types`
//     namespace, exactly as the type_rounding module calls them.
//
//   * The `update_structural` free function uses
//     `trex::with_FORCE_CLONE_AND_JOIN_INSTEAD_OF_DIRECT_SCHEDULE_set` and
//     `trex::with_FORCE_UPPER_BOUND_TO_BE_MAX_INSTEAD_OF_MIN_WHEN_JOINING_set` from
//     `structural.hpp`, exactly as upstream uses its `with_*_set` helpers.

#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <trex/containers.hpp>
#include <trex/joinable_container.hpp>
#include <trex/structural.hpp>

namespace trex {

// ---------------------------------------------------------------------------
// BuiltIn — C built-ins. Note: the `undefined*` variants are not real C built-ins;
// they exist to represent types with only their size known.
// ---------------------------------------------------------------------------

/// C built-ins. Order matches upstream `enum BuiltIn` exactly (declaration order is
/// discriminant order, used by the analysis pipeline's hashing/equality/comparison).
enum class BuiltIn : uint8_t
{
  Void = 0,
  Bool,
  Char,
  UChar,
  WCharT,
  /// Not actually a C-type, but `short short int` represents a `signed char` that also
  /// has integer operations occurring on it, rather than only character operations.
  ShortShort,
  /// Not actually a C-type, but `unsigned short short int` represents an `unsigned
  /// char` that also has integer operations occurring on it.
  UShortShort,
  Short,
  UShort,
  Int,
  Uint,
  Long,
  ULong,
  /// Not actually a C-type, but represents a signed 128 bit integer.
  SInt128,
  /// Not actually a C-type, but represents an unsigned 128 bit integer.
  UInt128,
  /// Not actually a C-type, but represents a signed 256 bit integer.
  SInt256,
  /// Not actually a C-type, but represents an unsigned 256 bit integer.
  UInt256,
  Float,
  Double,
  LongDouble,
  /// An unsized undefined type.
  Undefined,
  /// A 1-byte undefined type.
  Undefined1,
  /// A 2-byte undefined type.
  Undefined2,
  /// A 4-byte undefined type.
  Undefined4,
  /// A 8-byte undefined type.
  Undefined8,
  // NOTE: Make sure to extend `all_builtins` when this is extended.
};

/// Returns the canonical name of the Rust `Debug` formatting for `b`, i.e. the variant
/// name as a PascalCase identifier ("Void", "Int", "SInt128", etc.). Matches upstream's
/// `format!("{:?}", b)`, which is what the `sign_normalized_c_primitives` and
/// `structural_types_for_all_primitive_c_types` helpers consume.
std::string builtin_debug_name(BuiltIn b);

/// All built-ins. Returns a `std::vector` in upstream declaration order. The order is
/// load-bearing because `structural_types_for_all_primitive_c_types` enumerates them in
/// this order, and `std::vector` iteration order equals upstream `into_iter()` order.
std::vector<BuiltIn> all_builtins();

/// Convert to a printable C name (upstream `BuiltIn::to_printable`).
std::string builtin_to_printable(BuiltIn b);

// ---------------------------------------------------------------------------
// CType — a representation of C-like types.
// ---------------------------------------------------------------------------

/// A representation of C-like types. References to other types are done through naming
/// (the key in `CTypes::ctypes`); recursion is factored out of this enum and handled
/// by the external `CTypes` container.
struct CType
{
  enum class Kind : uint8_t
  {
    BuiltIn = 0,
    Union,
    Struct,
    TypeDef,
    Pointer,
    Enum,
    FixedSizeArray,
    UnsizedArray,
    Code,
  };

  Kind kind = Kind::BuiltIn;

  // BuiltIn
  BuiltIn builtin = BuiltIn::Void;

  // Union: Vec<String> of referenced type names.
  std::vector<std::string> union_members;

  // Struct: Vec<(offset, type_name)>.
  std::vector<std::pair<size_t, std::string>> struct_fields;

  // TypeDef: name of the aliased type.
  std::string typedef_target;

  // Pointer: (size, pointee type name).
  size_t pointer_size = 0;
  std::string pointer_target;

  // Enum: (size, set of allowed values).
  size_t enum_size = 0;
  std::vector<int32_t> enum_values;

  // FixedSizeArray: (element type name, element size, number of elements).
  std::string fixed_array_elem;
  size_t fixed_array_elem_size = 0;
  size_t fixed_array_count = 0;

  // UnsizedArray: element type name.
  std::string unsized_array_elem;

  // Constructors
  static CType make_builtin(BuiltIn b) noexcept;
  static CType make_union(std::vector<std::string> members);
  static CType make_struct(std::vector<std::pair<size_t, std::string>> fields);
  static CType make_typedef(std::string target);
  static CType make_pointer(size_t sz, std::string target);
  static CType make_enum(size_t sz, std::vector<int32_t> values);
  static CType make_fixed_array(std::string elem, size_t elem_sz, size_t count);
  static CType make_unsized_array(std::string elem);
  static CType make_code() noexcept;
  friend bool operator==(const CType &a, const CType &b);
  friend bool operator!=(const CType &a, const CType &b) { return !(a == b); }
  friend bool operator<(const CType &a, const CType &b);
};

// ---------------------------------------------------------------------------
// STypes — structural types equivalent to the relevant CTypes.
// ---------------------------------------------------------------------------

/// Structural types equivalent to the relevant [`CTypes`] this was converted from.
struct STypes
{
  /// Names for each structural type.
  unordered::UnorderedMap<std::string, Index> type_map;
  /// The structural types themselves.
  Container<StructuralType> types;
};

// ---------------------------------------------------------------------------
// Free helpers (upstream `c_types::is_undefined_padding`, etc.)
// ---------------------------------------------------------------------------

/// Returns `true` if `s` has only its upper bound set to 1 and nothing else (this is
/// the "undefined padding" marker used by struct member accounting).
bool is_undefined_padding(const StructuralType &s);

/// Construct the canonical "undefined padding" `StructuralType`.
StructuralType get_undefined_padding();

/// Update the structural types with the information encoded by the `CType` named `name`.
/// Returns `true` if initialization completed; `false` if it was postponed because one
/// or more referenced names had not yet been initialised.
bool update_structural(const CType &ctype,
                       const std::string &name,
                       STypes &stypes,
                       const unordered::UnorderedSet<std::string> &completed);

// ---------------------------------------------------------------------------
// CTypes — a collection of CType keyed by name.
// ---------------------------------------------------------------------------

/// A collection of [`CType`]s.
struct CTypes
{
  unordered::UnorderedMap<std::string, CType> ctypes;

  /// Convert c-like types to structural types. Mirrors upstream `CTypes::to_structural`.
  STypes to_structural() const;
};

// ---------------------------------------------------------------------------
// Helpers consumed by `type_rounding` (and the rest of the pipeline).
//
// These are at file scope in `trex::c_types` so other modules — type_rounding, the
// tests, the plugin — can call them without going through a class. This matches the
// intent of upstream `pub fn` items that live outside `impl CTypes`.
// ---------------------------------------------------------------------------

namespace c_types {

/// Structural types equivalent to all primitive C types. Mirrors upstream
/// `structural_types_for_all_primitive_c_types`. Note that this also includes `code`
/// and the `undefined`s, but does not include `void` or `wchar_t`. If type rounding is
/// not allowed on `upper_bound_size`, then the upper-bound-size-only `undefined` is
/// also skipped here (the copy-sized `undefined1`, `undefined2`, ..., are kept).
std::pair<std::vector<std::string>, std::vector<StructuralType>>
structural_types_for_all_primitive_c_types();

/// Map from `Debug` spelling of each `UndefinedN` to the `Debug` spelling of the most
/// likely C integer-like type at that size. Mirrors the literal table in upstream
/// `type_rounding.rs` lines 33-39. Used by `round_up_to_c_types` when
/// `CONFIG.round_up_undefined_n_to_integer` is set.
std::map<std::string, std::string> undefineds_to_integers_map();

/// Map from signed/unsigned integer `Debug` spellings to their canonical
/// (preferred) counterpart, used by `round_up_to_c_types` to force a collapse
/// whenever the type is an exact union of the two. Mirrors the literal table in
/// upstream `type_rounding.rs` lines 79-85. The keys are the "from" side; the
/// value is the canonical one to collapse to.
std::map<std::string, std::string> signed_unsigned_collapse_target();

/// Map from C primitives to their sign-ignored (i.e. sign-normalized) primitive.
/// Mirrors upstream `sign_normalized_c_primitives`.
std::map<std::string, std::string> sign_normalized_c_primitives();

} // namespace c_types

} // namespace trex