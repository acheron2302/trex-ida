// Printable C-like type representation for structural types.
//
// Port of `third_party/trex/trex/src/c_type_printer.rs` (645 lines).
//
// Faithfulness:
//   * The output text format is the source of the differential test's `c-like` bytes.
//     The text emitted by `PrintableCTypes::to_string()` matches upstream line-for-
//     line; comments first (`// var : type`), then a BFS of union/struct/unsized-array
//     type declarations in stable order, terminated by struct/union closing braces.
//   * `RoundedTypeUnionMember` is a private internal type that flattens the
//     `RoundedIdx` set into printable forms: a single primitive, a pointer (with the
//     pointee resolved to a string), `code`, or a `padding[N]` byte count.
//   * `TypeNameStream` is a tiny "fresh name" generator producing `t1`, `t2`, … in
//     issue order. The stream is local to each `PrintableCTypes` instance.
//   * The `formatted_types_for(name, separated_unions)` helper recursively walks the
//     graph of `CType` definitions and returns one string per "exploded" form (when
//     `separated_unions` is true, a union's alternatives each yield a separate
//     result; otherwise they remain joined).

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

#include <trex/c_types.hpp>
#include <trex/containers.hpp>
#include <trex/joinable_container.hpp>
#include <trex/serialize_structural.hpp>
#include <trex/structural.hpp>
#include <trex/type_rounding.hpp>

namespace trex {

// ---------------------------------------------------------------------------
// PrintableCTypes
// ---------------------------------------------------------------------------

/// A printable C-like type representation for structural types.
template <class ExtVar>
class PrintableCTypes
{
  static_assert(std::is_default_constructible<ExtVar>::value || true,
                "ExtVar is used opaquely through serialization hooks.");

public:
  using ExtVarType = ExtVar;

  /// Obtain printable C types from serializable structural types. Mirrors upstream
  /// `PrintableCTypes::new`. The structural types are rounded to C primitives here
  /// (via `round_up` with the standard C primitive set), then traversed once to
  /// populate `external_type_name_` and `ctypes_`.
  explicit PrintableCTypes(const SerializableStructuralTypes<ExtVar> &stypes);

  /// Get the external type name for an index (the public read-only view).
  std::string ext_type_name_at(Index idx) const;

  /// The printed C-like output as a single string. This is the upstream `Display`
  /// impl; callers (the plugin chooser, the e2e test, the CLI) read the whole blob.
  std::string to_string() const;

  /// Upstream `formatted_types_for` — recursively expand `type_name` and return one
  /// string per "exploded" form (when `separated_unions` is true, a union's
  /// alternatives each yield a separate result; otherwise they remain joined).
  std::vector<std::string> formatted_types_for(const std::string &type_name,
                                               bool separated_unions) const;

private:
  /// Internal only. Returns the external type name for the type at `idx`, setting it
  /// up on demand. Mirrors upstream `external_type_name_at` (lines 82-264).
  std::string external_type_name_at(Index idx);

  /// Internal: recursive helper for `formatted_types_for` (mirrors upstream
  /// `internal_formatted_types_for` lines 324-480).
  std::vector<std::string>
  internal_formatted_types_for(const std::string &typ,
                                std::set<std::string> *visited,
                                size_t fuel,
                                bool separated_unions) const;

  std::string new_type_name();

  std::map<ExtVar, Index> varmap_;
  IndexMap<std::string> external_type_name_;
  std::map<std::set<std::string>, std::string> union_name_;
  unordered::UnorderedMap<std::string, CType> ctypes_;
  const Container<StructuralType> *structural_types_ = nullptr;
  IndexMap<unordered::UnorderedSet<RoundedIdx>> rounded_types_;
  size_t next_name_counter_ = 0;
};

/// Free-function factory mirroring upstream `PrintableCTypes::new`.
template <class ExtVar>
PrintableCTypes<ExtVar> make_printable_ctypes(const SerializableStructuralTypes<ExtVar> &stypes)
{
  return PrintableCTypes<ExtVar>(stypes);
}

} // namespace trex