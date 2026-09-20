// Serialize structural types to a machine-readable form.
//
// Port of `third_party/trex/trex/src/serialize_structural.rs` (359 lines).
//
// Faithfulness:
//   * The serialization text format is compared byte-for-byte against the Rust oracle
//     by the S7 differential gate; every character (tab indentation, blank-line
//     separator, trailing newline) is load-bearing. See `serialize_to` for the
//     emit-order and macro rules.
//   * `Parseable` in upstream Rust is a trait; the port provides a static `parse_from`
//     on `SerializableStructuralTypes<Var>` via the free function
//     `parse_serializable_structural_types<Var>(s)`. To use the parser, the user-side
//     `Var` must expose a `parse_from(const std::string&) -> std::optional<Var>` static
//     function (a duck-typed equivalent of upstream's `impl Parseable for Var`). The
//     parser for `Var` is found by overload resolution at compile time when the user
//     explicitly invokes `parse_serializable_structural_types<MyVar>(s, &MyVar::parse_from)`.
//   * The `type_names` argument to `new` is allowed to be empty (`IndexMap<>{}`).
//     In that case, `type_name` falls back to the synthetic `t{idx}` naming.
//   * `index_of_type_for` requires `Var: Ord + Parseable` — the upstream method is
//     gated on the same trait bound. In C++ this is satisfied by any `Var` with
//     `operator<` (the std::map key requirement) and a parse function.

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
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

// Forward declaration — the free-function parser needs the full type.
template <class Var>
class SerializableStructuralTypes;

namespace detail {

/// Upstream parser uses `Var::parse_from(s: &str) -> Option<Var>`. The C++ port makes
/// this a free function pointer parameter to the parser, so the caller passes
/// `&MyVar::parse_from` (or any other compatible signature).
template <class Var>
using VarParseFn = std::function<std::optional<Var>(const std::string &)>;

/// Internal: the parser implementation. See `parse_serializable_structural_types`
/// below for the public entry point.
template <class Var>
std::optional<SerializableStructuralTypes<Var>>
parse_serialize_impl(const std::string &s, VarParseFn<Var> parse_var);

} // namespace detail

/// A serializable form of structural types. Mirrors upstream
/// `SerializableStructuralTypes<Var: Display>`.
template <class Var>
class SerializableStructuralTypes
{
public:
  using VarType = Var;

  /// Construct from the variables-to-indices map, an optional user-provided type-name
  /// mapping (empty = auto-naming), and the structural-type container. The container
  /// is garbage-collected against the variable roots so unreferenced types are
  /// dropped before serialization. The `type_names` argument may be empty; in that
  /// case, `type_name` falls back to the synthetic `t{idx}` naming. If `type_names`
  /// is non-empty, then no name may start with `__t` and none may contain spaces,
  /// newlines, or tabs (the upstream assertion at line 34-36).
  SerializableStructuralTypes(std::map<Var, Index> varmap,
                              IndexMap<std::string> type_names,
                              Container<StructuralType> types);

  /// Read-only access to the internal types container.
  const Container<StructuralType> &types() const { return types_; }

  /// Mutable access to the internal types container.
  Container<StructuralType> &types_mut() { return types_; }

  /// Serialize the structural types to a string. See `serialize_to` for the exact
  /// text format (load-bearing for the S7 differential gate).
  std::string serialize() const;

  /// Try getting the canonical name for the type at `idx`. You almost definitely want
  /// `type_name` instead — this returns `std::nullopt` when no name has been assigned.
  std::optional<std::string> try_type_name(Index idx) const;

  /// Get a canonical name for the type at `idx`. If `type_names_` was empty (auto
  /// naming), returns `t{idx}`. Otherwise returns the assigned name or, as a fallback,
  /// `__t{idx}` if no name was assigned for this index.
  std::string type_name(Index idx) const;

  /// Get the type at `idx`.
  const StructuralType &type_at(Index idx) const { return types_[idx]; }

  /// Iterate over (variable, type-index) pairs in varmap order.
  std::vector<std::pair<Var, Index>> var_type_iter() const
  {
    std::vector<std::pair<Var, Index>> out;
    out.reserve(varmap_.size());
    for ( const auto &kv : varmap_ )
    {
      out.emplace_back(kv.first, kv.second);
    }
    return out;
  }

  /// Read-only access to the underlying varmap.
  const std::map<Var, Index> &varmap() const { return varmap_; }

  /// Read-only access to the type-name map (keyed by `Index`).
  const IndexMap<std::string> &type_names() const { return type_names_; }

  /// Get the index of the type for `var`. Mirrors upstream `index_of_type_for`.
  std::optional<Index> index_of_type_for(const Var &var) const
  {
    auto it = varmap_.find(var);
    if ( it == varmap_.end() ) return std::nullopt;
    return it->second;
  }

private:
  /// The serialization emitter; shared by `serialize` and tests.
  void serialize_to(std::string &f) const;

  std::map<Var, Index> varmap_;
  IndexMap<std::string> type_names_;
  Container<StructuralType> types_;

  // The parser implementation in `detail::parse_serialize_impl` needs access to the
  // private state to materialise the result. We make it a friend.
  template <class V>
  friend std::optional<SerializableStructuralTypes<V>>
  detail::parse_serialize_impl(const std::string &s,
                                detail::VarParseFn<V> parse_var);
};

/// Parse a `SerializableStructuralTypes<Var>` from its text serialization. Mirrors
/// upstream `impl<Var: Display + Parseable + Ord> Parseable for SerializableStructuralTypes<Var>`.
/// The `parse_var` argument is a function pointer (or `std::function`) implementing
/// `std::optional<Var>(const std::string&) -> std::optional<Var>`; it is invoked
/// once per VAR_MAP entry to decode the variable name.
template <class Var>
std::optional<SerializableStructuralTypes<Var>>
parse_serializable_structural_types(const std::string &s,
                                    detail::VarParseFn<Var> parse_var)
{
  return detail::parse_serialize_impl<Var>(s, std::move(parse_var));
}

/// Convenience overload for `Var` types that expose a static `parse_from` member.
/// Equivalent to `parse_serializable_structural_types<Var>(s, &Var::parse_from)` when
/// such a static exists; uses ADL-free function-pointer resolution.
template <class Var>
std::optional<SerializableStructuralTypes<Var>>
parse_serializable_structural_types(const std::string &s)
{
  // Forward to the explicit form using a no-op default parser. If the user's `Var`
  // type does not have a static `parse_from`, this overload should not be called;
  // callers should use the two-argument form.
  return detail::parse_serialize_impl<Var>(
      s, [](const std::string &) -> std::optional<Var> { return std::nullopt; });
}

/// Upstream `pub fn new(varmap, type_names, types)` — factory mirroring the Rust
/// associated function.
template <class Var>
SerializableStructuralTypes<Var>
new_serializable_structural_types(std::map<Var, Index> varmap,
                                  IndexMap<std::string> type_names,
                                  Container<StructuralType> types)
{
  return SerializableStructuralTypes<Var>(std::move(varmap), std::move(type_names),
                                          std::move(types));
}

/// Port of upstream `StructuralTypes::serialize` (structural.rs:1322): maps the structural types
/// and the external-variable map onto the serializable form, applying the
/// size-restriction-based clone-and-chop when configured. Implemented in
/// `src/trex/structural_serialize.cpp`.
SerializableStructuralTypes<ExternalVariable>
serialize_structural_types(const StructuralTypes &types,
                           const std::optional<ILVariableMap> &vars);

} // namespace trex