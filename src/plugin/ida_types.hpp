#pragma once

// Install the planned TRex types as native IDA local types.
//
// This replaces the text round trip: the types used to be handed to IDA as a C source string and
// re-parsed (once for the whole type library, once per variable). Here the plan's offsets,
// extents and gap members go straight into `tinfo_t`.
//
// `ida_struct` / `add_struc` / `add_struc_member` are not public SDK APIs (they survive only as
// IDAPython `idc` shims, which the SDK itself implements with `udt_type_data_t` +
// `tinfo_t::create_udt()` + `set_named_type()`), so the same `typeinf` API is used directly. It is
// identical in SDK 9.3 and 9.4, so nothing branches on the SDK version.

#include <cstddef>
#include <string>
#include <vector>

#include <typeinf.hpp>

#include "type_plan.hpp"

namespace trexida::ida_types
{

/// What `emit_local_types` did. `failures` names each aggregate that could not be installed.
struct EmitStats
{
  std::size_t created_types = 0;
  std::size_t failed_types = 0;
  std::size_t gap_members = 0;
  std::size_t dropped_members = 0;
  /// Members (or union alternatives) whose TAFLD_GAP flag the kernel rejected: they were added
  /// again as a plain byte array of the same width.
  std::size_t normalized_alternatives = 0;
  std::vector<std::string> failures;
};

/// Install every aggregate in `plan` into the local type library, replacing any previous
/// definition. `til` is the target library (normally get_idati()).
EmitStats emit_local_types(til_t *til, const trexida::plan::TypePlan &plan);

/// Build the tinfo_t for one variable from its planned spelling. `width` is the variable's byte
/// width from the lift; it is what an unsized array or an untypable spelling falls back to.
/// Returns false when nothing could be built.
bool build_variable_type(til_t *til, const trexida::plan::TypePlan &plan,
                         const std::string &spelling, std::size_t width, tinfo_t *out);

} // namespace trexida::ida_types