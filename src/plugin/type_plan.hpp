#pragma once

// Plan the native IDA local types a finished TRex run must install.
//
// Everything that decides a member's offset, its byte extent, whether IDA can represent it at
// all, and in which order the aggregates have to be created lives here — IDA-free and free of any
// text round trip, so it is unit-testable without a database (tests/test_type_plan.cpp).
//
// This replaces the two consumers that used to re-parse `PrintableCTypes::to_string()`: the
// aggregate-sizes helper that lived in a regex-based plugin translation unit and the
// declaration-repair pass beside it. `to_string()` itself stays byte-identical: it is still the
// `.trex.c` export and the differential oracle (scripts/diff_oracle.py).

#include <cstddef>
#include <string>
#include <utility>
#include <vector>

#include <trex/c_type_printer.hpp>
#include <trex/serialize_structural.hpp>

namespace trexida::plan
{

/// One member of one aggregate, as IDA will see it.
struct PlannedMember
{
  std::string name;                 ///< field_<offset-in-decimal> / alt_<i> / gap_<name>
  std::size_t offset = 0;           ///< BYTES
  std::size_t extent = 0;           ///< BYTES the member occupies, including its trailing hole
  std::string type_spelling;        ///< as printed (for the window + the plan report)
  std::string ctype_name;           ///< name in `ctype_at`, or empty when none was stored
  bool is_gap = false;              ///< true => emit a TAFLD_GAP member
  bool is_flexible_array = false;   ///< trailing `T[]` member (nelems == 0)
};

/// One aggregate (struct or union) the plan will install.
struct PlannedAggregate
{
  std::string name;                 ///< tN
  bool is_union = false;
  std::size_t size = 0;             ///< bytes; 0 when unknown
  bool size_known = false;
  std::vector<PlannedMember> members; ///< ascending offset; every union member at 0
};

/// One external variable and the type spelling the printer gave it.
struct PlannedVariable
{
  std::string name;                    ///< `<lvar>@<func>@<entry-hex>`, as the printer stores it
  std::string spelling;                ///< as printed
  bool has_type_info = true;           ///< false => not applied, counted as `no_type_info`
};

/// The whole plan: every aggregate in creation (dependency) order, plus the variables.
struct TypePlan
{
  std::vector<PlannedAggregate> aggregates;
  std::vector<PlannedVariable> variable_types;
  std::size_t dropped_members = 0;
  std::size_t gap_members = 0;
};

/// True when a variable spelling carries no type information — the rule run_apply() has always
/// applied (plugin.cpp:1285-1286): an empty spelling, `void` (an empty rounded set), or TRex's
/// `undefined*` / `padding*` placeholders. Such a variable keeps IDA's own type.
bool has_type_information(const std::string &spelling);

/// Build the plan from a finished run. `pointer_size` comes from the pipeline
/// (`program->pointer_size`), never a hardcoded 8.
TypePlan build_plan(const trex::SerializableStructuralTypes<trex::ExternalVariable> &stypes,
                    const trex::PrintableCTypes<trex::ExternalVariable> &printer,
                    std::size_t pointer_size);

} // namespace trexida::plan