// Implementation of trexida::ida_types — see ida_types.hpp.
//
// Emission sequence per run:
//   1. a forward declaration for every aggregate, so that every by-name reference below resolves
//      and a self-referential type terminates;
//   2. per aggregate: an anonymous UDT (not a typeref - `calc_udt_aligns` and `set_struct_size`
//      refuse to work on typerefs), its members at the offsets the analysis recovered, and
//      `set_named_type(..., NTF_REPLACE)`.

#include "ida_types.hpp"

// C++/STL FIRST (mirror plugin.cpp): the IDA SDK shadows C library names the STL headers use.
#include <cstddef>
#include <cstdlib>
#include <map>
#include <string>
#include <vector>

#include <typeinf.hpp>

namespace trexida::ida_types
{

namespace
{

using trexida::plan::PlannedAggregate;
using trexida::plan::PlannedMember;
using trexida::plan::TypePlan;

/// The C spellings `builtin_to_printable` produces (c_types.cpp:108) that map onto a stock IDA
/// type. Everything else TRex prints is either an aggregate name, a pointer, an array, one of the
/// `padding[N]` / `code` forms, or a placeholder the planner already turned into a gap.
const std::map<std::string, type_t> &builtin_types()
{
  static const std::map<std::string, type_t> types = {
    { "bool", BTF_BOOL },
    { "char", BTF_CHAR },
    { "unsigned char", BTF_UCHAR },
    // No stock wchar in this SDK's stock_type_id_t; a 16-bit integer is the same storage.
    { "wchar_t", BTF_INT16 },
    { "int8_t", BTF_INT8 },
    { "uint8_t", BTF_UINT8 },
    { "int16_t", BTF_INT16 },
    { "uint16_t", BTF_UINT16 },
    { "int32_t", BTF_INT32 },
    { "uint32_t", BTF_UINT32 },
    { "int64_t", BTF_INT64 },
    { "uint64_t", BTF_UINT64 },
    { "int128_t", BTF_INT128 },
    { "uint128_t", BTF_UINT128 },
    { "float", BTF_FLOAT },
    { "double", BTF_DOUBLE },
    { "long double", BTF_LDOUBLE },
  };
  return types;
}

const PlannedAggregate *find_aggregate(const TypePlan &plan, const std::string &name)
{
  for ( const PlannedAggregate &a : plan.aggregates )
    if ( a.name == name )
      return &a;
  return nullptr;
}

/// `padding[N]` -> N, otherwise 0.
std::size_t padding_width(const std::string &spelling)
{
  const std::string prefix = "padding[";
  if ( spelling.size() <= prefix.size() + 1 || spelling.rfind(prefix, 0) != 0
       || spelling.back() != ']' )
    return 0;
  const std::string digits =
    spelling.substr(prefix.size(), spelling.size() - prefix.size() - 1);
  if ( digits.find_first_not_of("0123456789") != std::string::npos )
    return 0;
  return (std::size_t)strtoull(digits.c_str(), nullptr, 10);
}

/// `T[N]` -> N, otherwise 0 (0 also means "not a fixed array").
std::size_t fixed_array_count(const std::string &spelling, std::string *elem)
{
  if ( spelling.empty() || spelling.back() != ']' )
    return 0;
  const size_t open = spelling.find('[');
  if ( open == std::string::npos )
    return 0;
  const std::string digits = spelling.substr(open + 1, spelling.size() - open - 2);
  if ( digits.empty() || digits.find_first_not_of("0123456789") != std::string::npos )
    return 0;
  *elem = spelling.substr(0, open);
  return (std::size_t)strtoull(digits.c_str(), nullptr, 10);
}

/// A byte blob of `width` bytes - the only remaining "we know the size but not the type".
bool byte_array(std::size_t width, tinfo_t *out)
{
  out->create_array(tinfo_t(BTF_BYTE), (uint32)(width != 0 ? width : 1));
  return true;
}

/// Resolve a bare aggregate name (no pointer, no array) to an unresolved typeref. `resolve=false`
/// keeps it a reference, which is what lets mutually referential structs terminate.
bool resolve_aggregate(til_t *til, const TypePlan &plan, const std::string &name, tinfo_t *out)
{
  const PlannedAggregate *agg = find_aggregate(plan, name);
  if ( agg == nullptr )
    return false;
  return out->get_named_type(til, name.c_str(),
                             agg->is_union ? BTF_UNION : BTF_STRUCT, /*resolve=*/false);
}

/// Resolve one spelling into `out`. `width` is only consulted for the forms whose length is not
/// written in the spelling: `T[]` and anything that ends up unknown.
bool resolve_spelling(til_t *til, const TypePlan &plan, const std::string &spelling,
                      std::size_t width, tinfo_t *out)
{
  if ( spelling.empty() || spelling == "void" )
    return false;

  // `padding[N]`: exactly N bytes, whatever the surrounding members look like.
  if ( const std::size_t n = padding_width(spelling); n != 0 )
    return byte_array(n, out);

  // Pointers: strip the stars, resolve the base, and rebuild one pointer per star. A base that is
  // `code` (Ghidra's executable-code type) or a name that is not a planned aggregate becomes
  // `void*` - a pointer stays a pointer whatever it points at.
  if ( spelling.back() == '*' )
  {
    std::string base = spelling;
    std::size_t stars = 0;
    while ( !base.empty() && base.back() == '*' )
    {
      base.pop_back();
      ++stars;
    }
    while ( !base.empty() && base.back() == ' ' )
      base.pop_back();

    tinfo_t pointee;
    bool resolved = false;
    if ( base != "code" && base != "void" )
    {
      std::string elem;
      if ( fixed_array_count(base, &elem) != 0 )
        resolved = resolve_spelling(til, plan, elem, 0, &pointee);
      else if ( base.size() > 2 && base.compare(base.size() - 2, 2, "[]") == 0 )
        resolved = resolve_spelling(til, plan, base.substr(0, base.size() - 2), 0, &pointee);
      else if ( resolve_aggregate(til, plan, base, &pointee) )
        resolved = true;
      else if ( auto it = builtin_types().find(base); it != builtin_types().end() )
      {
        pointee = tinfo_t(it->second);
        resolved = true;
      }
    }
    if ( !resolved )
      pointee = tinfo_t(BTF_VOID);
    for ( std::size_t i = 0; i < stars; ++i )
    {
      if ( !out->create_ptr(pointee) )
        return false;
    }
    return true;
  }

  // `T[N]`.
  {
    std::string elem;
    if ( const std::size_t n = fixed_array_count(spelling, &elem); n != 0 )
    {
      tinfo_t base;
      if ( resolve_spelling(til, plan, elem, 0, &base) )
        return out->create_array(base, (uint32)n);
      return byte_array(n, out);
    }
  }

  // `T[]`: the element count is not in the spelling, so it comes from the observed width when
  // that divides evenly, and from a byte blob when it does not.
  if ( spelling.size() > 2 && spelling.compare(spelling.size() - 2, 2, "[]") == 0 )
  {
    tinfo_t base;
    if ( resolve_spelling(til, plan, spelling.substr(0, spelling.size() - 2), 0, &base) )
    {
      const std::size_t elem_size = base.get_size();
      if ( elem_size != 0 && width != 0 && width % elem_size == 0 )
        return out->create_array(base, (uint32)(width / elem_size));
    }
    return byte_array(width, out);
  }

  // `code` is Ghidra's executable-code type. It has no C-level counterpart, but an address to code
  // is an address: `void*` keeps the width honest. (Inside an aggregate the planner has already
  // turned it into a gap member; this only applies to a variable typed `code`.)
  if ( spelling == "code" )
    return out->create_ptr(tinfo_t(BTF_VOID));

  if ( auto it = builtin_types().find(spelling); it != builtin_types().end() )
  {
    *out = tinfo_t(it->second);
    return true;
  }

  if ( resolve_aggregate(til, plan, spelling, out) )
    return true;

  // `code`, a 256-bit integer, anything else: the width is known, the type is not.
  return byte_array(width, out);
}

/// The member type for one planned member. Gap members are a byte array of exactly their extent
/// carrying TAFLD_GAP; a flexible array member is an element type with zero elements.
bool build_member_type(til_t *til, const TypePlan &plan, const PlannedMember &m, tinfo_t *out)
{
  if ( m.is_gap )
    return byte_array(m.extent, out);

  if ( m.is_flexible_array )
  {
    const std::string &spelling = m.type_spelling;
    if ( spelling.size() <= 2 || spelling.compare(spelling.size() - 2, 2, "[]") != 0 )
      return false;
    tinfo_t elem;
    if ( !resolve_spelling(til, plan, spelling.substr(0, spelling.size() - 2), 0, &elem) )
      return false;
    return out->create_array(elem, /*nelems=*/0);
  }

  return resolve_spelling(til, plan, m.type_spelling, m.extent, out);
}

/// Add one member at `offset` bytes. `udm_t::offset` / `udm_t::size` are in BITS, while the plan
/// works in bytes.
tinfo_code_t add_member(tinfo_t &tif, const PlannedMember &m, tinfo_t *member_type,
                        std::size_t *normalized)
{
  if ( !m.is_gap )
    return tif.add_udm(m.name.c_str(), *member_type, m.offset * 8, ETF_NO_SAVE);

  udm_t udm(m.name.c_str(), *member_type, m.offset * 8);
  udm.size = m.extent * 8;
  udm.tafld_bits |= TAFLD_GAP;
  tinfo_code_t rc = tif.add_udm(udm, ETF_NO_SAVE);
  if ( rc == TERR_OK )
    return rc;

  // The SDK documents TAFLD_GAP but not exactly what makes the kernel reject one (TERR_BAD_GAP).
  // Retry once as a plain byte array of the same width: the bytes keep their place, only the
  // "this is padding" decoration is lost.
  udm.tafld_bits &= ~(uint32)TAFLD_GAP;
  rc = tif.add_udm(udm, ETF_NO_SAVE);
  if ( rc == TERR_OK )
    ++*normalized;
  return rc;
}

} // namespace

EmitStats emit_local_types(til_t *til, const TypePlan &plan)
{
  EmitStats stats;
  if ( plan.aggregates.empty() )
    return stats;

  begin_type_updating(UTP_STRUCT);

  // 1. Every aggregate exists (even if only as an empty forward declaration) before any member is
  //    added, so a reference from one type to another always resolves and a cycle terminates.
  for ( const PlannedAggregate &agg : plan.aggregates )
  {
    tinfo_t fwd;
    const tinfo_code_t rc = fwd.create_forward_decl(
      til, agg.is_union ? BTF_UNION : BTF_STRUCT, agg.name.c_str(), NTF_REPLACE);
    if ( rc != TERR_OK )
    {
      ++stats.failed_types;
      stats.failures.push_back(agg.name + ": forward declaration failed ("
                               + tinfo_errstr(rc) + ")");
    }
  }

  for ( const PlannedAggregate &agg : plan.aggregates )
  {
    // 2. An anonymous UDT: `calc_udt_aligns` / `set_struct_size` work on one but not on a
    //    typeref, and the name only has to be attached at the very end.
    tinfo_t tif;
    if ( !tif.create_udt(agg.is_union) )
    {
      ++stats.failed_types;
      stats.failures.push_back(agg.name + ": could not create the type");
      continue;
    }

    // 3. Fixed layout for structs: TRex offsets are observed bytes and need not match natural
    //    alignment. Unions are never fixed (TAUDT_FIXED cannot be set for them) and need no
    //    offsets, since every alternative starts at 0.
    if ( !agg.is_union )
      tif.set_fixed_struct(true);

    for ( const PlannedMember &m : agg.members )
    {
      tinfo_t member_type;
      if ( !build_member_type(til, plan, m, &member_type) || member_type.empty() )
      {
        ++stats.dropped_members;
        stats.failures.push_back(agg.name + "." + m.name + ": no type for `"
                                 + m.type_spelling + "`");
        continue;
      }
      if ( add_member(tif, m, &member_type, &stats.normalized_alternatives) != TERR_OK )
      {
        ++stats.dropped_members;
        stats.failures.push_back(agg.name + "." + m.name + ": member rejected");
        continue;
      }
      if ( m.is_gap )
        ++stats.gap_members;
    }

    // 4. Recalculate the field alignments from the members that are now there (an anonymous type,
    //    not a typeref). SUDT_GAPS is deliberately not passed: the gap members are already
    //    explicit, and letting the kernel insert more would duplicate them.
    if ( !tif.calc_udt_aligns(SUDT_ALIGN) )
      stats.failures.push_back(agg.name + ": could not recalculate the member alignments");

    // 5. The observed total, when there is one. A rejection here is recorded, not fatal: the
    //    members and their offsets are already installed.
    if ( !agg.is_union && agg.size_known )
    {
      const tinfo_code_t rc = tif.set_struct_size(agg.size);
      if ( rc != TERR_OK )
        stats.failures.push_back(agg.name + ": could not set the struct size ("
                                 + tinfo_errstr(rc) + ")");
    }

    // 6. Publish. NTF_REPLACE makes a re-run of the same reconstruction idempotent; NTF_NO_NAMECHK
    //    is deliberately not passed, so a name IDA dislikes is reported instead of forced in.
    const tinfo_code_t rc = tif.set_named_type(til, agg.name.c_str(), NTF_REPLACE);
    if ( rc == TERR_OK )
      ++stats.created_types;
    else
    {
      ++stats.failed_types;
      stats.failures.push_back(agg.name + ": " + tinfo_errstr(rc));
    }
  }

  end_type_updating(UTP_STRUCT);
  return stats;
}

bool build_variable_type(til_t *til, const TypePlan &plan, const std::string &spelling,
                         std::size_t width, tinfo_t *out)
{
  if ( width == 0 )
    return false;
  tinfo_t tif;
  if ( !resolve_spelling(til, plan, spelling, width, &tif) || tif.empty() )
    return false;
  *out = tif;
  return true;
}

} // namespace trexida::ida_types