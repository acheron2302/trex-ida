// Implementation of trexida::plan::build_plan — see type_plan.hpp.
//
// Reads the printer's structured `CType` graph (never its text) plus the structural types it was
// built from, and decides for every aggregate member: its byte offset, the byte extent it owns,
// and whether IDA can represent the type at all (otherwise it becomes a gap member).

#include "type_plan.hpp"

#include <algorithm>
#include <cstddef>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <trex/c_types.hpp>
#include <trex/containers.hpp>
#include <trex/joinable_container.hpp>
#include <trex/structural.hpp>

namespace trexida::plan
{

namespace
{

using trex::AggregateSize;
using trex::CType;
using trex::Index;
using trex::StructuralType;

/// Byte sizes of the scalar spellings the printer emits (`builtin_to_printable`, c_types.cpp:108).
/// `void` is absent: it carries no size, and a bare `void` member is always a gap.
const std::map<std::string, std::size_t> &scalar_sizes()
{
  static const std::map<std::string, std::size_t> sizes = {
    { "bool", 1 },            { "char", 1 },            { "unsigned char", 1 },
    { "wchar_t", 2 },         { "int8_t", 1 },          { "uint8_t", 1 },
    { "int16_t", 2 },         { "uint16_t", 2 },        { "int32_t", 4 },
    { "uint32_t", 4 },        { "int64_t", 8 },         { "uint64_t", 8 },
    { "int128_t", 16 },       { "uint128_t", 16 },      { "float", 4 },
    { "double", 8 },          { "long double", 8 },
    // TRex's "bytes but no type information" spellings. They are gaps, but they do have a width.
    { "undefined", 1 },       { "undefined1", 1 },      { "undefined2", 2 },
    { "undefined4", 4 },      { "undefined8", 8 },      { "padding", 1 },
    { "int256_t", 32 },       { "uint256_t", 32 },
  };
  return sizes;
}

/// `padding[N]` -> N, otherwise std::nullopt.
std::optional<std::size_t> padding_extent(const std::string &spelling)
{
  const std::string prefix = "padding[";
  if ( spelling.size() <= prefix.size() + 1 || spelling.rfind(prefix, 0) != 0
       || spelling.back() != ']' )
    return std::nullopt;
  const std::string digits =
    spelling.substr(prefix.size(), spelling.size() - prefix.size() - 1);
  if ( digits.empty()
       || digits.find_first_not_of("0123456789") != std::string::npos )
    return std::nullopt;
  return (std::size_t)strtoull(digits.c_str(), nullptr, 10);
}

/// Base name of `T[]` / `T[]*` (star-suffix forms included), or std::nullopt.
std::optional<std::string> unsized_array_base(const std::string &spelling)
{
  const size_t bracket = spelling.find("[]");
  if ( bracket == std::string::npos )
    return std::nullopt;
  for ( size_t k = bracket + 2; k < spelling.size(); ++k )
    if ( spelling[k] == '*' )
      return std::nullopt; // `T[]*` is a pointer, not an array by value
  return spelling.substr(0, bracket);
}

/// Strip a trailing run of `*` (and the whitespace before it). `pointer_depth` counts the stars.
std::pair<std::string, std::size_t> split_stars(const std::string &spelling)
{
  size_t end = spelling.size();
  while ( end > 0 && (spelling[end - 1] == '*' || spelling[end - 1] == ' ') )
    --end;
  size_t stars = 0;
  for ( size_t k = end; k < spelling.size(); ++k )
    if ( spelling[k] == '*' )
      ++stars;
  return { spelling.substr(0, end), stars };
}

/// `T[N]` -> (T, N), otherwise std::nullopt.
std::optional<std::pair<std::string, std::size_t>> fixed_array(const std::string &spelling)
{
  if ( spelling.empty() || spelling.back() != ']' )
    return std::nullopt;
  const size_t open = spelling.find('[');
  if ( open == std::string::npos )
    return std::nullopt;
  const std::string digits = spelling.substr(open + 1, spelling.size() - open - 2);
  if ( digits.empty() || digits.find_first_not_of("0123456789") != std::string::npos )
    return std::nullopt;
  return std::make_pair(spelling.substr(0, open),
                        (std::size_t)strtoull(digits.c_str(), nullptr, 10));
}

/// A structural index for a printer type name, or nullopt when no live type carries that name.
///
/// The mapping is built from the printer itself: it walks every live canonical index in `types_`
/// (the very container the printer rounded and named) and asks it for that index's external name.
/// `stypes.type_names()` cannot be used for this: the serializer leaves it empty
/// (structural_serialize.cpp:531), in which case `type_name()` only answers `t{idx}` — a name the
/// printer never issues.
///
/// Two indices may carry one name (a union's alternatives intern to a single CType,
/// c_type_printer.cpp:355-370); the first wins, which is enough because both describe the same
/// `CType`.
class NameIndex
{
public:
  NameIndex(const trex::Container<StructuralType> &types,
            const trex::PrintableCTypes<trex::ExternalVariable> &printer)
  {
    for ( const Index &idx : types.currently_alive_canon_indices_iter() )
    {
      const Index canon = types.get_canonical_index(idx);
      by_name_.emplace(printer.ext_type_name_at(canon), canon);
    }
  }

  const Index *find(const std::string &name) const
  {
    auto it = by_name_.find(name);
    return it == by_name_.end() ? nullptr : &it->second;
  }

private:
  std::map<std::string, Index> by_name_;
};

/// Why a member cannot be represented, if it cannot.
enum class Unrepresentable
{
  No,          ///< IDA can hold this type
  Plain,       ///< gap of exactly the slot extent (void / code / undefinedN / self reference)
  Padding,     ///< gap of exactly the `padding[N]` width
  PointerToArrayOfUnknown, ///< `T[]*` where T is a referenced-but-never-defined aggregate
};

/// Byte size of a spelling, as far as it is statically known. `aggregate_sizes` holds the planned
/// aggregates' sizes; `pointer_size` the pipeline's pointer width.
std::optional<std::size_t> spelling_size(const std::string &spelling,
                                         const std::map<std::string, std::size_t> &aggregate_sizes,
                                         std::size_t pointer_size)
{
  if ( spelling.empty() || spelling == "void" )
    return std::nullopt;
  if ( const auto pad = padding_extent(spelling) )
    return pad;
  if ( const auto arr = fixed_array(spelling) )
  {
    const std::size_t elems = arr->second;
    const std::optional<std::size_t> elem = spelling_size(arr->first, aggregate_sizes, pointer_size);
    if ( !elem.has_value() || *elem == 0 )
      return std::nullopt;
    return elems * *elem;
  }
  const auto [base, stars] = split_stars(spelling);
  if ( stars > 0 )
    return pointer_size;
  if ( base == "code" )
    return pointer_size;
  if ( auto it = scalar_sizes().find(base); it != scalar_sizes().end() )
    return it->second;
  if ( auto it = aggregate_sizes.find(base); it != aggregate_sizes.end() )
    return it->second;
  return std::nullopt;
}

class Planner
{
public:
  Planner(const trex::SerializableStructuralTypes<trex::ExternalVariable> &stypes,
          const trex::PrintableCTypes<trex::ExternalVariable> &printer,
          std::size_t pointer_size)
    : stypes_(stypes),
      types_(stypes.types()),
      printer_(printer),
      names_(stypes.types(), printer),
      pointer_size_(pointer_size)
  {
  }

  TypePlan run()
  {
    TypePlan plan;
    for ( const auto &entry : printer_.named_ctypes() )
    {
      const std::string &name = entry.first;
      const CType &ctype = *entry.second;
      if ( ctype.kind != CType::Kind::Struct && ctype.kind != CType::Kind::Union )
        continue;

      const Index *found = names_.find(name);
      if ( found == nullptr )
        continue;
      const Index canon = types_.get_canonical_index(*found);

      PlannedAggregate agg;
      agg.name = name;
      agg.is_union = (ctype.kind == CType::Kind::Union);
      const std::optional<AggregateSize> total = types_.get(canon).aggregate_size(types_, 64);
      agg.size_known = total.has_value() && total->kind == AggregateSize::Kind::Definite;
      agg.size = agg.size_known ? total->value : 0;

      if ( agg.is_union )
        plan_union(agg, ctype);
      else
        plan_struct(agg, ctype, canon);

      if ( agg.size_known )
        known_sizes_.emplace(agg.name, agg.size);
      plan.aggregates.push_back(std::move(agg));
    }

    order_aggregates(plan.aggregates);
    plan_variables(plan);
    plan.dropped_members = dropped_;
    plan.gap_members = gap_members_;
    return plan;
  }

private:
  void plan_struct(PlannedAggregate &agg, const CType &ctype, const Index &canon)
  {
    const auto &fields = ctype.struct_fields;
    if ( fields.empty() )
      return;

    // `struct_fields[0]` is the aggregate's own (offset 0) head type; `struct_fields[k + 1]`
    // corresponds to the k-th entry of `colocated_struct_fields` (c_type_printer.cpp:449-465).
    std::vector<Index> field_index(fields.size());
    {
      std::size_t k = 1;
      for ( const auto &kv : types_.get(canon).colocated_struct_fields )
      {
        if ( k < fields.size() )
          field_index[k] = types_.get_canonical_index(kv.second);
        ++k;
      }
    }

    for ( std::size_t k = 0; k < fields.size(); ++k )
    {
      const std::size_t offset = fields[k].first;
      const std::string &spelling = fields[k].second;

      // The slot runs up to the next member, or to the aggregate's total when this is the last
      // one and that total is known.
      const std::size_t next_offset =
        (k + 1 < fields.size()) ? fields[k + 1].first : (agg.size_known ? agg.size : offset);
      const std::size_t slot_extent = next_offset > offset ? next_offset - offset : 0;

      // Per-member extent: the field's own observed size. For the head member that would be the
      // whole aggregate's observed size (it covers the colocated fields too), so its slot extent
      // is used instead.
      std::size_t extent = slot_extent;
      if ( k != 0 )
      {
        if ( const std::optional<std::size_t> observed = types_.get(field_index[k]).observed_size() )
          extent = *observed;
      }

      const Unrepresentable why = classify(spelling, agg.name);
      if ( why == Unrepresentable::Padding )
      {
        // `padding[N]`: N is authoritative, no differencing against the next member.
        const std::size_t gap_extent = *padding_extent(spelling);
        if ( gap_extent == 0 )
        {
          ++dropped_;
          continue;
        }
        agg.members.push_back(gap_member(spelling, offset, gap_extent));
        continue;
      }
      if ( why == Unrepresentable::PointerToArrayOfUnknown )
      {
        agg.members.push_back(gap_member(spelling, offset, extent));
        continue;
      }

      if ( std::optional<std::string> elem = unsized_array_base(spelling); elem.has_value() )
      {
        agg.members.push_back(make_member(spelling, offset, 0));
        agg.members.back().is_flexible_array = true;
        continue;
      }

      if ( why == Unrepresentable::Plain )
      {
        if ( slot_extent == 0 )
        {
          ++dropped_;
          continue;
        }
        agg.members.push_back(gap_member(spelling, offset, slot_extent));
        continue;
      }

      agg.members.push_back(make_member(spelling, offset, extent));
    }
  }

  void plan_union(PlannedAggregate &agg, const CType &ctype)
  {
    // Every alternative starts at offset 0. A representable alternative covers its own width; a
    // gap alternative covers the union's bytes, because that is all we know about what it stands
    // for (`padding[N]` is the exception: N is authoritative).
    std::vector<PlannedMember> alternatives;
    alternatives.reserve(ctype.union_members.size());

    for ( std::size_t i = 0; i < ctype.union_members.size(); ++i )
    {
      const std::string &spelling = ctype.union_members[i];
      const Unrepresentable why = classify(spelling, agg.name);

      PlannedMember m;
      m.type_spelling = spelling;
      m.name = "alt_" + std::to_string(i);
      m.offset = 0;
      if ( printer_.ctype_at(spelling) != nullptr )
        m.ctype_name = spelling;
      m.is_gap = (why != Unrepresentable::No);

      if ( why == Unrepresentable::Padding )
        m.extent = *padding_extent(spelling);
      else if ( !m.is_gap )
      {
        if ( const std::optional<std::size_t> sz =
               spelling_size(spelling, known_sizes_, pointer_size_) )
          m.extent = *sz;
      }
      alternatives.push_back(std::move(m));
    }

    std::size_t max_representable = 0;
    for ( const PlannedMember &m : alternatives )
      if ( !m.is_gap )
        max_representable = std::max(max_representable, m.extent);

    std::vector<PlannedMember> kept;
    kept.reserve(alternatives.size());
    for ( PlannedMember &m : alternatives )
    {
      if ( !m.is_gap )
      {
        kept.push_back(std::move(m));
        continue;
      }
      if ( m.extent == 0 ) // not a `padding[N]`: the gap spans the whole union
        m.extent = agg.size_known ? agg.size : max_representable;
      if ( m.extent == 0 )
      {
        ++dropped_;
        continue;
      }
      m.name = "gap_" + m.name;
      ++gap_members_;
      kept.push_back(std::move(m));
    }
    agg.members = std::move(kept);
  }

  Unrepresentable classify(const std::string &spelling, const std::string &self) const
  {
    if ( spelling == "code" )
      return Unrepresentable::Plain;
    if ( padding_extent(spelling).has_value() )
      return Unrepresentable::Padding;
    if ( const auto [base, stars] = split_stars(spelling); stars == 0 )
    {
      if ( base == "void" || base == "undefined" || base == "undefined1" || base == "undefined2"
           || base == "undefined4" || base == "undefined8" || base == "int256_t"
           || base == "uint256_t" )
        return Unrepresentable::Plain;
      if ( base == self )
        return Unrepresentable::Plain; // by-value self reference (TERR_NESTED)
    }
    // `T[]*`: a pointer to an array of T. Same width as `T*`, but the pointee may be an aggregate
    // the printer referenced and never defined (c_type_printer.cpp:419-437).
    {
      std::string base = spelling;
      bool starred = false;
      while ( !base.empty() && base.back() == '*' )
      {
        base.pop_back();
        starred = true;
      }
      if ( starred )
      {
        while ( !base.empty() && base.back() == ' ' )
          base.pop_back();
        const size_t bracket = base.find("[]");
        if ( bracket != std::string::npos && bracket + 2 == base.size() )
        {
          const std::string elem = base.substr(0, bracket);
          if ( printer_.ctype_at(elem) == nullptr && scalar_sizes().count(elem) == 0 )
            return Unrepresentable::PointerToArrayOfUnknown;
        }
      }
    }
    return Unrepresentable::No;
  }

  PlannedMember make_member(const std::string &spelling, std::size_t offset, std::size_t extent) const
  {
    PlannedMember m;
    m.type_spelling = spelling;
    m.name = "field_" + std::to_string(offset);
    m.offset = offset;
    m.extent = extent;
    if ( printer_.ctype_at(spelling) != nullptr )
      m.ctype_name = spelling;
    return m;
  }

  PlannedMember gap_member(const std::string &spelling, std::size_t offset,
                           std::size_t extent)
  {
    PlannedMember m = make_member(spelling, offset, extent);
    m.name = "gap_" + m.name;
    m.is_gap = true;
    ++gap_members_;
    return m;
  }

  /// Aggregates in creation order: anything referenced by value precedes its referrer. Pointer
  /// references do not constrain the order — every aggregate has a forward declaration by the
  /// time the members are added. Ties (and cycles) break on the name, ascending.
  void order_aggregates(std::vector<PlannedAggregate> &aggs) const
  {
    std::map<std::string, std::size_t> position;
    for ( std::size_t i = 0; i < aggs.size(); ++i )
      position.emplace(aggs[i].name, i);

    std::vector<std::vector<std::size_t>> dependents(aggs.size());
    std::vector<std::size_t> indegree(aggs.size(), 0);
    for ( std::size_t i = 0; i < aggs.size(); ++i )
    {
      std::set<std::size_t> refs;
      for ( const PlannedMember &m : aggs[i].members )
      {
        std::string base = m.type_spelling;
        while ( !base.empty() && base.back() == '*' )
          base.pop_back();
        while ( !base.empty() && base.back() == ' ' )
          base.pop_back();
        const size_t bracket = base.find('[');
        if ( bracket != std::string::npos )
          base = base.substr(0, bracket);
        if ( m.is_gap )
          continue;
        auto it = position.find(base);
        if ( it != position.end() && it->second != i )
          refs.insert(it->second);
      }
      for ( std::size_t r : refs )
      {
        dependents[r].push_back(i);
        ++indegree[i];
      }
    }

    std::set<std::pair<std::string, std::size_t>> ready;
    for ( std::size_t i = 0; i < aggs.size(); ++i )
      if ( indegree[i] == 0 )
        ready.emplace(aggs[i].name, i);

    std::vector<std::size_t> order;
    order.reserve(aggs.size());
    while ( !ready.empty() )
    {
      const std::size_t i = ready.begin()->second;
      ready.erase(ready.begin());
      order.push_back(i);
      for ( std::size_t d : dependents[i] )
        if ( --indegree[d] == 0 )
          ready.emplace(aggs[d].name, d);
    }
    // A cycle (a type that contains itself by value would be a gap, so this is only reachable
    // through an unrepresentable-by-value edge): keep the rest in name order.
    if ( order.size() != aggs.size() )
    {
      std::set<std::size_t> placed(order.begin(), order.end());
      for ( std::size_t i = 0; i < aggs.size(); ++i )
        if ( placed.count(i) == 0 )
          order.push_back(i);
    }

    std::vector<PlannedAggregate> sorted;
    sorted.reserve(aggs.size());
    for ( std::size_t i : order )
      sorted.push_back(std::move(aggs[i]));
    aggs = std::move(sorted);
  }

  void plan_variables(TypePlan &plan) const
  {
    for ( const auto &entry : stypes_.var_type_iter() )
    {
      PlannedVariable v;
      v.name = entry.first.name;
      v.spelling = printer_.ext_type_name_at(entry.second);
      v.has_type_info = has_type_information(v.spelling);
      plan.variable_types.push_back(std::move(v));
    }
  }

  const trex::SerializableStructuralTypes<trex::ExternalVariable> &stypes_;
  const trex::Container<StructuralType> &types_;
  const trex::PrintableCTypes<trex::ExternalVariable> &printer_;
  NameIndex names_;
  std::size_t pointer_size_ = 8;
  std::map<std::string, std::size_t> known_sizes_;
  std::size_t dropped_ = 0;
  std::size_t gap_members_ = 0;
};

} // namespace

bool has_type_information(const std::string &spelling)
{
  return !(spelling.empty() || spelling == "void" || spelling.rfind("undefined", 0) == 0
           || spelling.rfind("padding", 0) == 0);
}

TypePlan build_plan(const trex::SerializableStructuralTypes<trex::ExternalVariable> &stypes,
                    const trex::PrintableCTypes<trex::ExternalVariable> &printer,
                    std::size_t pointer_size)
{
  Planner planner(stypes, printer, pointer_size);
  return planner.run();
}

} // namespace trexida::plan