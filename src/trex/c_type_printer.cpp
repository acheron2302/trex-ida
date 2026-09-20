// Printable C-like types — implementation. Port of
// `third_party/trex/trex/src/c_type_printer.rs` (645 lines).
//
// Faithfulness notes:
//   * The output text format is load-bearing for the S7 differential gate (compared
//     byte-for-byte against the Rust oracle). The Display impl emits:
//       - One `// <var> : <type>` line per (var, idx) pair in varmap iteration order.
//       - Then a BFS through the named types. For each unique name, it emits either:
//           struct <name> {  <type> field_<pos>; ... };
//         or
//           union <name> {  <type> alt_<i>; ... };
//       - UnsizedArray produces no output (the elem is pushed onto the queue).
//   * `external_type_name_at` is recursive and memoised via `external_type_name_`. The
//     pre-insertion of a fresh name (the "bottom out recursion" pattern) matches
//     upstream lines 96-99 and 128-130.
//   * `RoundedTypeUnionMember` translates each `RoundedIdx` into one of four printable
//     forms (`Primitive(name)`, `Pointer`, `Code`, `Padding(N)`). The translation is
//     1:1 with upstream `impl From<RoundedIdx<'_>> for RoundedTypeUnionMember`.
//   * `TypeNameStream` issues `t1`, `t2`, ... in order — the counter starts at 0 and
//     is incremented before each call, matching upstream lines 578-580.
//   * `formatted_types_for` and `internal_formatted_types_for` are byte-exact
//     transcriptions; the fuel limit is 100 (upstream line 487). `visited` is
//     mutated via a `std::set<std::string>`; upstream uses `UnorderedSet<String>`.

#include <trex/c_type_printer.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <trex/c_types.hpp>
#include <trex/inference_config.hpp>
#include <trex/serialize_structural.hpp>
#include <trex/type_rounding.hpp>

namespace trex {

namespace {

// ---------------------------------------------------------------------------
// RoundedTypeUnionMember
//
// Upstream `enum RoundedTypeUnionMember { Primitive(String), Pointer, Code, Padding(usize) }`.
// Ported as a small struct + factory; ordering is the upstream variant declaration
// order.
// ---------------------------------------------------------------------------

struct RoundedTypeUnionMember
{
  enum class Kind : uint8_t
  {
    Primitive = 0,
    Pointer,
    Code,
    Padding,
  };
  Kind kind = Kind::Primitive;
  std::string primitive_name;
  size_t padding_bytes = 0;

  static RoundedTypeUnionMember primitive(std::string n)
  {
    RoundedTypeUnionMember m;
    m.kind = Kind::Primitive;
    m.primitive_name = std::move(n);
    return m;
  }
  static RoundedTypeUnionMember pointer()
  {
    RoundedTypeUnionMember m;
    m.kind = Kind::Pointer;
    return m;
  }
  static RoundedTypeUnionMember code()
  {
    RoundedTypeUnionMember m;
    m.kind = Kind::Code;
    return m;
  }
  static RoundedTypeUnionMember padding(size_t n)
  {
    RoundedTypeUnionMember m;
    m.kind = Kind::Padding;
    m.padding_bytes = n;
    return m;
  }

  friend bool operator==(const RoundedTypeUnionMember &a, const RoundedTypeUnionMember &b)
  {
    if ( a.kind != b.kind ) return false;
    switch ( a.kind )
    {
      case Kind::Primitive: return a.primitive_name == b.primitive_name;
      case Kind::Pointer:   return true;
      case Kind::Code:      return true;
      case Kind::Padding:   return a.padding_bytes == b.padding_bytes;
    }
    return false;
  }
  friend bool operator!=(const RoundedTypeUnionMember &a, const RoundedTypeUnionMember &b)
  {
    return !(a == b);
  }
  friend bool operator<(const RoundedTypeUnionMember &a, const RoundedTypeUnionMember &b)
  {
    if ( a.kind != b.kind ) return static_cast<uint8_t>(a.kind) < static_cast<uint8_t>(b.kind);
    switch ( a.kind )
    {
      case Kind::Primitive: return a.primitive_name < b.primitive_name;
      case Kind::Pointer:   return false;
      case Kind::Code:      return false;
      case Kind::Padding:   return a.padding_bytes < b.padding_bytes;
    }
    return false;
  }

  /// Mirrors upstream `RoundedTypeUnionMember::to_external(pointee)`.
  std::string to_external(const std::optional<std::string> &pointee) const
  {
    if ( kind == Kind::Pointer )
    {
      TREX_CHECK(pointee.has_value(),
                 "RoundedTypeUnionMember::to_external: Pointer requires pointee");
      return *pointee + "*";
    }
    if ( kind == Kind::Primitive ) return primitive_name;
    if ( kind == Kind::Code ) return "code";
    return "padding[" + std::to_string(padding_bytes) + "]";
  }
};

/// Mirror of upstream `impl From<RoundedIdx<'_>> for RoundedTypeUnionMember`.
RoundedTypeUnionMember rounded_idx_to_union_member(const RoundedIdx &ri)
{
  if ( ri.kind == RoundedIdx::Kind::Padding )
  {
    return RoundedTypeUnionMember::padding(ri.padding_bytes);
  }
  // Primitive
  if ( ri.name == "Code" ) return RoundedTypeUnionMember::code();
  if ( ri.name == "VoidPtr" ) return RoundedTypeUnionMember::pointer();
  // Generic primitive — find the BuiltIn whose Debug name matches and emit its
  // printable C spelling.
  for ( BuiltIn b : all_builtins() )
  {
    if ( builtin_debug_name(b) == ri.name )
    {
      return RoundedTypeUnionMember::primitive(builtin_to_printable(b));
    }
  }
  TREX_UNREACHABLE("RoundedIdx has unknown Primitive name %s", ri.name.c_str());
}

} // namespace

// ===========================================================================
// PrintableCTypes<ExtVar>
// ===========================================================================

template <class ExtVar>
PrintableCTypes<ExtVar>::PrintableCTypes(const SerializableStructuralTypes<ExtVar> &stypes)
{
  // Build the varmap and structural-types view.
  varmap_.clear();
  for ( const auto &kv : stypes.varmap() )
  {
    varmap_.insert({kv.first, kv.second});
  }
  structural_types_ = &stypes.types();

  // Round up via the standard C primitive set. Mirrors upstream lines 53-64 exactly.
  auto [c_type_names, c_types] = c_types::structural_types_for_all_primitive_c_types();
  const auto rounding = round_up(*structural_types_, c_types, c_type_names);
  for ( const auto &kv : rounding.iter() )
  {
    const Index idx = kv.first;
    const auto &stype_and_set_ref = kv.second;
    const auto &stype_and_set = stype_and_set_ref.get();
    const auto &hm = stype_and_set.second;
    unordered::UnorderedSet<RoundedIdx> converted;
    for ( const RoundedIdx &ri : hm.iter() )
    {
      // Upstream `From<RoundedIdx>` — directly convert.
      RoundedTypeUnionMember m = rounded_idx_to_union_member(ri);
      // Wrap back into RoundedIdx via name? No — the port stores the
      // RoundedTypeUnionMember set. But our header declares `rounded_types_` as
      // `IndexMap<UnorderedSet<RoundedIdx>>`. To keep the public surface
      // consistent with upstream (where `rounded_types` is
      // `IndexMap<UnorderedSet<RoundedTypeUnionMember>>`), we'd need to convert
      // here. We do that in the field below; for now, only the iterator matters.
      (void)m;
    }
    // Convert the UnorderedSet<RoundedIdx> into UnorderedSet<RoundedTypeUnionMember>.
    // Because RoundedTypeUnionMember is a private detail of the .cpp, we inline the
    // conversion here and store the converted set in a separate map keyed by Index.
    // (We do not use the public `rounded_types_` field of `RoundedIdx` here because
    //  the public header uses RoundedIdx directly to keep the contract clean.)
    unordered::UnorderedSet<RoundedIdx> raw;
    for ( const RoundedIdx &ri : hm.iter() )
    {
      raw.insert(ri);
    }
    rounded_types_.insert(idx, std::move(raw));
  }

  // Walk the varmap, populating `external_type_name_`. Upstream lines 66-68.
  for ( const auto &kv : varmap_ )
  {
    (void)external_type_name_at(kv.second);
  }
}

template <class ExtVar>
std::string PrintableCTypes<ExtVar>::ext_type_name_at(Index idx) const
{
  const Index canon = structural_types_->get_canonical_index(idx);
  const std::string *p = external_type_name_.get(canon);
  TREX_CHECK(p != nullptr,
             "PrintableCTypes::ext_type_name_at: index not initialised");
  return *p;
}

template <class ExtVar>
std::string PrintableCTypes<ExtVar>::new_type_name()
{
  ++next_name_counter_;
  return "t" + std::to_string(next_name_counter_);
}

template <class ExtVar>
std::string PrintableCTypes<ExtVar>::external_type_name_at(Index idx)
{
  // Mirrors upstream `external_type_name_at` lines 82-264. The body is large and
  // recursive; the pre-insertion of a fresh name before recursing on the pointee
  // is the load-bearing "bottom out recursion" trick.
  const Index canon = structural_types_->get_canonical_index(idx);
  if ( const std::string *existing = external_type_name_.get(canon) )
  {
    return *existing;
  }

  const StructuralType &this_stype = structural_types_->get(canon);
  const bool has_colocated = !this_stype.colocated_struct_fields.empty();
  // Upstream `last_key_value().unwrap().1` — the value (Index) of the last
  // colocated_struct_fields entry, which is the highest-offset field.
  const bool last_colocated_is_self = has_colocated
      && structural_types_->index_eq(
             this_stype.colocated_struct_fields.rbegin()->second, canon);
  // (Upstream's `last_colocated_is_self` is unused outside the predicates below.)
  const auto *rounded_set = rounded_types_.get(canon);
  TREX_CHECK(rounded_set != nullptr,
             "PrintableCTypes::external_type_name_at: no rounded types for index");
  const bool many_rounded = rounded_set->len() > 1;

  if ( (!this_stype.colocated_struct_fields.empty()
        && !structural_types_->index_eq(
              this_stype.colocated_struct_fields.rbegin()->second, canon))
       || many_rounded )
  {
    std::string this_name = new_type_name();
    external_type_name_.insert(canon, this_name);
  }

  // Self-referential-pointer detection.
  bool forced_void_pointee = false;
  bool self_referential_pointee = false;
  if ( this_stype.pointer_to.has_value() )
  {
    if ( structural_types_->index_eq(*this_stype.pointer_to, canon) )
    {
      self_referential_pointee = true;
      if ( this_stype.colocated_struct_fields.empty() )
      {
        if ( rounded_set->len() == 0 )
        {
          TREX_UNREACHABLE("Can't round to nothing if there is a pointer");
        }
        else if ( rounded_set->len() == 1 )
        {
          // Plain old pointer; set to `void*`.
          forced_void_pointee = true;
        }
        else
        {
          // Will bottom out (name pre-inserted).
        }
      }
      else if ( structural_types_->index_eq(
                   this_stype.colocated_struct_fields.rbegin()->second, canon) )
      {
        // Pointer + unsized array — pre-insert a fresh name to bottom out the
        // recursion.
        std::string this_name = new_type_name();
        external_type_name_.insert(canon, this_name);
      }
      else
      {
        // Will bottom out (name pre-inserted above).
      }
    }
    else
    {
      // No issues, carry on.
    }
  }

  // Compute the pointee name (if any).
  std::optional<std::string> pointee;
  if ( forced_void_pointee )
  {
    pointee = std::string("void");
  }
  else if ( this_stype.pointer_to.has_value() )
  {
    pointee = external_type_name_at(*this_stype.pointer_to);
  }

  // Convert the rounded set to RoundedTypeUnionMember and pick a `head_name`.
  std::vector<RoundedTypeUnionMember> rounded_mems;
  rounded_mems.reserve(rounded_set->len());
  for ( const RoundedIdx &ri : rounded_set->iter() )
  {
    rounded_mems.push_back(rounded_idx_to_union_member(ri));
  }
  // Convert to std::set for stable iteration order (mirror upstream `BTreeSet`).
  std::set<RoundedTypeUnionMember> rounded(rounded_mems.begin(), rounded_mems.end());

  std::string head_name;
  if ( rounded.empty() )
  {
    head_name = "void";
  }
  else if ( rounded.size() == 1 )
  {
    head_name = rounded.begin()->to_external(pointee);
  }
  else
  {
    // union — collect union members into a BTreeSet-of-string.
    std::set<std::string> union_members;
    for ( const RoundedTypeUnionMember &m : rounded )
    {
      union_members.insert(m.to_external(pointee));
    }
    auto it = union_name_.find(union_members);
    std::string this_name;
    if ( it != union_name_.end() )
    {
      this_name = it->second;
    }
    else
    {
      if ( self_referential_pointee )
      {
        const std::string *p = external_type_name_.get(canon);
        TREX_CHECK(p != nullptr, "self_referential_pointee needs pre-inserted name");
        this_name = *p;
      }
      else
      {
        this_name = new_type_name();
      }
      union_name_.insert({union_members, this_name});
    }
    std::vector<std::string> member_vec(union_members.begin(), union_members.end());
    ctypes_.insert(this_name, CType::make_union(std::move(member_vec)));
    head_name = this_name;
  }

  if ( this_stype.colocated_struct_fields.empty() )
  {
    if ( this_stype.observed_array )
    {
      std::string this_name = head_name + "[]";
      ctypes_.insert(this_name, CType::make_unsized_array(head_name));
      external_type_name_.insert(canon, this_name);
      return this_name;
    }
    else
    {
      external_type_name_.insert(canon, head_name);
      return head_name;
    }
  }
  else
  {
    // Struct path
    if ( structural_types_->index_eq(
             this_stype.colocated_struct_fields.rbegin()->second, canon) )
    {
      // Last field is the same as the struct → unsized array
      if ( this_stype.colocated_struct_fields.size() == 1 )
      {
        std::string this_name = head_name + "[]";
        ctypes_.insert(this_name, CType::make_unsized_array(head_name));
        external_type_name_.insert(canon, this_name);
        return this_name;
      }
      else
      {
        std::string new_name;
        const std::string *existing = external_type_name_.get(canon);
        if ( existing != nullptr )
        {
          new_name = *existing;
        }
        else
        {
          new_name = new_type_name();
        }
        std::string this_name = new_name + "[]";
        ctypes_.insert(this_name, CType::make_unsized_array(new_name));
        external_type_name_.insert(canon, this_name);

        // Build the struct for all fields except the last (the self-reference).
        std::vector<std::pair<size_t, std::string>> new_struct_fields;
        new_struct_fields.reserve(this_stype.colocated_struct_fields.size());
        new_struct_fields.emplace_back(0, head_name);
        // Iterate entries in key order (std::map iterates in key order).
        for ( const auto &kv : this_stype.colocated_struct_fields )
        {
          const size_t field_pos = static_cast<size_t>(kv.first);
          const Index field_idx = kv.second;
          if ( structural_types_->index_eq(field_idx, canon) )
            continue;
          new_struct_fields.emplace_back(field_pos, external_type_name_at(field_idx));
        }
        ctypes_.insert(new_name, CType::make_struct(std::move(new_struct_fields)));
        return this_name;
      }
    }
    else
    {
      // Plain old struct
      const std::string *existing = external_type_name_.get(canon);
      std::string this_name;
      if ( existing != nullptr )
      {
        this_name = *existing;
      }
      else
      {
        this_name = new_type_name();
      }
      external_type_name_.insert(canon, this_name);

      std::vector<std::pair<size_t, std::string>> struct_fields;
      struct_fields.reserve(this_stype.colocated_struct_fields.size() + 1);
      struct_fields.emplace_back(0, head_name);
      for ( const auto &kv : this_stype.colocated_struct_fields )
      {
        struct_fields.emplace_back(static_cast<size_t>(kv.first),
                                    external_type_name_at(kv.second));
      }
      ctypes_.insert(this_name, CType::make_struct(std::move(struct_fields)));
      return this_name;
    }
  }
}

template <class ExtVar>
std::string PrintableCTypes<ExtVar>::to_string() const
{
  // Mirrors upstream `impl Display for PrintableCTypes` lines 267-318.
  std::string out;

  // First: comments block.
  for ( const auto &kv : varmap_ )
  {
    const Index idx = structural_types_->get_canonical_index(kv.second);
    const std::string *exttype = external_type_name_.get(idx);
    if ( exttype == nullptr ) continue;
    out += "// ";
    std::ostringstream vs;
    vs << kv.first;
    out += vs.str();
    out += " : ";
    out += *exttype;
    out += "\n";
  }

  // Then: BFS through the named types.
  std::set<std::string> printed;
  std::deque<std::string> queue;
  for ( const auto &kv : external_type_name_.iter() )
  {
    const std::string &name = kv.second;
    queue.push_back(name);
  }

  while ( !queue.empty() )
  {
    std::string typ = queue.front();
    queue.pop_front();
    if ( !printed.insert(typ).second )
      continue;

    const CType *ctyp_ptr = ctypes_.get(typ);
    if ( ctyp_ptr == nullptr )
      continue;

    const CType &ctyp = *ctyp_ptr;
    if ( ctyp.kind == CType::Kind::Struct )
    {
      out += "\nstruct ";
      out += typ;
      out += " {\n";
      for ( const auto &field : ctyp.struct_fields )
      {
        out += "  ";
        out += field.second;
        out += " field_";
        out += std::to_string(field.first);
        out += ";\n";
        queue.push_back(field.second);
      }
      out += "};\n";
    }
    else if ( ctyp.kind == CType::Kind::Union )
    {
      out += "\nunion ";
      out += typ;
      out += " {\n";
      size_t i = 0;
      for ( const std::string &member : ctyp.union_members )
      {
        out += "  ";
        out += member;
        out += " alt_";
        out += std::to_string(i);
        out += ";\n";
        ++i;
        queue.push_back(member);
      }
      out += "};\n";
    }
    else if ( ctyp.kind == CType::Kind::UnsizedArray )
    {
      queue.push_back(ctyp.unsized_array_elem);
    }
    else
    {
      // Other kinds (BuiltIn, Pointer, etc.) are printed via the comment block or
      // are reached transitively from struct/union fields.
    }
  }

  return out;
}

template <class ExtVar>
std::vector<std::string>
PrintableCTypes<ExtVar>::internal_formatted_types_for(
    const std::string &typ, std::set<std::string> *visited, size_t fuel,
    bool separated_unions) const
{
  if ( fuel == 0 )
  {
    return {std::string("out-of-fuel")};
  }
  if ( !visited->insert(typ).second )
  {
    return {};
  }

  const CType *ctyp_ptr = ctypes_.get(typ);
  if ( ctyp_ptr != nullptr )
  {
    const CType &ctyp = *ctyp_ptr;
    {
      std::string res = "struct " + typ + " {\n";
      std::vector<std::vector<std::string>> multipliers;
      for ( const auto &field : ctyp.struct_fields )
      {
        res += "  " + field.second + " field_" + std::to_string(field.first) + ";\n";
        multipliers.push_back(internal_formatted_types_for(field.second, visited,
                                                            fuel - 1, separated_unions));
      }
      res += "};\n\n";

      std::vector<std::string> v{res};
      for ( auto &m : multipliers )
      {
        std::vector<std::string> old_v;
        old_v.swap(v);
        std::vector<std::string> next_m = m.empty() ? std::vector<std::string>{""} : m;
        for ( const std::string &x : next_m )
        {
          for ( const std::string &r : old_v )
          {
            v.push_back(r + x);
          }
        }
      }
      return v;
    }
    if ( ctyp.kind == CType::Kind::Union && separated_unions )
    {
      std::vector<std::string> res;
      for ( const std::string &member : ctyp.union_members )
      {
        // The "is a self-pointer" check: `member.starts_with(typ) && ends_with('*')`
        // and the only `*` chars in `member` are its trailing asterisks. We mirror
        // upstream exactly (lines 372-376).
        bool all_asterisks_after_prefix = false;
        if ( member.size() >= typ.size() && member.compare(0, typ.size(), typ) == 0
             && !member.empty() && member.back() == '*' )
        {
          size_t star_count = 0;
          for ( char c : member )
          {
            if ( c == '*' ) ++star_count;
          }
          if ( member.size() == typ.size() + star_count )
          {
            all_asterisks_after_prefix = true;
          }
        }
        const std::string &effective_member =
            all_asterisks_after_prefix ? std::string("void*") : member;
        std::set<std::string> visited_clone = *visited;
        std::vector<std::string> mem = internal_formatted_types_for(
            effective_member, &visited_clone, fuel - 1, separated_unions);
        if ( mem.empty() )
        {
          res.push_back(effective_member);
        }
        else
        {
          for ( const std::string &s : mem ) res.push_back(s);
        }
      }
      return res;
    }
    if ( ctyp.kind == CType::Kind::Union )
    {
      std::string res = "union " + typ + " {\n";
      std::vector<std::vector<std::string>> multipliers;
      size_t i = 0;
      for ( const std::string &member : ctyp.union_members )
      {
        res += "  " + member + " alt_" + std::to_string(i) + ";\n";
        multipliers.push_back(internal_formatted_types_for(member, visited,
                                                            fuel - 1, separated_unions));
        ++i;
      }
      res += "};\n\n";

      std::vector<std::string> v{res};
      for ( auto &m : multipliers )
      {
        std::vector<std::string> old_v;
        old_v.swap(v);
        std::vector<std::string> next_m = m.empty() ? std::vector<std::string>{""} : m;
        for ( const std::string &x : next_m )
        {
          for ( const std::string &r : old_v )
          {
            v.push_back(r + x);
          }
        }
      }
      return v;
    }
    if ( ctyp.kind == CType::Kind::UnsizedArray )
    {
      std::string res = ctyp.unsized_array_elem + "\n";
      std::vector<std::string> v{res};
      std::vector<std::string> inner = internal_formatted_types_for(
          ctyp.unsized_array_elem, visited, fuel - 1, separated_unions);
      std::vector<std::string> next_inner =
          inner.empty() ? std::vector<std::string>{""} : inner;
      std::vector<std::string> old_v;
      old_v.swap(v);
      for ( const std::string &x : next_inner )
      {
        for ( const std::string &r : old_v )
        {
          v.push_back(r + x);
        }
      }
      return v;
    }
  }

  // Else: typ is a primitive / pointer / array name not in ctypes.
  if ( !typ.empty() && typ.back() == '*' )
  {
    std::string res = typ + "\n";
    std::vector<std::string> v{res};
    // Trim trailing *'s and any trailing whitespace.
    std::string inner = typ;
    while ( !inner.empty() && inner.back() == '*' ) inner.pop_back();
    while ( !inner.empty() && (inner.back() == ' ' || inner.back() == '\t') )
      inner.pop_back();
    std::vector<std::string> m = internal_formatted_types_for(
        inner, visited, fuel - 1, separated_unions);
    std::vector<std::string> next_m = m.empty() ? std::vector<std::string>{""} : m;
    std::vector<std::string> old_v;
    old_v.swap(v);
    for ( const std::string &x : next_m )
    {
      for ( const std::string &r : old_v )
      {
        v.push_back(r + x);
      }
    }
    return v;
  }
  if ( !typ.empty() && typ.back() == ']' )
  {
    std::string res = typ + "\n";
    std::vector<std::string> v{res};
    const size_t open = typ.rfind('[');
    std::string elem = (open == std::string::npos) ? typ : typ.substr(0, open);
    std::vector<std::string> m = internal_formatted_types_for(
        elem, visited, fuel - 1, separated_unions);
    std::vector<std::string> next_m = m.empty() ? std::vector<std::string>{""} : m;
    std::vector<std::string> old_v;
    old_v.swap(v);
    for ( const std::string &x : next_m )
    {
      for ( const std::string &r : old_v )
      {
        v.push_back(r + x);
      }
    }
    return v;
  }
  return {};
}

template <class ExtVar>
std::vector<std::string>
PrintableCTypes<ExtVar>::formatted_types_for(const std::string &type_name,
                                             bool separated_unions) const
{
  std::set<std::string> visited;
  std::vector<std::string> res = internal_formatted_types_for(
      type_name, &visited, 100, separated_unions);
  if ( res.empty() )
  {
    // Reachable only for primitives.
    bool is_primitive = (type_name == "code");
    if ( !is_primitive )
    {
      for ( BuiltIn b : all_builtins() )
      {
        if ( builtin_to_printable(b) == type_name )
        {
          is_primitive = true;
          break;
        }
      }
    }
    TREX_CHECK(is_primitive,
               "Only builtins should reach this branch, got %s",
               type_name.c_str());
    return {type_name};
  }
  if ( !separated_unions )
  {
    TREX_CHECK(res.size() == 1,
               "Expected only one element for %s, got %zu items",
               type_name.c_str(), res.size());
  }
  for ( const std::string &s : res )
  {
    if ( s.find("out-of-fuel") != std::string::npos )
    {
      TREX_UNREACHABLE("Infinite recursion detected for type %s", type_name.c_str());
    }
  }
  return res;
}

// The class template's member definitions live in this TU, so the instantiations actually used
// must be spelled out here (ExternalVariable is the only variable type the pipeline uses).
template class PrintableCTypes<ExternalVariable>;

} // namespace trex
