// Serialize structural types — implementation. Port of
// `third_party/trex/trex/src/serialize_structural.rs` (359 lines).
//
// Faithfulness notes:
//   * The text format is load-bearing for the S7 differential gate (byte-for-byte
//     comparison against the Rust oracle). Every detail matters:
//       - VAR_MAP header is a single line, followed by one `\t<var>\t<type>` line per
//         varmap entry, then a single blank line.
//       - STRUCTURAL_TYPES header is a single line, followed by one or more
//         `struct` blocks. Each block starts with `\t<name>`, then contains zero or
//         more `\t\t<FIELD>\t<value>` or `\t\t<FIELD>` lines, then a blank line.
//       - The set of FIELDs emitted in order is: UPPER_BOUND_SIZE, COPY_SIZES,
//         ZERO_COMPARABLE, POINTER_TO, OBSERVED_BOOLEAN, INTEGER_OPS, BOOLEAN_OPS,
//         FLOAT_OPS, OBSERVED_CODE, COLOCATED_STRUCT_FIELDS (one per entry),
//         OBSERVED_ARRAY, IS_TYPE_FOR_IL_CONSTANT_VARIABLE.
//       - IntegerOp/BooleanOp/FloatOp display names use the upstream `Debug` output
//         (PascalCase variant name).
//   * The worklist algorithm is: start with `queue = varmap.values()` (in key order),
//     `seen = {}`. Pop one, canonicalize, dedupe, then enqueue `typ.refers_to()` and
//     print the block. The queue order therefore follows the upstream BFS
//     exactly. The inner macros (`_`, `b`, `opsset`, `s`, `o`) mirror upstream's
//     `w!` macro family line-for-line.
//   * The `type_names` assertion (`!starts_with("__t")`, no whitespace) is preserved
//     verbatim from upstream lines 34-36.

#include <trex/serialize_structural.hpp>

#include <cstddef>
#include <deque>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace trex {

namespace {

// ---------------------------------------------------------------------------
// Small formatting helpers
// ---------------------------------------------------------------------------

/// Upstream `format!("{:?}", op)` — for op enums whose Rust `Debug` derives the
/// PascalCase variant name. Mirrors upstream: `IntegerOp::Add` -> `"Add"`, etc.
std::string op_debug_name(IntegerOp op)
{
  switch ( op )
  {
    case IntegerOp::Add: return "Add";
    case IntegerOp::Sub: return "Sub";
    case IntegerOp::Mult: return "Mult";
    case IntegerOp::UDiv: return "UDiv";
    case IntegerOp::SDiv: return "SDiv";
    case IntegerOp::URem: return "URem";
    case IntegerOp::SRem: return "SRem";
    case IntegerOp::And: return "And";
    case IntegerOp::Or: return "Or";
    case IntegerOp::Xor: return "Xor";
    case IntegerOp::Eq: return "Eq";
    case IntegerOp::Neq: return "Neq";
    case IntegerOp::ULt: return "ULt";
    case IntegerOp::SLt: return "SLt";
    case IntegerOp::UCarry: return "UCarry";
    case IntegerOp::SCarry: return "SCarry";
    case IntegerOp::SBorrow: return "SBorrow";
    case IntegerOp::OnesComplement: return "OnesComplement";
    case IntegerOp::TwosComplement: return "TwosComplement";
    case IntegerOp::Popcount: return "Popcount";
    case IntegerOp::ZeroExtendSrc: return "ZeroExtendSrc";
    case IntegerOp::SignExtendSrc: return "SignExtendSrc";
    case IntegerOp::ZeroExtendTgt: return "ZeroExtendTgt";
    case IntegerOp::SignExtendTgt: return "SignExtendTgt";
    case IntegerOp::LeftShift: return "LeftShift";
    case IntegerOp::URightShift: return "URightShift";
    case IntegerOp::SRightShift: return "SRightShift";
    case IntegerOp::ShiftAmount: return "ShiftAmount";
    case IntegerOp::ConvertToFloat: return "ConvertToFloat";
    case IntegerOp::ConvertFromFloatTrunc: return "ConvertFromFloatTrunc";
  }
  return "?";
}

std::string op_debug_name(BooleanOp op)
{
  switch ( op )
  {
    case BooleanOp::Negate: return "Negate";
    case BooleanOp::And: return "And";
    case BooleanOp::Or: return "Or";
    case BooleanOp::Xor: return "Xor";
  }
  return "?";
}

std::string op_debug_name(FloatOp op)
{
  switch ( op )
  {
    case FloatOp::Add: return "Add";
    case FloatOp::Sub: return "Sub";
    case FloatOp::Mult: return "Mult";
    case FloatOp::Div: return "Div";
    case FloatOp::Eq: return "Eq";
    case FloatOp::Neq: return "Neq";
    case FloatOp::Lt: return "Lt";
    case FloatOp::LEq: return "LEq";
    case FloatOp::Sqrt: return "Sqrt";
    case FloatOp::Abs: return "Abs";
    case FloatOp::Neg: return "Neg";
    case FloatOp::Ceil: return "Ceil";
    case FloatOp::Floor: return "Floor";
    case FloatOp::Round: return "Round";
    case FloatOp::ConvertFromInt: return "ConvertFromInt";
    case FloatOp::ConvertToIntTrunc: return "ConvertToIntTrunc";
    case FloatOp::ConvertFromDifferentSizedFloat: return "ConvertFromDifferentSizedFloat";
    case FloatOp::ConvertToDifferentSizedFloat: return "ConvertToDifferentSizedFloat";
  }
  return "?";
}

} // namespace

// ===========================================================================
// SerializableStructuralTypes<Var>
// ===========================================================================

template <class Var>
SerializableStructuralTypes<Var>::SerializableStructuralTypes(
    std::map<Var, Index> varmap,
    IndexMap<std::string> type_names,
    Container<StructuralType> types)
{
  // Mirrors upstream `new`: collect all the values, then garbage-collect against
  // those roots so unreferenced types are dropped before serialization.
  std::vector<Index> roots;
  roots.reserve(varmap.size());
  for ( const auto &kv : varmap )
  {
    roots.push_back(kv.second);
  }
  types.garbage_collect_with_roots(roots);

  // Assert on type_names — no name may start with "__t" and no name may contain
  // whitespace. Mirrors upstream assertion at lines 34-36 exactly.
  for ( const auto &kv : type_names.iter() )
  {
    const std::string &name = kv.second;
    TREX_CHECK(name.find("__t") != 0,
               "SerializableStructuralTypes: type_names must not start with __t (got %s)",
               name.c_str());
    for ( char c : name )
    {
      TREX_CHECK(c != ' ' && c != '\n' && c != '\t',
                 "SerializableStructuralTypes: type_names must not contain whitespace "
                 "(name=%s, char=%d)",
                 name.c_str(), int(c));
    }
  }

  varmap_ = std::move(varmap);
  type_names_ = std::move(type_names);
  types_ = std::move(types);
}

template <class Var>
std::string SerializableStructuralTypes<Var>::serialize() const
{
  std::string f;
  serialize_to(f);
  return f;
}

template <class Var>
std::optional<std::string> SerializableStructuralTypes<Var>::try_type_name(Index idx) const
{
  const Index canon = types_.get_canonical_index(idx);
  const std::string *p = type_names_.get(canon);
  if ( p == nullptr ) return std::nullopt;
  return *p;
}

template <class Var>
std::string SerializableStructuralTypes<Var>::type_name(Index idx) const
{
  const Index canon = types_.get_canonical_index(idx);
  const size_t canon_idx = canon.idx;

  if ( type_names_.is_empty() )
  {
    // Upstream `format!("t{}", idx)` when no name has been assigned and no
    // user-supplied names exist.
    return "t" + std::to_string(canon_idx);
  }
  const std::string *p = type_names_.get(canon);
  if ( p != nullptr ) return *p;
  // Fallback: synthetic `__t{idx}` name (mirrors upstream lines 76-77).
  return "__t" + std::to_string(canon_idx);
}

template <class Var>
void SerializableStructuralTypes<Var>::serialize_to(std::string &f) const
{
  // Mirrors upstream `serialize_to` lines 92-190 exactly. The worklist algorithm is:
  //   queue = self.map.values() (in key order)
  //   seen  = {}
  //   while !queue.is_empty():
  //     idx = queue.pop()
  //     canon = canonicalize(idx)
  //     if canon in seen: continue
  //     seen.insert(canon)
  //     queue.extend(typ.refers_to())
  //     print block
  // Note: `pop()` in Rust is stack-style (LIFO); `queue.pop()` in the C++ port is
  // likewise the end of a `std::vector` (mirroring Rust `Vec::pop`). The initial
  // ordering is key-sorted (BTreeMap order upstream = std::map order in the port).
  std::vector<Index> queue;
  queue.reserve(varmap_.size());
  for ( const auto &kv : varmap_ )
  {
    queue.push_back(kv.second);
  }

  std::set<Index> seen;

  // VAR_MAP block.
  f += "VAR_MAP\n";
  for ( const auto &kv : varmap_ )
  {
    // We render `var` with `std::ostream << var` — the upstream uses `{}` formatting,
    // which calls `<Var as Display>::fmt`. The Var type is expected to provide
    // `operator<<` (the C++ analogue of `Display`).
    std::ostringstream vs;
    vs << kv.first;
    f += "\t";
    f += vs.str();
    f += "\t";
    f += type_name(kv.second);
    f += "\n";
  }
  f += "\n";

  // STRUCTURAL_TYPES block.
  f += "STRUCTURAL_TYPES\n";

  while ( !queue.empty() )
  {
    const Index raw_idx = queue.back();
    queue.pop_back();
    const Index idx = types_.get_canonical_index(raw_idx);
    if ( !seen.insert(idx).second )
    {
      continue;
    }

    const StructuralType &typ = types_[idx];
    // Upstream: `queue.extend(typ.refers_to())`. We push the referred-to indices
    // onto the back of the queue; the `seen` set will dedupe. Note that
    // `refers_to()` returns owned `std::vector<Index>` (per the Container API).
    const auto referred = typ.refers_to();
    for ( const Index &r : referred )
    {
      queue.push_back(r);
    }

    f += "\t";
    f += type_name(idx);
    f += "\n";

    // Mirrors upstream's `w!` macro family — five variants (`_`, `b`, `opsset`, `s`,
    // `o`). Each `w!` is inlined below in the same order as upstream.
    //
    // `w!(o upper_bound_size |&t| t)` — Option<FIELD>: emit "FIELD\tVALUE" only if Some.
    if ( typ.upper_bound_size.has_value() )
    {
      f += "\t\tUPPER_BOUND_SIZE\t";
      f += std::to_string(*typ.upper_bound_size);
      f += "\n";
    }
    // `w!(s copy_sizes)` — Set<FIELD>: emit "FIELD\t{:?}" if non-empty. The
    // upstream `{:?}` of `BTreeSet<usize>` is e.g. `{1, 2, 4}`.
    if ( !typ.copy_sizes.empty() )
    {
      std::set<size_t> ordered(typ.copy_sizes.begin(), typ.copy_sizes.end());
      f += "\t\tCOPY_SIZES\t{";
      bool first = true;
      for ( size_t v : ordered )
      {
        if ( !first ) f += ", ";
        first = false;
        f += std::to_string(v);
      }
      f += "}\n";
    }
    // `w!(b zero_comparable)` — Bool: emit just "FIELD" if true.
    if ( typ.zero_comparable )
    {
      f += "\t\tZERO_COMPARABLE\n";
    }
    // `w!(o pointer_to |&t| self.type_name(t))` — Option<Index>: emit name if Some.
    if ( typ.pointer_to.has_value() )
    {
      f += "\t\tPOINTER_TO\t";
      f += type_name(*typ.pointer_to);
      f += "\n";
    }
    if ( typ.observed_boolean )
    {
      f += "\t\tOBSERVED_BOOLEAN\n";
    }
    // `w!(opsset integer_ops)` — Set<(Op, usize)>: emit "FIELD\t{{Op_sz, ...}}"
    // if non-empty, in BTreeSet order.
    if ( !typ.integer_ops.empty() )
    {
      std::set<std::pair<IntegerOp, size_t>> ordered(typ.integer_ops.begin(),
                                                    typ.integer_ops.end());
      f += "\t\tINTEGER_OPS\t{";
      bool first = true;
      for ( const auto &kv : ordered )
      {
        if ( !first ) f += ", ";
        first = false;
        f += op_debug_name(kv.first);
        f += "_";
        f += std::to_string(kv.second);
      }
      f += "}\n";
    }
    if ( !typ.boolean_ops.empty() )
    {
      std::set<std::pair<BooleanOp, size_t>> ordered(typ.boolean_ops.begin(),
                                                    typ.boolean_ops.end());
      f += "\t\tBOOLEAN_OPS\t{";
      bool first = true;
      for ( const auto &kv : ordered )
      {
        if ( !first ) f += ", ";
        first = false;
        f += op_debug_name(kv.first);
        f += "_";
        f += std::to_string(kv.second);
      }
      f += "}\n";
    }
    if ( !typ.float_ops.empty() )
    {
      std::set<std::pair<FloatOp, size_t>> ordered(typ.float_ops.begin(),
                                                   typ.float_ops.end());
      f += "\t\tFLOAT_OPS\t{";
      bool first = true;
      for ( const auto &kv : ordered )
      {
        if ( !first ) f += ", ";
        first = false;
        f += op_debug_name(kv.first);
        f += "_";
        f += std::to_string(kv.second);
      }
      f += "}\n";
    }
    if ( typ.observed_code )
    {
      f += "\t\tOBSERVED_CODE\n";
    }
    // `w!(_ colocated_struct_fields ...)` — one entry per (offset, Index).
    // Upstream uses `colocated_struct_fields` in BTreeMap iteration order; the
    // port stores it as `std::map<uint64_t, Index>` which is already in key order.
    for ( const auto &kv : typ.colocated_struct_fields )
    {
      f += "\t\tCOLOCATED_STRUCT_FIELDS\t";
      f += std::to_string(kv.first);
      f += "\t";
      f += type_name(kv.second);
      f += "\n";
    }
    if ( typ.observed_array )
    {
      f += "\t\tOBSERVED_ARRAY\n";
    }
    if ( typ.is_type_for_il_constant_variable )
    {
      f += "\t\tIS_TYPE_FOR_IL_CONSTANT_VARIABLE\n";
    }
    // Blank line separator between structural-type blocks.
    f += "\n";
  }
}

// ===========================================================================
// Parser — `parse_serializable_structural_types`
// ===========================================================================

namespace detail {

template <class Var>
std::optional<SerializableStructuralTypes<Var>>
parse_serialize_impl(const std::string &s, VarParseFn<Var> parse_var)
{
  // Mirrors upstream `impl Parseable for SerializableStructuralTypes` lines 207-358.
  //
  // The format is:
  //   VAR_MAP\n
  //   \t<var>\t<type>\n          (zero or more)
  //   \n
  //   STRUCTURAL_TYPES\n
  //   \t<type>\n
  //   \t\t<FIELD>\t<value>\n     (zero or more)
  //   ...
  //   \n
  //   \t<type>\n
  //   ...
  //
  // Upstream filters out "[WARN]" lines and ignores blank lines mid-section. We
  // mirror the same.

  std::vector<std::string> lines;
  {
    std::istringstream iss(s);
    std::string line;
    while ( std::getline(iss, line) )
    {
      // Skip lines containing "[WARN]" — upstream filters them out (line 208).
      if ( line.find("[WARN]") != std::string::npos ) continue;
      lines.push_back(line);
    }
  }

  size_t cursor = 0;
  auto peek = [&]() -> const std::string &
  {
    TREX_CHECK(cursor < lines.size(),
               "parse_serialize_impl: unexpected end of input");
    return lines[cursor];
  };
  auto next = [&]() -> std::string
  {
    TREX_CHECK(cursor < lines.size(),
               "parse_serialize_impl: unexpected end of input");
    return lines[cursor++];
  };

  // "VAR_MAP" header
  TREX_CHECK(next() == "VAR_MAP",
             "parse_serialize_impl: expected VAR_MAP header, got line %zu", cursor);

  // The VAR_MAP entries are tab-prefixed (`\t<var>\t<type>`); the first
  // non-tab-prefixed line marks the end of VAR_MAP.
  SerializableStructuralTypes<Var> ret{
      std::map<Var, Index>{},
      IndexMap<std::string>{},
      Container<StructuralType>{}};
  // Build a local type-name -> Index map to track allocations.
  std::map<std::string, Index> type_name_map;

  auto ty = [&](const std::string &name) -> Index
  {
    auto it = type_name_map.find(name);
    if ( it != type_name_map.end() ) return it->second;
    const Index fresh = ret.types_mut().insert_default();
    type_name_map.insert({name, fresh});
    return fresh;
  };

  while ( cursor < lines.size() && !peek().empty() && peek()[0] == '\t' )
  {
    std::string line = next();
    // Strip the leading tab (one occurrence).
    TREX_CHECK(!line.empty() && line[0] == '\t',
               "parse_serialize_impl: expected tab-prefixed VAR_MAP line");
    line.erase(0, 1);
    // Split on remaining tabs: <var>\t<type>
    std::string var_part;
    std::string type_part;
    {
      const size_t tab = line.find('\t');
      TREX_CHECK(tab != std::string::npos,
                 "parse_serialize_impl: VAR_MAP line missing tab separator");
      var_part = line.substr(0, tab);
      type_part = line.substr(tab + 1);
    }
    std::optional<Var> parsed_var = parse_var(var_part);
    if ( !parsed_var.has_value() )
    {
      return std::nullopt;
    }
    const Index typ_idx = ty(type_part);
    auto inserted = ret.varmap_.insert({std::move(*parsed_var), typ_idx});
    (void)inserted;
    TREX_CHECK(inserted.second,
               "parse_serialize_impl: duplicate variable in VAR_MAP");
  }

  // Blank line between sections
  TREX_CHECK(cursor < lines.size() && next() == "",
             "parse_serialize_impl: expected blank line between sections");
  // STRUCTURAL_TYPES header
  TREX_CHECK(cursor < lines.size() && next() == "STRUCTURAL_TYPES",
             "parse_serialize_impl: expected STRUCTURAL_TYPES header");

  while ( cursor < lines.size() )
  {
    std::string line = next();
    if ( line.empty() )
    {
      continue;
    }
    TREX_CHECK(!line.empty() && line[0] == '\t',
               "parse_serialize_impl: expected tab-prefixed type name, got '%s'",
               line.c_str());
    line.erase(0, 1);
    const Index tyi = ty(line);
    StructuralType typ;

    while ( cursor < lines.size() && !peek().empty()
            && peek().compare(0, 2, "\t\t") == 0 )
    {
      std::string inner = next();
      // Strip the leading "\t\t"
      inner.erase(0, 2);
      const size_t tab = inner.find('\t');
      std::string desc;
      std::string body;
      if ( tab == std::string::npos )
      {
        desc = inner;
        body = "";
      }
      else
      {
        desc = inner.substr(0, tab);
        body = inner.substr(tab + 1);
      }

      if ( desc == "UPPER_BOUND_SIZE" )
      {
        typ.upper_bound_size = static_cast<size_t>(std::stoull(body));
      }
      else if ( desc == "COPY_SIZES" )
      {
        std::string trimmed = body;
        // Trim '{' and '}'
        if ( !trimmed.empty() && trimmed.front() == '{' ) trimmed.erase(0, 1);
        if ( !trimmed.empty() && trimmed.back() == '}' ) trimmed.pop_back();
        std::set<size_t> out;
        if ( !trimmed.empty() )
        {
          std::stringstream ts(trimmed);
          std::string item;
          while ( std::getline(ts, item, ',') )
          {
            // Trim whitespace.
            size_t a = 0;
            while ( a < item.size() && (item[a] == ' ' || item[a] == '\t') ) ++a;
            size_t b2 = item.size();
            while ( b2 > a && (item[b2 - 1] == ' ' || item[b2 - 1] == '\t') ) --b2;
            out.insert(static_cast<size_t>(std::stoull(item.substr(a, b2 - a))));
          }
        }
        typ.copy_sizes = std::move(out);
      }
      else if ( desc == "ZERO_COMPARABLE" )
      {
        typ.zero_comparable = true;
      }
      else if ( desc == "POINTER_TO" )
      {
        typ.pointer_to = ty(body);
      }
      else if ( desc == "OBSERVED_BOOLEAN" )
      {
        typ.observed_boolean = true;
      }
      else if ( desc == "INTEGER_OPS" )
      {
        std::string trimmed = body;
        if ( !trimmed.empty() && trimmed.front() == '{' ) trimmed.erase(0, 1);
        if ( !trimmed.empty() && trimmed.back() == '}' ) trimmed.pop_back();
        std::set<std::pair<IntegerOp, size_t>> out;
        if ( !trimmed.empty() )
        {
          std::stringstream ts(trimmed);
          std::string item;
          while ( std::getline(ts, item, ',') )
          {
            const size_t u = item.find('_');
            TREX_CHECK(u != std::string::npos,
                       "parse_serialize_impl: INTEGER_OPS item missing '_'");
            std::string opname = item.substr(0, u);
            std::string sz = item.substr(u + 1);
            // Trim whitespace.
            auto trim = [](std::string &x)
            {
              size_t a = 0;
              while ( a < x.size() && (x[a] == ' ' || x[a] == '\t') ) ++a;
              size_t b2 = x.size();
              while ( b2 > a && (x[b2 - 1] == ' ' || x[b2 - 1] == '\t') ) --b2;
              x = x.substr(a, b2 - a);
            };
            trim(opname);
            trim(sz);
            // Find the IntegerOp whose Debug name matches `opname`.
            bool found = false;
            for ( IntegerOp op : all_integer_ops() )
            {
              if ( op_debug_name(op) == opname )
              {
                out.insert({op, static_cast<size_t>(std::stoull(sz))});
                found = true;
                break;
              }
            }
            TREX_CHECK(found,
                       "parse_serialize_impl: unknown IntegerOp %s",
                       opname.c_str());
          }
        }
        typ.integer_ops = std::move(out);
      }
      else if ( desc == "BOOLEAN_OPS" )
      {
        std::string trimmed = body;
        if ( !trimmed.empty() && trimmed.front() == '{' ) trimmed.erase(0, 1);
        if ( !trimmed.empty() && trimmed.back() == '}' ) trimmed.pop_back();
        std::set<std::pair<BooleanOp, size_t>> out;
        if ( !trimmed.empty() )
        {
          std::stringstream ts(trimmed);
          std::string item;
          while ( std::getline(ts, item, ',') )
          {
            const size_t u = item.find('_');
            TREX_CHECK(u != std::string::npos,
                       "parse_serialize_impl: BOOLEAN_OPS item missing '_'");
            std::string opname = item.substr(0, u);
            std::string sz = item.substr(u + 1);
            auto trim = [](std::string &x)
            {
              size_t a = 0;
              while ( a < x.size() && (x[a] == ' ' || x[a] == '\t') ) ++a;
              size_t b2 = x.size();
              while ( b2 > a && (x[b2 - 1] == ' ' || x[b2 - 1] == '\t') ) --b2;
              x = x.substr(a, b2 - a);
            };
            trim(opname);
            trim(sz);
            bool found = false;
            for ( BooleanOp op : all_boolean_ops() )
            {
              if ( op_debug_name(op) == opname )
              {
                out.insert({op, static_cast<size_t>(std::stoull(sz))});
                found = true;
                break;
              }
            }
            TREX_CHECK(found,
                       "parse_serialize_impl: unknown BooleanOp %s",
                       opname.c_str());
          }
        }
        typ.boolean_ops = std::move(out);
      }
      else if ( desc == "FLOAT_OPS" )
      {
        std::string trimmed = body;
        if ( !trimmed.empty() && trimmed.front() == '{' ) trimmed.erase(0, 1);
        if ( !trimmed.empty() && trimmed.back() == '}' ) trimmed.pop_back();
        std::set<std::pair<FloatOp, size_t>> out;
        if ( !trimmed.empty() )
        {
          std::stringstream ts(trimmed);
          std::string item;
          while ( std::getline(ts, item, ',') )
          {
            const size_t u = item.find('_');
            TREX_CHECK(u != std::string::npos,
                       "parse_serialize_impl: FLOAT_OPS item missing '_'");
            std::string opname = item.substr(0, u);
            std::string sz = item.substr(u + 1);
            auto trim = [](std::string &x)
            {
              size_t a = 0;
              while ( a < x.size() && (x[a] == ' ' || x[a] == '\t') ) ++a;
              size_t b2 = x.size();
              while ( b2 > a && (x[b2 - 1] == ' ' || x[b2 - 1] == '\t') ) --b2;
              x = x.substr(a, b2 - a);
            };
            trim(opname);
            trim(sz);
            bool found = false;
            for ( FloatOp op : all_float_ops() )
            {
              if ( op_debug_name(op) == opname )
              {
                out.insert({op, static_cast<size_t>(std::stoull(sz))});
                found = true;
                break;
              }
            }
            TREX_CHECK(found,
                       "parse_serialize_impl: unknown FloatOp %s",
                       opname.c_str());
          }
        }
        typ.float_ops = std::move(out);
      }
      else if ( desc == "OBSERVED_CODE" )
      {
        typ.observed_code = true;
      }
      else if ( desc == "COLOCATED_STRUCT_FIELDS" )
      {
        const size_t tab2 = body.find('\t');
        TREX_CHECK(tab2 != std::string::npos,
                   "parse_serialize_impl: COLOCATED_STRUCT_FIELDS missing tab");
        std::string offset_str = body.substr(0, tab2);
        std::string coloidx_str = body.substr(tab2 + 1);
        size_t a = 0;
        while ( a < offset_str.size() && (offset_str[a] == ' ' || offset_str[a] == '\t') ) ++a;
        const uint64_t offset = static_cast<uint64_t>(std::stoull(offset_str.substr(a)));
        const Index co_idx = ty(coloidx_str);
        auto ins = typ.colocated_struct_fields.insert({offset, co_idx});
        (void)ins;
        TREX_CHECK(ins.second,
                   "parse_serialize_impl: duplicate COLOCATED_STRUCT_FIELDS offset");
      }
      else if ( desc == "OBSERVED_ARRAY" )
      {
        typ.observed_array = true;
      }
      else if ( desc == "IS_TYPE_FOR_IL_CONSTANT_VARIABLE" )
      {
        typ.is_type_for_il_constant_variable = true;
      }
      else
      {
        TREX_UNREACHABLE("parse_serialize_impl: unknown field '%s'", desc.c_str());
      }
    }

    ret.types_mut()[tyi] = std::move(typ);

    // Blank line separator (or end of input).
    if ( cursor < lines.size() )
    {
      TREX_CHECK(next() == "",
                 "parse_serialize_impl: expected blank line between type blocks");
    }
  }

  // Materialise the type_names IndexMap from the local type_name_map.
  for ( const auto &kv : type_name_map )
  {
    ret.type_names_.insert(kv.second, kv.first);
  }

  return ret;
}

} // namespace detail

// ===========================================================================
// Explicit template instantiations are intentionally omitted — this header is
// instantiated for each `Var` type on demand.
// ===========================================================================

// We still need a single anchor so the compiler emits the template's definitions
// in this TU; users instantiate it explicitly via `parse_serializable_structural_types`.
// No out-of-line definitions are required because the template's body lives here.

// The class template's member definitions live in this TU; spell out the instantiations the
// pipeline uses (ExternalVariable is the only variable type that reaches serialization).
template class SerializableStructuralTypes<ExternalVariable>;

} // namespace trex
