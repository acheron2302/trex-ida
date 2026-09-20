// C types — implementation. Port of `third_party/trex/trex/src/c_types.rs` (677 lines).
//
// Faithfulness notes:
//   * The `update_structural` queue is a `std::deque<std::pair<std::string, CType>>`
//     and is initialised from `UnorderedMap::iter()`, which is `std::map` order. The
//     Rust upstream's `BTreeMap::iter()` is also in key order, so the iteration order
//     of the queue matches upstream exactly.
//   * The two `with_FORCE_*_set` dynamic-variable guards are set for the duration of
//     each join, exactly as upstream does. They are `trex`-namespace free templates in
//     `structural.hpp`; we include that header transitively through `c_types.hpp`.
//   * `set_upper_and_copy_size` is an exact transcription of the upstream helper,
//     including the `_ => unreachable!()` arm.
//   * `is_undefined_padding` compares every field of `StructuralType` — this is
//     necessary because Rust's destructuring `let StructuralType { ... } = s;` checks
//     all fields, and any extra field added later would silently flip the result.
//   * `sign_normalized_c_primitives` calls
//     `structural_types_for_all_primitive_c_types` and asserts the key-count matches the
//     hardcoded `map`. The hardcoded table is upstream's literal.

#include <trex/c_types.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>
#include <trex/inference_config.hpp>

namespace trex {

// ===========================================================================
// BuiltIn helpers
// ===========================================================================

std::string builtin_debug_name(BuiltIn b)
{
  // Upstream `format!("{:?}", b)` — Rust's derived Debug prints the enum variant name
  // as a PascalCase identifier. Match the upstream variant spellings exactly.
  switch ( b )
  {
    case BuiltIn::Void:       return "Void";
    case BuiltIn::Bool:       return "Bool";
    case BuiltIn::Char:       return "Char";
    case BuiltIn::UChar:      return "UChar";
    case BuiltIn::WCharT:     return "WCharT";
    case BuiltIn::ShortShort: return "ShortShort";
    case BuiltIn::UShortShort:return "UShortShort";
    case BuiltIn::Short:      return "Short";
    case BuiltIn::UShort:     return "UShort";
    case BuiltIn::Int:        return "Int";
    case BuiltIn::Uint:       return "Uint";
    case BuiltIn::Long:       return "Long";
    case BuiltIn::ULong:      return "ULong";
    case BuiltIn::SInt128:    return "SInt128";
    case BuiltIn::UInt128:    return "UInt128";
    case BuiltIn::SInt256:    return "SInt256";
    case BuiltIn::UInt256:    return "UInt256";
    case BuiltIn::Float:      return "Float";
    case BuiltIn::Double:     return "Double";
    case BuiltIn::LongDouble: return "LongDouble";
    case BuiltIn::Undefined:  return "Undefined";
    case BuiltIn::Undefined1: return "Undefined1";
    case BuiltIn::Undefined2: return "Undefined2";
    case BuiltIn::Undefined4: return "Undefined4";
    case BuiltIn::Undefined8: return "Undefined8";
  }
  TREX_UNREACHABLE("unknown BuiltIn");
}

std::vector<BuiltIn> all_builtins()
{
  // Order matches upstream declaration order exactly. Iteration order is the order
  // here; downstream consumers iterate this and use it as a positional map.
  return {
    BuiltIn::Void,
    BuiltIn::Bool,
    BuiltIn::Char,
    BuiltIn::UChar,
    BuiltIn::WCharT,
    BuiltIn::ShortShort,
    BuiltIn::UShortShort,
    BuiltIn::Short,
    BuiltIn::UShort,
    BuiltIn::Int,
    BuiltIn::Uint,
    BuiltIn::Long,
    BuiltIn::ULong,
    BuiltIn::SInt128,
    BuiltIn::UInt128,
    BuiltIn::SInt256,
    BuiltIn::UInt256,
    BuiltIn::Float,
    BuiltIn::Double,
    BuiltIn::LongDouble,
    BuiltIn::Undefined,
    BuiltIn::Undefined1,
    BuiltIn::Undefined2,
    BuiltIn::Undefined4,
    BuiltIn::Undefined8,
  };
}

std::string builtin_to_printable(BuiltIn b)
{
  // Upstream `BuiltIn::to_printable` — the C spelling of each variant.
  switch ( b )
  {
    case BuiltIn::Void:       return "void";
    case BuiltIn::Bool:       return "bool";
    case BuiltIn::Char:       return "char";
    case BuiltIn::UChar:      return "unsigned char";
    case BuiltIn::WCharT:     return "wchar_t";
    case BuiltIn::ShortShort: return "int8_t";
    case BuiltIn::UShortShort:return "uint8_t";
    case BuiltIn::Short:      return "int16_t";
    case BuiltIn::UShort:     return "uint16_t";
    case BuiltIn::Int:        return "int32_t";
    case BuiltIn::Uint:       return "uint32_t";
    case BuiltIn::Long:       return "int64_t";
    case BuiltIn::ULong:      return "uint64_t";
    case BuiltIn::SInt128:    return "int128_t";
    case BuiltIn::UInt128:    return "uint128_t";
    case BuiltIn::SInt256:    return "int256_t";
    case BuiltIn::UInt256:    return "uint256_t";
    case BuiltIn::Float:      return "float";
    case BuiltIn::Double:     return "double";
    case BuiltIn::LongDouble: return "long double";
    case BuiltIn::Undefined:  return "undefined";
    case BuiltIn::Undefined1: return "undefined1";
    case BuiltIn::Undefined2: return "undefined2";
    case BuiltIn::Undefined4: return "undefined4";
    case BuiltIn::Undefined8: return "undefined8";
  }
  TREX_UNREACHABLE("unknown BuiltIn");
}

// ===========================================================================
// CType
// ===========================================================================

static CType make_builtin(BuiltIn b) noexcept
{
  CType c;
  c.kind = CType::Kind::BuiltIn;
  c.builtin = b;
  return c;
}
CType CType::make_builtin(BuiltIn b) noexcept { return ::trex::make_builtin(b); }

static CType make_union(std::vector<std::string> members)
{
  CType c;
  c.kind = CType::Kind::Union;
  c.union_members = std::move(members);
  return c;
}
CType CType::make_union(std::vector<std::string> members) { return ::trex::make_union(std::move(members)); }

static CType make_struct(std::vector<std::pair<size_t, std::string>> fields)
{
  CType c;
  c.kind = CType::Kind::Struct;
  c.struct_fields = std::move(fields);
  return c;
}
CType CType::make_struct(std::vector<std::pair<size_t, std::string>> fields)
{
  return ::trex::make_struct(std::move(fields));
}

static CType make_typedef(std::string target)
{
  CType c;
  c.kind = CType::Kind::TypeDef;
  c.typedef_target = std::move(target);
  return c;
}
CType CType::make_typedef(std::string target) { return ::trex::make_typedef(std::move(target)); }

static CType make_pointer(size_t sz, std::string target)
{
  CType c;
  c.kind = CType::Kind::Pointer;
  c.pointer_size = sz;
  c.pointer_target = std::move(target);
  return c;
}
CType CType::make_pointer(size_t sz, std::string target)
{
  return ::trex::make_pointer(sz, std::move(target));
}

static CType make_enum(size_t sz, std::vector<int32_t> values)
{
  CType c;
  c.kind = CType::Kind::Enum;
  c.enum_size = sz;
  c.enum_values = std::move(values);
  return c;
}
CType CType::make_enum(size_t sz, std::vector<int32_t> values)
{
  return ::trex::make_enum(sz, std::move(values));
}

static CType make_fixed_array(std::string elem, size_t elem_sz, size_t count)
{
  CType c;
  c.kind = CType::Kind::FixedSizeArray;
  c.fixed_array_elem = std::move(elem);
  c.fixed_array_elem_size = elem_sz;
  c.fixed_array_count = count;
  return c;
}
CType CType::make_fixed_array(std::string elem, size_t elem_sz, size_t count)
{
  return ::trex::make_fixed_array(std::move(elem), elem_sz, count);
}

static CType make_unsized_array(std::string elem)
{
  CType c;
  c.kind = CType::Kind::UnsizedArray;
  c.unsized_array_elem = std::move(elem);
  return c;
}
CType CType::make_unsized_array(std::string elem)
{
  return ::trex::make_unsized_array(std::move(elem));
}

CType CType::make_code() noexcept
{
  CType c;
  c.kind = CType::Kind::Code;
  return c;
}

bool operator==(const CType &a, const CType &b)
{
  if ( a.kind != b.kind )
    return false;
  switch ( a.kind )
  {
    case CType::Kind::BuiltIn:        return a.builtin == b.builtin;
    case CType::Kind::Union:          return a.union_members == b.union_members;
    case CType::Kind::Struct:         return a.struct_fields == b.struct_fields;
    case CType::Kind::TypeDef:        return a.typedef_target == b.typedef_target;
    case CType::Kind::Pointer:        return a.pointer_size == b.pointer_size
                                       && a.pointer_target == b.pointer_target;
    case CType::Kind::Enum:           return a.enum_size == b.enum_size
                                       && a.enum_values == b.enum_values;
    case CType::Kind::FixedSizeArray: return a.fixed_array_elem == b.fixed_array_elem
                                       && a.fixed_array_elem_size == b.fixed_array_elem_size
                                       && a.fixed_array_count == b.fixed_array_count;
    case CType::Kind::UnsizedArray:   return a.unsized_array_elem == b.unsized_array_elem;
    case CType::Kind::Code:           return true;
  }
  return false;
}

bool operator<(const CType &a, const CType &b)
{
  // Mirrors upstream `derive(PartialOrd, Ord)` — discriminant first, then payload
  // fields in declaration order.
  if ( a.kind != b.kind )
    return static_cast<uint8_t>(a.kind) < static_cast<uint8_t>(b.kind);
  switch ( a.kind )
  {
    case CType::Kind::BuiltIn:        return static_cast<uint8_t>(a.builtin) < static_cast<uint8_t>(b.builtin);
    case CType::Kind::Union:          return a.union_members < b.union_members;
    case CType::Kind::Struct:         return a.struct_fields < b.struct_fields;
    case CType::Kind::TypeDef:        return a.typedef_target < b.typedef_target;
    case CType::Kind::Pointer:        if ( a.pointer_size != b.pointer_size ) return a.pointer_size < b.pointer_size;
                                       return a.pointer_target < b.pointer_target;
    case CType::Kind::Enum:           if ( a.enum_size != b.enum_size ) return a.enum_size < b.enum_size;
                                       return a.enum_values < b.enum_values;
    case CType::Kind::FixedSizeArray: if ( a.fixed_array_elem != b.fixed_array_elem ) return a.fixed_array_elem < b.fixed_array_elem;
                                       if ( a.fixed_array_elem_size != b.fixed_array_elem_size ) return a.fixed_array_elem_size < b.fixed_array_elem_size;
                                       return a.fixed_array_count < b.fixed_array_count;
    case CType::Kind::UnsizedArray:   return a.unsized_array_elem < b.unsized_array_elem;
    case CType::Kind::Code:           return false;
  }
  return false;
}

// ===========================================================================
// is_undefined_padding / get_undefined_padding
// ===========================================================================

bool is_undefined_padding(const StructuralType &s)
{
  // Mirrors upstream's destructuring `let StructuralType { ... } = s;` — every field
  // is matched; if any future field is added, this check must extend too.
  return s.upper_bound_size == std::optional<size_t>(1)
         && s.copy_sizes.empty()
         && !s.zero_comparable
         && !s.pointer_to.has_value()
         && !s.observed_boolean
         && s.integer_ops.empty()
         && s.boolean_ops.empty()
         && s.float_ops.empty()
         && !s.observed_code
         && s.colocated_struct_fields.empty()
         && !s.observed_array
         && !s.is_type_for_il_constant_variable;
}

StructuralType get_undefined_padding()
{
  StructuralType ret;
  ret.set_upper_bound_size(1);
  return ret;
}

// ===========================================================================
// Internal: set_upper_and_copy_size helper
// ===========================================================================

namespace {

void set_upper_and_copy_size(StructuralType &out, size_t sz)
{
  // Mirrors upstream `set_upper_and_copy_size` lines 163-174 exactly.
  switch ( sz )
  {
    case 1:  out.copy_sizes.insert(1); break;
    case 2:  out.copy_sizes.insert(1); out.copy_sizes.insert(2); break;
    case 4:  out.copy_sizes.insert(1); out.copy_sizes.insert(2); out.copy_sizes.insert(4); break;
    case 8:  out.copy_sizes.insert(1); out.copy_sizes.insert(2); out.copy_sizes.insert(4); out.copy_sizes.insert(8); break;
    case 16: out.copy_sizes.insert(1); out.copy_sizes.insert(2); out.copy_sizes.insert(4); out.copy_sizes.insert(8); out.copy_sizes.insert(16); break;
    case 32: out.copy_sizes.insert(1); out.copy_sizes.insert(2); out.copy_sizes.insert(4); out.copy_sizes.insert(8); out.copy_sizes.insert(16); out.copy_sizes.insert(32); break;
    default:
      TREX_UNREACHABLE("set_upper_and_copy_size(..., %zu)", sz);
  }
  out.set_upper_bound_size(sz);
}

} // namespace

// ===========================================================================
// update_structural — upstream `fn update_structural`
// ===========================================================================

bool update_structural(const CType &ctype,
                       const std::string &name,
                       STypes &stypes,
                       const unordered::UnorderedSet<std::string> &completed)
{
  // Mirrors upstream `update_structural` lines 220-545, including the inner-loop
  // reborrow pattern (`stypes.types[this_idx]` is reborrowed multiple times within a
  // single arm because Rust's borrow checker forbids holding one mut borrow while
  // accessing another field of the same struct).

  // Look up the canonical index for `name`, creating a default-constructed type slot
  // if not yet present. The `entry().or_insert_with(...)` pattern in Rust maps to
  // the same try_emplace idiom in the port.
  Index this_idx;
  {
    Index *existing = stypes.type_map.get_mut(name);
    if ( existing == nullptr )
    {
      Index fresh = stypes.types.insert(StructuralType{});
      stypes.type_map.insert(name, fresh);
      this_idx = fresh;
    }
    else
    {
      this_idx = *existing;
    }
  }

  bool success;
  switch ( ctype.kind )
  {
    case CType::Kind::BuiltIn:
    {
      const BuiltIn t = ctype.builtin;
      if ( t == BuiltIn::Void )
      {
        // XXX: Is there a different representation that would be better here?
        success = true;
      }
      else if ( t == BuiltIn::Undefined )
      {
        stypes.types[this_idx].set_upper_bound_size(1); // Explicitly not setting copy size here
        // XXX: We should probably explicitly mark this as undefined somehow? Seems to
        // only be used for padding purposes in structs.
        TREX_CHECK(is_undefined_padding(stypes.types[this_idx]),
                   "CType::BuiltIn(Undefined) must produce undefined-padding type");
        success = true;
      }
      else if ( t == BuiltIn::Undefined1 )
      {
        set_upper_and_copy_size(stypes.types[this_idx], 1);
        success = true;
      }
      else if ( t == BuiltIn::Undefined2 )
      {
        set_upper_and_copy_size(stypes.types[this_idx], 2);
        success = true;
      }
      else if ( t == BuiltIn::Undefined4 )
      {
        set_upper_and_copy_size(stypes.types[this_idx], 4);
        success = true;
      }
      else if ( t == BuiltIn::Undefined8 )
      {
        set_upper_and_copy_size(stypes.types[this_idx], 8);
        success = true;
      }
      else if ( t == BuiltIn::Bool )
      {
        set_upper_and_copy_size(stypes.types[this_idx], 1);
        stypes.types[this_idx].observed_boolean = true;
        stypes.types[this_idx].zero_comparable = true;
        for ( BooleanOp o : all_boolean_ops() )
        {
          stypes.types[this_idx].boolean_ops.insert({o, 1});
        }
        success = true;
      }
      else if ( t == BuiltIn::Char || t == BuiltIn::UChar || t == BuiltIn::WCharT )
      {
        bool is_signed;
        size_t sz;
        switch ( t )
        {
          case BuiltIn::Char:   is_signed = true;  sz = 1; break;
          case BuiltIn::UChar:  is_signed = false; sz = 1; break;
          case BuiltIn::WCharT: is_signed = true;  sz = 4; break;
          default: TREX_UNREACHABLE("unreachable Char/UChar/WCharT branch");
        }
        set_upper_and_copy_size(stypes.types[this_idx], sz);
        stypes.types[this_idx].zero_comparable = true;
        for ( IntegerOp o : char_integer_ops(is_signed) )
        {
          stypes.types[this_idx].integer_ops.insert({o, sz});
        }
        success = true;
      }
      else if ( t == BuiltIn::ShortShort
              || t == BuiltIn::UShortShort
              || t == BuiltIn::Short
              || t == BuiltIn::UShort
              || t == BuiltIn::Int
              || t == BuiltIn::Uint
              || t == BuiltIn::Long
              || t == BuiltIn::ULong
              || t == BuiltIn::SInt128
              || t == BuiltIn::UInt128
              || t == BuiltIn::SInt256
              || t == BuiltIn::UInt256 )
      {
        bool is_signed;
        size_t sz;
        switch ( t )
        {
          case BuiltIn::ShortShort: is_signed = true;  sz = 1; break;
          case BuiltIn::UShortShort:is_signed = false; sz = 1; break;
          case BuiltIn::Short:      is_signed = true;  sz = 2; break;
          case BuiltIn::UShort:     is_signed = false; sz = 2; break;
          case BuiltIn::Int:        is_signed = true;  sz = 4; break;
          case BuiltIn::Uint:       is_signed = false; sz = 4; break;
          case BuiltIn::Long:       is_signed = true;  sz = 8; break;
          case BuiltIn::ULong:      is_signed = false; sz = 8; break;
          case BuiltIn::SInt128:    is_signed = true;  sz = 16; break;
          case BuiltIn::UInt128:    is_signed = false; sz = 16; break;
          case BuiltIn::SInt256:    is_signed = true;  sz = 32; break;
          case BuiltIn::UInt256:    is_signed = false; sz = 32; break;
          default: TREX_UNREACHABLE("unreachable integer built-in branch");
        }
        set_upper_and_copy_size(stypes.types[this_idx], sz);
        stypes.types[this_idx].zero_comparable = true;
        const InferenceConfig &cfg = config();
        if ( is_signed )
        {
          const std::vector<IntegerOp> &all_ops_v = all_integer_ops();
          const std::vector<IntegerOp> &signed_ops_v = signed_integer_ops();
          const std::vector<IntegerOp> &ops = cfg.signed_integers_support_all_integer_ops
                                                  ? all_ops_v
                                                  : signed_ops_v;
          for ( IntegerOp o : ops )
          {
            stypes.types[this_idx].integer_ops.insert({o, sz});
          }
          if ( cfg.additionally_include_next_size_nonlinear_ops_for_integers )
          {
            stypes.types[this_idx].integer_ops.insert({IntegerOp::SDiv, sz * 2});
            stypes.types[this_idx].integer_ops.insert({IntegerOp::SRem, sz * 2});
            stypes.types[this_idx].integer_ops.insert({IntegerOp::Mult, sz * 2});
          }
          if ( cfg.signed_integers_support_all_integer_ops
               && cfg.additionally_include_next_size_nonlinear_ops_for_integers )
          {
            stypes.types[this_idx].integer_ops.insert({IntegerOp::UDiv, sz * 2});
            stypes.types[this_idx].integer_ops.insert({IntegerOp::URem, sz * 2});
          }
        }
        else
        {
          for ( IntegerOp o : unsigned_integer_ops() )
          {
            stypes.types[this_idx].integer_ops.insert({o, sz});
          }
          if ( cfg.additionally_include_next_size_nonlinear_ops_for_integers )
          {
            stypes.types[this_idx].integer_ops.insert({IntegerOp::UDiv, sz * 2});
            stypes.types[this_idx].integer_ops.insert({IntegerOp::URem, sz * 2});
            stypes.types[this_idx].integer_ops.insert({IntegerOp::Mult, sz * 2});
          }
        }
        success = true;
      }
      else if ( t == BuiltIn::Float || t == BuiltIn::Double || t == BuiltIn::LongDouble )
      {
        size_t sz;
        switch ( t )
        {
          case BuiltIn::Float:      sz = 4; break;
          case BuiltIn::Double:     sz = 8; break;
          case BuiltIn::LongDouble: sz = 16; break; // XXX: Is this reasonable?
          default: TREX_UNREACHABLE("unreachable float built-in branch");
        }
        set_upper_and_copy_size(stypes.types[this_idx], sz);
        if ( t == BuiltIn::LongDouble )
        {
          // 80- and 96-bit "long double"s are quite common
          stypes.types[this_idx].copy_sizes.insert(10);
          stypes.types[this_idx].copy_sizes.insert(12);
          // We don't update upper bound size because it is set to 16 already.
        }
        stypes.types[this_idx].zero_comparable = true;
        // TODO: Is this actually zero-comparable? Why do we even have zero-comparable
        // around anymore?
        for ( FloatOp o : all_float_ops() )
        {
          stypes.types[this_idx].float_ops.insert({o, sz});
        }
        if ( t == BuiltIn::LongDouble )
        {
          // 80- and 96-bit "long double"s are quite common
          for ( size_t shorter_sz : {size_t(10), size_t(12)} )
          {
            for ( FloatOp o : all_float_ops() )
            {
              stypes.types[this_idx].float_ops.insert({o, shorter_sz});
            }
          }
        }
        success = true;
      }
      else
      {
        TREX_UNREACHABLE("unhandled BuiltIn variant in update_structural");
      }
      break;
    }

    case CType::Kind::Union:
    {
      const auto &u = ctype.union_members;
      bool all_done = true;
      for ( const std::string &t : u )
      {
        if ( !completed.contains(t) ) { all_done = false; break; }
      }
      if ( all_done )
      {
        for ( const std::string &t : u )
        {
          const Index t_idx_local = [&]{ const Index *p = stypes.type_map.get(t); TREX_CHECK(p != nullptr, "Union: type missing"); return *p; }();
          // The Rust call site does `stypes.types.clone_at(t_idx)` first, then joins
          // the clone into `this_idx`. The clone-and-join semantics are activated by
          // these two `with_*_set` RAII guards.
          Index t_idx = stypes.types.clone_at(t_idx_local);
          with_FORCE_CLONE_AND_JOIN_INSTEAD_OF_DIRECT_SCHEDULE_set([&]{
            with_FORCE_UPPER_BOUND_TO_BE_MAX_INSTEAD_OF_MIN_WHEN_JOINING_set([&]{
              stypes.types.join(this_idx, t_idx);
            });
          });
        }
        success = true;
      }
      else
      {
        success = false;
      }
      break;
    }

    case CType::Kind::TypeDef:
    {
      const std::string &t = ctype.typedef_target;
      if ( completed.contains(t) )
      {
        const Index *ti = stypes.type_map.get(t);
        TREX_CHECK(ti != nullptr,
                   "update_structural(CType::TypeDef): completed types should exist in map");
        stypes.types.join(*ti, this_idx);
        return true; // Early return — mirrors upstream's `return true;` here.
      }
      success = false;
      break;
    }

    case CType::Kind::Struct:
    {
      const auto &s = ctype.struct_fields;
      // Note: It _is_ feasible to relax this `completed` constraint a little
      // (specifically, only the head needs to be complete; the colocated members only
      // need to be named to be able to successfully complete a struct). However, we
      // do not do this for now, opting instead to expect a full completion.
      bool all_done = true;
      for ( const auto &field : s )
      {
        if ( !completed.contains(field.second) ) { all_done = false; break; }
      }
      if ( all_done )
      {
        if ( s.empty() )
        {
          stypes.types[this_idx].set_upper_bound_size(0);
        }
        else
        {
          bool all_undefined = true;
          for ( const auto &field : s )
          {
            const Index *ti = stypes.type_map.get(field.second);
            if ( ti == nullptr || !is_undefined_padding(stypes.types[*ti]) )
            {
              all_undefined = false;
              break;
            }
          }
          if ( all_undefined )
          {
            // If the entire struct is filled with `undefined`s, then the struct is
            // just a massive non-struct variable that has a big size.
            //
            // XXX: Or should we interpret this as a struct even then?
            //
            // Note: we are forced to reborrow `this` because otherwise it is a
            // mut-shared-mut pattern.
            stypes.types[this_idx].set_upper_bound_size(s.back().first + 1);
          }
          else
          {
            // Note: we are forced to reborrow `this` because otherwise it is a
            // mut-shared-mut pattern.
            {
              const Index *s0_ti = stypes.type_map.get(s.front().second);
              TREX_CHECK(s0_ti != nullptr,
                         "update_structural(Struct): head type must exist in type_map");
              stypes.types[this_idx] = stypes.types[*s0_ti]; // copy
            }
            std::optional<size_t> size = stypes.types[this_idx].observed_size();
            if ( !size.has_value() )
            {
              // Unable to obtain a max type size, defer.
              return false;
            }
            const size_t size_val = *size;
            for ( size_t i = 1; i < s.size(); ++i )
            {
              const auto &field = s[i];
              const Index *ti_ptr = stypes.type_map.get(field.second);
              TREX_CHECK(ti_ptr != nullptr,
                         "update_structural(Struct): field type must exist in type_map");
              const Index ti = *ti_ptr;
              if ( !is_undefined_padding(stypes.types[ti]) )
              {
                if ( field.first == 0 )
                {
                  // Upstream `trace!("Likely bitfield in 0th offset"; ...)` — emitted
                  // through `trex::log::trace` if logging is wired up. We deliberately
                  // skip the trace to keep the port's log surface minimal; the
                  // assertion is unchanged.
                }
                else
                {
                  stypes.types[this_idx].colocated_struct_fields.insert(
                      {static_cast<uint64_t>(field.first), ti});
                }
              }
            }
            stypes.types[this_idx].set_upper_bound_size(size_val);
          }
        }
        success = true;
      }
      else
      {
        success = false;
      }
      break;
    }

    case CType::Kind::FixedSizeArray:
    {
      const std::string &elem = ctype.fixed_array_elem;
      const size_t elemsize = ctype.fixed_array_elem_size;
      const size_t size = ctype.fixed_array_count;
      if ( completed.contains(elem) )
      {
        if ( size == 0 )
        {
          stypes.types[this_idx].set_upper_bound_size(0);
        }
        else
        {
          const Index *elem_idx_ptr = stypes.type_map.get(elem);
          TREX_CHECK(elem_idx_ptr != nullptr,
                     "update_structural(FixedSizeArray): element type must exist in type_map");
          const Index elem_idx = *elem_idx_ptr;
          // Note: we are forced to reborrow `this` because otherwise it is a
          // mut-shared-mut pattern.
          stypes.types[this_idx] = stypes.types[elem_idx]; // copy
          for ( size_t i = 1; i < size; ++i )
          {
            const size_t offset = elemsize * i;
            TREX_CHECK(elemsize > 0,
                       "update_structural(FixedSizeArray): elemsize must be > 0");
            stypes.types[this_idx].colocated_struct_fields.insert(
                {static_cast<uint64_t>(offset), elem_idx});
          }
        }
        success = true;
      }
      else
      {
        success = false;
      }
      break;
    }

    case CType::Kind::UnsizedArray:
    {
      // Upstream `todo!("Trying to convert unsized arrays");`
      TREX_UNREACHABLE("update_structural(UnsizedArray): upstream todo!()");
    }

    case CType::Kind::Enum:
    {
      const size_t sz = ctype.enum_size;
      const auto &_e = ctype.enum_values;
      stypes.types[this_idx].set_upper_bound_size(sz);
      // We don't insert smaller sizes for copying, since enums should not be split
      // when reading
      stypes.types[this_idx].copy_sizes.insert(sz);
      // XXX: For now, we are ignoring the values within the enumeration, except for
      // zero, simply because we have a zero_comparable.
      bool has_zero = false;
      for ( int32_t v : _e ) { if ( v == 0 ) { has_zero = true; break; } }
      if ( has_zero )
      {
        stypes.types[this_idx].zero_comparable = true;
      }
      stypes.types[this_idx].integer_ops.insert({IntegerOp::Eq, 1});
      stypes.types[this_idx].integer_ops.insert({IntegerOp::Neq, 1});
      success = true;
      break;
    }

    case CType::Kind::Pointer:
    {
      const size_t sz = ctype.pointer_size;
      const std::string &t = ctype.pointer_target;
      stypes.types[this_idx].set_upper_bound_size(sz);
      stypes.types[this_idx].copy_sizes.insert(sz);
      stypes.types[this_idx].zero_comparable = true;
      const Index *ti_ptr = stypes.type_map.get(t);
      if ( ti_ptr != nullptr )
      {
        stypes.types[this_idx].pointer_to = *ti_ptr;
        for ( IntegerOp o : all_pointer_integer_ops() )
        {
          stypes.types[this_idx].integer_ops.insert({o, sz});
        }
        success = true;
      }
      else
      {
        success = false;
      }
      break;
    }

    case CType::Kind::Code:
    {
      stypes.types[this_idx].observed_code = true;
      success = true;
      break;
    }
  }

  if ( is_undefined_padding(stypes.types[this_idx]) )
  {
    // Ensure that `undefined` is the only type that can be marked as undefined.
    // Required for the correct generation of `CType::Struct`.
    TREX_CHECK(ctype.kind == CType::Kind::BuiltIn && ctype.builtin == BuiltIn::Undefined,
               "For %s, %s is not undefined even though %s is undefined padding.",
               name.c_str(),
               "<ctype>",
               "<type>");
  }
  return success;
}

// ===========================================================================
// CTypes::to_structural
// ===========================================================================

STypes CTypes::to_structural() const
{
  STypes res;
  // Note: `Default::default()` for `UnorderedMap` and `Container` is `std::map<>{}`
  // and a freshly-constructed empty `Container<StructuralType>{}` — matching upstream
  // `Default` impls.
  unordered::UnorderedMap<std::string, uint64_t> postponed_count;
  unordered::UnorderedSet<std::string> completed;

  // `self.ctypes.iter().collect()` in Rust — `UnorderedMap::iter()` is `std::map`
  // order (BTreeMap order upstream). The `deque::VecDeque` is a FIFO, mirroring
  // upstream `pop_front`.
  std::deque<std::pair<std::string, CType>> queue;
  for ( const auto &kv : ctypes.iter() )
  {
    queue.emplace_back(kv.first, kv.second);
  }

  while ( !queue.empty() )
  {
    auto front = queue.front();
    queue.pop_front();
    const std::string &tn = front.first;
    const CType &ct = front.second;
    if ( update_structural(ct, tn, res, completed) )
    {
      // updated
      completed.insert(tn);
    }
    else
    {
      // postponed till others are updated
      uint64_t *count = postponed_count.get_mut(tn);
      if ( count != nullptr )
      {
        ++*count;
        // Fallback in the (hopefully never) case of an infinite loop; this catches
        // it and reports it, matching upstream's panic-with-counter pattern.
        TREX_CHECK(*count < 10000,
                   "Extremely unexpected number of postponements; ctypes must be broken");
      }
      else
      {
        postponed_count.insert(tn, 1);
      }
      queue.emplace_back(tn, ct);
    }
  }

  return res;
}

// ===========================================================================
// structural_types_for_all_primitive_c_types + helpers
// ===========================================================================

namespace c_types {

std::pair<std::vector<std::string>, std::vector<StructuralType>>
structural_types_for_all_primitive_c_types()
{
  CTypes builtins;
  for ( BuiltIn b : all_builtins() )
  {
    std::string name = builtin_debug_name(b);
    builtins.ctypes.insert(std::move(name), CType::make_builtin(b));
  }
  // XXX: Pointer size — upstream hardcodes `8` here, independent of `pointer_size`.
  // We do the same so the .c output is identical for the same inputs.
  builtins.ctypes.insert(std::string("VoidPtr"), CType::make_pointer(8, std::string("Void")));

  STypes structural = builtins.to_structural();

  std::vector<std::string> names;
  std::vector<StructuralType> types;
  for ( const auto &kv : structural.type_map.iter() )
  {
    names.push_back(kv.first);
    types.push_back(structural.types[kv.second]); // copy
  }
  // Plus the `Code` entry — observed_code-only, not in the Container.
  StructuralType code_st;
  code_st.observed_code = true;
  names.push_back("Code");
  types.push_back(std::move(code_st));

  // Filter `Void` and `WCharT` out (mirror upstream `name != "Void" && name != "WCharT"`).
  std::vector<std::string> filtered_names;
  std::vector<StructuralType> filtered_types;
  filtered_names.reserve(names.size());
  filtered_types.reserve(types.size());
  const InferenceConfig &cfg = config();
  for ( size_t i = 0; i < names.size(); ++i )
  {
    const std::string &nm = names[i];
    if ( nm == "Void" || nm == "WCharT" )
      continue;
    if ( !cfg.allow_type_rounding_based_on_upper_bound_size && nm == "Undefined" )
      continue;
    filtered_names.push_back(nm);
    filtered_types.push_back(std::move(types[i]));
  }
  return {std::move(filtered_names), std::move(filtered_types)};
}

std::map<std::string, std::string> undefineds_to_integers_map()
{
  // Mirror of the upstream literal (type_rounding.rs lines 33-39).
  return {
    {"Undefined1", "Char"},
    {"Undefined2", "Short"},
    {"Undefined4", "Int"},
    {"Undefined8", "ULong"},
  };
}

std::map<std::string, std::string> signed_unsigned_collapse_target()
{
  // Mirror of the upstream literal (type_rounding.rs lines 79-85). Keys are the
  // "from" side; values are the canonical (preferred) ones.
  return {
    {"UChar",       "Char"},
    {"ShortShort",  "UShortShort"},
    {"UShort",      "Short"},
    {"Uint",        "Int"},
    {"Long",        "ULong"},
  };
}

std::map<std::string, std::string> sign_normalized_c_primitives()
{
  // Hardcoded table mirroring upstream lines 633-660. The keys must match the names
  // that come out of `structural_types_for_all_primitive_c_types`; the assertion at
  // the end of this function enforces that.
  static const std::vector<std::pair<std::string, std::string>> table = {
    {"Bool",        "Bool"},
    {"Char",        "Char"},
    {"Code",        "Code"},
    {"Double",      "Double"},
    {"Float",       "Float"},
    {"Int",         "Int"},
    {"Long",        "Long"},
    {"LongDouble",  "LongDouble"},
    {"SInt128",     "SInt128"},
    {"SInt256",     "SInt256"},
    {"Short",       "Short"},
    {"ShortShort",  "ShortShort"},
    {"UChar",       "Char"},
    {"UInt128",     "Int128"},
    {"UInt256",     "Int256"},
    {"ULong",       "Long"},
    {"UShort",      "Short"},
    {"UShortShort", "ShortShort"},
    {"Uint",        "Int"},
    {"Undefined",   "Undefined"},
    {"Undefined1",  "Undefined1"},
    {"Undefined2",  "Undefined2"},
    {"Undefined4",  "Undefined4"},
    {"Undefined8",  "Undefined8"},
    {"VoidPtr",     "VoidPtr"},
  };
  std::map<std::string, std::string> ret;
  for ( const auto &p : table ) ret.insert(p);

  auto ctypes = structural_types_for_all_primitive_c_types();
  std::vector<std::string> ctype_names;
  ctype_names.reserve(ctypes.first.size());
  for ( const auto &nm : ctypes.first )
  {
    ctype_names.push_back(nm);
  }
  TREX_CHECK(ret.size() == ctype_names.size(),
             "sign_normalized_c_primitives: hardcoded table size (%zu) "
             "does not match ctypes size (%zu)",
             ret.size(), ctype_names.size());

  std::map<std::string, std::string> out;
  for ( const std::string &t : ctype_names )
  {
    auto it = ret.find(t);
    TREX_CHECK(it != ret.end(),
               "sign_normalized_c_primitives: missing key %s in hardcoded table",
               t.c_str());
    out.insert({t, it->second});
  }
  return out;
}

} // namespace c_types

} // namespace trex