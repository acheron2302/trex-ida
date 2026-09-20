// Structural-type engine — port of `third_party/trex/trex/src/structural.rs`
// (2046 lines) into C++20.
//
// Layout:
//   * The op-enum helpers (`all_integer_ops`, `signed_integer_ops`,
//     `char_integer_ops`, `is_signed_op`, plus the BooleanOp/FloatOp
//     analogues).
//   * `AggregateSize` factories and `cmp_with_indefinite_as_infinity`.
//   * `StructuralType::observed_size`, `set_upper_bound_size`,
//     `aggregate_size`, `join` (the Joinable glue), `refers_to`,
//     `refers_to_mut`.
//   * `StructuralTypes` constructor, all `capability_*` methods,
//     `propagate_pointerness_through_arithmetic_constraints`,
//     `canonicalize_indexes`, the index/type query API, deep clone,
//     struct/array conversions, `mark_types_as_equal`,
//     `are_equal_at_indexes`, and the GraphViz dumper.
//   * The two `with_FORCE_*_set` RAII wrappers around the
//     `DynamicVariable` instances declared in `structural.hpp`.
//
// Faithfulness:
//   * All op variants and all fields are kept in upstream order.
//   * `join` returns `nullopt` on success (other consumed) or the rejected
//     `other` on failure, matching the Rust `Result<(), Self>`.
//   * `Container<StructuralType>::get(idx)` / `::get_mut(idx)` are what the
//     upstream `self.types[idx]`/`self.types.get_mut(idx)` call sites
//     mean — the `Container` template does not expose `operator[]`.
//   * The `dump_inference_log_dot_files` branch drops only the
//     `/usr/bin/diff` highlighting hack; the `.dot` file itself is still
//     written (the public `write_dot` covers that for callers).

#include <trex/structural.hpp>

#include <trex/global_value_numbering.hpp>
#include <trex/inference_config.hpp>
#include <trex/ssa.hpp>

#include <algorithm>
#include <array>
#include <cstdarg>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <inttypes.h>
#include <ios>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

namespace trex {

// ============================================================================
// The two `dynamic_variable!` instances.
// ============================================================================

::trex::dynamic_variable::DynamicVariable
    FORCE_CLONE_AND_JOIN_INSTEAD_OF_DIRECT_SCHEDULE(false);
::trex::dynamic_variable::DynamicVariable
    FORCE_UPPER_BOUND_TO_BE_MAX_INSTEAD_OF_MIN_WHEN_JOINING(false);

// ============================================================================
// Integer-op / Boolean-op / Float-op helpers + name lookup.
// ============================================================================

namespace {

const std::vector<IntegerOp> &all_integer_ops_vec()
{
  static const std::vector<IntegerOp> v = {
    IntegerOp::Add, IntegerOp::Sub, IntegerOp::Mult, IntegerOp::UDiv,
    IntegerOp::SDiv, IntegerOp::URem, IntegerOp::SRem, IntegerOp::And,
    IntegerOp::Or, IntegerOp::Xor, IntegerOp::Eq, IntegerOp::Neq,
    IntegerOp::ULt, IntegerOp::SLt, IntegerOp::UCarry, IntegerOp::SCarry,
    IntegerOp::SBorrow, IntegerOp::OnesComplement, IntegerOp::TwosComplement,
    IntegerOp::Popcount, IntegerOp::ZeroExtendSrc, IntegerOp::SignExtendSrc,
    IntegerOp::ZeroExtendTgt, IntegerOp::SignExtendTgt, IntegerOp::LeftShift,
    IntegerOp::URightShift, IntegerOp::SRightShift, IntegerOp::ShiftAmount,
    IntegerOp::ConvertToFloat, IntegerOp::ConvertFromFloatTrunc,
  };
  return v;
}

const std::vector<IntegerOp> &signed_integer_ops_vec()
{
  // `is_signed_op().unwrap_or(true)` keeps None and Some(true) only.
  static const std::vector<IntegerOp> v = {
    IntegerOp::Add, IntegerOp::Sub, IntegerOp::Mult, IntegerOp::SDiv,
    IntegerOp::SRem, IntegerOp::And, IntegerOp::Or, IntegerOp::Xor,
    IntegerOp::Eq, IntegerOp::Neq, IntegerOp::SLt, IntegerOp::SCarry,
    IntegerOp::SBorrow, IntegerOp::OnesComplement, IntegerOp::TwosComplement,
    IntegerOp::ZeroExtendSrc, IntegerOp::SignExtendSrc,
    IntegerOp::ZeroExtendTgt, IntegerOp::SignExtendTgt,
    IntegerOp::SRightShift,
    IntegerOp::ConvertToFloat, IntegerOp::ConvertFromFloatTrunc,
  };
  return v;
}

const std::vector<IntegerOp> &unsigned_integer_ops_vec()
{
  // `!is_signed_op().unwrap_or(false)` keeps None and Some(false).
  static const std::vector<IntegerOp> v = {
    IntegerOp::Add, IntegerOp::Sub, IntegerOp::Mult, IntegerOp::UDiv,
    IntegerOp::URem, IntegerOp::And, IntegerOp::Or, IntegerOp::Xor,
    IntegerOp::Eq, IntegerOp::Neq, IntegerOp::ULt, IntegerOp::UCarry,
    IntegerOp::OnesComplement, IntegerOp::Popcount,
    IntegerOp::ZeroExtendSrc, IntegerOp::ZeroExtendTgt,
    IntegerOp::LeftShift, IntegerOp::URightShift, IntegerOp::ShiftAmount,
    IntegerOp::ConvertToFloat, IntegerOp::ConvertFromFloatTrunc,
  };
  return v;
}

const std::vector<IntegerOp> &all_pointer_integer_ops_vec()
{
  static const std::vector<IntegerOp> v = {
    IntegerOp::Add, IntegerOp::Sub, IntegerOp::And, IntegerOp::Or,
    IntegerOp::Xor, IntegerOp::Eq, IntegerOp::Neq, IntegerOp::ULt,
    IntegerOp::SLt, IntegerOp::UCarry, IntegerOp::SCarry, IntegerOp::SBorrow,
  };
  return v;
}

const std::vector<BooleanOp> &all_boolean_ops_vec()
{
  static const std::vector<BooleanOp> v = {
    BooleanOp::Negate, BooleanOp::And, BooleanOp::Or, BooleanOp::Xor,
  };
  return v;
}

const std::vector<FloatOp> &all_float_ops_vec()
{
  static const std::vector<FloatOp> v = {
    FloatOp::Add, FloatOp::Sub, FloatOp::Mult, FloatOp::Div,
    FloatOp::Eq, FloatOp::Neq, FloatOp::Lt, FloatOp::LEq,
    FloatOp::Sqrt, FloatOp::Abs, FloatOp::Neg, FloatOp::Ceil,
    FloatOp::Floor, FloatOp::Round, FloatOp::ConvertFromInt,
    FloatOp::ConvertToIntTrunc, FloatOp::ConvertFromDifferentSizedFloat,
    FloatOp::ConvertToDifferentSizedFloat,
  };
  return v;
}

std::optional<bool> is_signed_op_impl(IntegerOp op)
{
  switch ( op )
  {
    case IntegerOp::Add:        return std::nullopt;
    case IntegerOp::Sub:        return std::nullopt;
    case IntegerOp::Mult:       return std::nullopt;
    case IntegerOp::UDiv:       return std::optional<bool>(false);
    case IntegerOp::SDiv:       return std::optional<bool>(true);
    case IntegerOp::URem:       return std::optional<bool>(false);
    case IntegerOp::SRem:       return std::optional<bool>(true);
    case IntegerOp::And:        return std::nullopt;
    case IntegerOp::Or:         return std::nullopt;
    case IntegerOp::Xor:        return std::nullopt;
    case IntegerOp::Eq:         return std::nullopt;
    case IntegerOp::Neq:        return std::nullopt;
    case IntegerOp::ULt:        return std::optional<bool>(false);
    case IntegerOp::SLt:        return std::optional<bool>(true);
    case IntegerOp::UCarry:     return std::optional<bool>(false);
    case IntegerOp::SCarry:     return std::optional<bool>(true);
    case IntegerOp::SBorrow:    return std::optional<bool>(true);
    case IntegerOp::OnesComplement:    return std::nullopt;
    case IntegerOp::TwosComplement:    return std::optional<bool>(true);
    case IntegerOp::Popcount:          return std::optional<bool>(false);
    case IntegerOp::ZeroExtendSrc:     return std::nullopt;
    case IntegerOp::SignExtendSrc:     return std::optional<bool>(true);
    case IntegerOp::ZeroExtendTgt:     return std::nullopt;
    case IntegerOp::SignExtendTgt:     return std::optional<bool>(true);
    case IntegerOp::LeftShift:         return std::optional<bool>(false);
    case IntegerOp::URightShift:       return std::optional<bool>(false);
    case IntegerOp::SRightShift:       return std::optional<bool>(true);
    case IntegerOp::ShiftAmount:       return std::optional<bool>(false);
    case IntegerOp::ConvertToFloat:    return std::optional<bool>(true);
    case IntegerOp::ConvertFromFloatTrunc: return std::optional<bool>(true);
  }
  return std::nullopt;
}

const char *integer_op_name(IntegerOp op)
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

const char *boolean_op_name(BooleanOp op)
{
  switch ( op )
  {
    case BooleanOp::Negate: return "Negate";
    case BooleanOp::And:    return "And";
    case BooleanOp::Or:     return "Or";
    case BooleanOp::Xor:    return "Xor";
  }
  return "?";
}

const char *float_op_name(FloatOp op)
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

}  // namespace

const std::vector<IntegerOp> &all_integer_ops()               { return all_integer_ops_vec(); }
const std::vector<IntegerOp> &signed_integer_ops()             { return signed_integer_ops_vec(); }
const std::vector<IntegerOp> &unsigned_integer_ops()          { return unsigned_integer_ops_vec(); }
const std::vector<IntegerOp> &all_pointer_integer_ops()       { return all_pointer_integer_ops_vec(); }
const std::vector<BooleanOp> &all_boolean_ops()               { return all_boolean_ops_vec(); }
const std::vector<FloatOp>   &all_float_ops()                 { return all_float_ops_vec(); }

std::vector<IntegerOp> char_integer_ops(bool is_signed)
{
  const IntegerOp pool[] = {
    IntegerOp::Add, IntegerOp::Sub, IntegerOp::And, IntegerOp::Or, IntegerOp::Xor,
    IntegerOp::Eq, IntegerOp::Neq, IntegerOp::ULt, IntegerOp::SLt,
    IntegerOp::UCarry, IntegerOp::SCarry, IntegerOp::SBorrow,
    IntegerOp::ZeroExtendSrc, IntegerOp::SignExtendSrc,
    IntegerOp::ZeroExtendTgt, IntegerOp::SignExtendTgt,
  };
  std::vector<IntegerOp> out;
  for ( IntegerOp op : pool )
  {
    auto s = is_signed_op_impl(op);
    bool keep;
    if ( is_signed )
      keep = s.value_or(true);
    else
      keep = !s.value_or(false);
    if ( keep )
      out.push_back(op);
  }
  return out;
}

std::optional<bool> is_signed_op(IntegerOp op) { return is_signed_op_impl(op); }

std::string to_string(IntegerOp op) { return integer_op_name(op); }
std::string to_string(BooleanOp op) { return boolean_op_name(op); }
std::string to_string(FloatOp op)   { return float_op_name(op); }

std::string to_string(Padding pad)
{
  switch ( pad )
  {
    case Padding::IsValue:   return "Value";
    case Padding::IsPadding: return "Padding";
  }
  return "?";
}

// ============================================================================
// AggregateSize
// ============================================================================

AggregateSize AggregateSize::definite(size_t n)
{
  AggregateSize r;
  r.kind = Kind::Definite;
  r.value = n;
  return r;
}

AggregateSize AggregateSize::indefinite_struct_lower_bounded_by(size_t n)
{
  AggregateSize r;
  r.kind = Kind::IndefiniteStructLowerBoundedBy;
  r.value = n;
  return r;
}

AggregateSize AggregateSize::indefinite_array_with_element_size(size_t n)
{
  AggregateSize r;
  r.kind = Kind::IndefiniteArrayWithElementSize;
  r.value = n;
  return r;
}

AggregateSize AggregateSize::indefinite_out_of_fuel()
{
  AggregateSize r;
  r.kind = Kind::IndefiniteOutOfFuel;
  r.value = 0;
  return r;
}

std::optional<int> AggregateSize::cmp_with_indefinite_as_infinity(
    const AggregateSize &other) const
{
  if ( kind == Kind::IndefiniteOutOfFuel || other.kind == Kind::IndefiniteOutOfFuel )
    return std::nullopt;
  auto indef = [](Kind k) {
    return k == Kind::IndefiniteStructLowerBoundedBy
        || k == Kind::IndefiniteArrayWithElementSize;
  };
  if ( kind == Kind::Definite && other.kind == Kind::Definite )
  {
    if ( value < other.value ) return -1;
    if ( value > other.value ) return  1;
    return 0;
  }
  if ( kind == Kind::Definite && indef(other.kind) ) return -1;
  if ( indef(kind) && other.kind == Kind::Definite ) return  1;
  if ( indef(kind) && indef(other.kind) )              return 0;
  return 0;
}

std::string AggregateSize::debug_string() const
{
  switch ( kind )
  {
    case Kind::Definite:                       return std::string("Definite(") + std::to_string(value) + ")";
    case Kind::IndefiniteStructLowerBoundedBy: return std::string("IndefiniteStructLowerBoundedBy(") + std::to_string(value) + ")";
    case Kind::IndefiniteArrayWithElementSize: return std::string("IndefiniteArrayWithElementSize(") + std::to_string(value) + ")";
    case Kind::IndefiniteOutOfFuel:            return "IndefiniteOutOfFuel";
  }
  return "?";
}

// ============================================================================
// StructuralType — observed_size / set_upper_bound_size / aggregate_size
// ============================================================================

std::optional<size_t> StructuralType::observed_size() const
{
  std::optional<size_t> res = upper_bound_size;
  bool ignored_claim_msg_printed = false;
  auto use_sz = [&](size_t sz)
  {
    size_t cur = res.value_or(sz);
    if ( cur < sz ) cur = sz;
    if ( upper_bound_size.has_value() && cur > *upper_bound_size )
    {
      if ( !ignored_claim_msg_printed )
      {
        log::debug("Larger operation size than upper bound size. Ignoring op size.",
                   { { "stype", debug_string() } });
        ignored_claim_msg_printed = true;
      }
      cur = *upper_bound_size;
    }
    res = cur;
  };

  for ( size_t v : copy_sizes )       use_sz(v);
  for ( auto &p : integer_ops )       use_sz(p.second);
  for ( auto &p : float_ops )         use_sz(p.second);
  for ( auto &p : boolean_ops )       use_sz(p.second);
  return res;
}

bool StructuralType::set_upper_bound_size(size_t size)
{
  if ( upper_bound_size.has_value() )
  {
    if ( *upper_bound_size != size )
    {
      log::debug("Trying to set different upper bound size value; ignoring",
                 { { "old", *upper_bound_size }, { "new", size } });
      return false;
    }
    return true;
  }
  upper_bound_size = size;
  return true;
}

std::optional<AggregateSize> StructuralType::aggregate_size(
    const Container<StructuralType> &types,
    std::optional<size_t> fuel) const
{
  const size_t f = fuel.value_or(10);
  if ( f == 0 )
    return std::optional<AggregateSize>(AggregateSize::indefinite_out_of_fuel());

  std::optional<size_t> obs = observed_size();
  if ( !obs.has_value() )
    return std::nullopt;
  size_t res = *obs;

  if ( colocated_struct_fields.empty() )
  {
    if ( observed_array )
      return std::optional<AggregateSize>(
          AggregateSize::indefinite_array_with_element_size(res));
    return std::optional<AggregateSize>(AggregateSize::definite(res));
  }

  if ( observed_array )
  {
    log::debug("TODO: Array of structs",
               { { "type", debug_string() } });
  }

  bool found_flexible_struct_member = false;
  for ( const auto &kv : colocated_struct_fields )
  {
    const size_t field_offset = kv.first;
    const Index  fieldidx     = kv.second;
    if ( found_flexible_struct_member )
    {
      log::debug("Found a flexible struct member in the middle of the type.",
                 { { "type", debug_string() },
                   { "field_offset", field_offset },
                   { "field_idx", fieldidx.to_string() } });
    }
    if ( res > field_offset )
    {
      log::debug(
          "Inconsistent struct size+fields. Claimed size of field crosses into next field.",
          { { "type", debug_string() },
            { "field_offset", field_offset },
            { "res", res } });
    }
    res = field_offset;
    const StructuralType &field = types.get(fieldidx);
    std::optional<AggregateSize> sub_opt =
        field.aggregate_size(types, std::optional<size_t>(f - 1));
    if ( !sub_opt.has_value() )
    {
      log::debug("Found field with no aggregate size; assuming size as zero.",
                 { { "field", field.debug_string() },
                   { "field_offset", field_offset },
                   { "field_idx", fieldidx.to_string() },
                   { "type", debug_string() } });
      sub_opt = AggregateSize::definite(0);
    }
    AggregateSize sub = sub_opt.value();
    switch ( sub.kind )
    {
      case AggregateSize::Kind::Definite:
        res += sub.value;
        break;
      case AggregateSize::Kind::IndefiniteArrayWithElementSize:
        found_flexible_struct_member = true;
        break;
      case AggregateSize::Kind::IndefiniteStructLowerBoundedBy:
        res += sub.value;
        found_flexible_struct_member = true;
        break;
      case AggregateSize::Kind::IndefiniteOutOfFuel:
        return std::optional<AggregateSize>(AggregateSize::indefinite_out_of_fuel());
    }
  }
  if ( found_flexible_struct_member )
    return std::optional<AggregateSize>(
        AggregateSize::indefinite_struct_lower_bounded_by(res));
  return std::optional<AggregateSize>(AggregateSize::definite(res));
}

// ============================================================================
// StructuralType::join — the Joinable impl.
//
// Inlined form of upstream's `join` + `join_colocated_struct_fields`: the
// colocated-struct-fields join step is a private detail of `join` and not
// part of the public API. The recursion into the container's delayed-joiner
// uses `Container::join(...)`, which is what the upstream
// `self.types.join(...)` call sites mean.
// ============================================================================

std::optional<StructuralType> StructuralType::join(StructuralType other,
                                                    DelayedJoiner &delayed_joiner)
{
  if ( is_type_for_il_constant_variable || other.is_type_for_il_constant_variable )
    return other;

  std::optional<size_t> op_ubs = std::move(other.upper_bound_size);
  std::set<size_t> op_copy_sizes = std::move(other.copy_sizes);
  bool op_zero_comparable = other.zero_comparable;
  std::optional<Index> op_pointer_to = std::move(other.pointer_to);
  bool op_observed_boolean = other.observed_boolean;
  std::set<std::pair<IntegerOp, size_t>> op_integer_ops = std::move(other.integer_ops);
  std::set<std::pair<BooleanOp, size_t>> op_boolean_ops = std::move(other.boolean_ops);
  std::set<std::pair<FloatOp,   size_t>> op_float_ops   = std::move(other.float_ops);
  bool op_observed_code = other.observed_code;
  std::map<uint64_t, Index> op_colocated_struct_fields =
      std::move(other.colocated_struct_fields);
  bool op_observed_array = other.observed_array;

  if ( upper_bound_size.has_value() && op_ubs.has_value() )
  {
    if ( *upper_bound_size != *op_ubs )
    {
      log::trace("Received unequal `upper_bound_size` when joining",
                 { { "x", *upper_bound_size }, { "y", *op_ubs } });
    }
    size_t joined = dynamic_variable::if_var_set(
        FORCE_UPPER_BOUND_TO_BE_MAX_INSTEAD_OF_MIN_WHEN_JOINING,
        [&] { return std::max(*upper_bound_size, *op_ubs); },
        [&] { return std::min(*upper_bound_size, *op_ubs); });
    upper_bound_size = joined;
  }
  else if ( !upper_bound_size.has_value() && op_ubs.has_value() )
  {
    upper_bound_size = op_ubs;
  }

  for ( size_t s : op_copy_sizes )
    copy_sizes.insert(s);

  zero_comparable = zero_comparable || op_zero_comparable;

  if ( pointer_to.has_value() && op_pointer_to.has_value() )
  {
    if ( !pointer_to->surely_equal(*op_pointer_to) )
    {
      bool clone_and_join = dynamic_variable::if_var_set(
          FORCE_CLONE_AND_JOIN_INSTEAD_OF_DIRECT_SCHEDULE,
          [&] { return true; },
          [&] { return !trex::config().direct_join_pointees_rather_than_clone_and_join; });
      if ( clone_and_join )
        *pointer_to = delayed_joiner.schedule_clone_and_join(*pointer_to, *op_pointer_to);
      else
        delayed_joiner.schedule(*pointer_to, *op_pointer_to);
    }
  }
  else if ( !pointer_to.has_value() && op_pointer_to.has_value() )
  {
    pointer_to = op_pointer_to;
  }

  observed_boolean = observed_boolean || op_observed_boolean;

  for ( auto &p : op_integer_ops ) integer_ops.insert(p);
  for ( auto &p : op_boolean_ops ) boolean_ops.insert(p);
  for ( auto &p : op_float_ops   ) float_ops.insert(p);

  observed_code = observed_code || op_observed_code;

  // ---- join_colocated_struct_fields (inlined) ----
  if ( !op_colocated_struct_fields.empty() )
  {
    if ( colocated_struct_fields.empty() )
    {
      colocated_struct_fields = std::move(op_colocated_struct_fields);
    }
    else
    {
      log::debug("Both non-empty struct fields when joining.",
                 { { "other", std::string("...") },
                   { "self",  std::string("...") } });

      // Mirror upstream `std::mem::take(&mut self.colocated_struct_fields)`:
      // move the existing map out so the assert below sees an empty `self`,
      // and so the inconsistent-branch early return leaves the map empty
      // (matching upstream's "ignoring both sides" semantics).
      std::vector<std::pair<uint64_t, Index>> this_v;
      {
        std::map<uint64_t, Index> taken;
        taken.swap(colocated_struct_fields);
        for ( auto &p : taken )
          this_v.push_back(p);
      }
      std::vector<std::pair<uint64_t, Index>> other_v(
          op_colocated_struct_fields.begin(), op_colocated_struct_fields.end());

      if ( this_v.size() != other_v.size() )
      {
        log::info("Inconsistent struct field lengths found. Picking the shorter length.",
                  { { "other", std::string("...") }, { "self", std::string("...") } });
      }

      size_t i = 0, j = 0;
      while ( i < this_v.size() && j < other_v.size() )
      {
        if ( this_v[i].first == other_v[j].first )
        {
          bool clone_and_join = dynamic_variable::if_var_set(
              FORCE_CLONE_AND_JOIN_INSTEAD_OF_DIRECT_SCHEDULE,
              [&] { return true; },
              [&] { return !trex::config().direct_join_struct_fields_rather_than_clone_and_join; });
          if ( clone_and_join )
          {
            this_v[i].second = delayed_joiner.schedule_clone_and_join(
                this_v[i].second, other_v[j].second);
          }
          else
          {
            delayed_joiner.schedule(this_v[i].second, other_v[j].second);
          }
          ++i;
          ++j;
        }
        else
        {
          log::debug("Inconsistent struct joining requested. Ignoring both sides.",
                     {});
          log::trace("Incosistent struct joining",
                     { { "other", std::string("...") }, { "self", std::string("...") } });
          // `colocated_struct_fields` was swapped out above; leaving it empty
          // matches upstream's "Ignoring both sides of struct fields entirely".
          return std::nullopt;
        }
      }

      TREX_CHECK(colocated_struct_fields.empty() && !this_v.empty(),
                 "StructuralType::join: join_colocated invariant broken");
      for ( auto &p : this_v )
        colocated_struct_fields.emplace(p.first, p.second);
    }
  }

  observed_array = observed_array || op_observed_array;

  return std::nullopt;
}

std::vector<Index> StructuralType::refers_to() const
{
  std::vector<Index> out;
  if ( is_type_for_il_constant_variable )
    return out;
  if ( pointer_to.has_value() )
    out.push_back(*pointer_to);
  for ( auto &kv : colocated_struct_fields )
    out.push_back(kv.second);
  return out;
}

std::vector<Index *> StructuralType::refers_to_mut()
{
  std::vector<Index *> out;
  if ( is_type_for_il_constant_variable )
    return out;
  if ( pointer_to.has_value() )
    out.push_back(&*pointer_to);
  for ( auto &kv : colocated_struct_fields )
    out.push_back(&kv.second);
  return out;
}

bool operator==(const StructuralType &a, const StructuralType &b)
{
  bool ptr_eq;
  if ( a.pointer_to.has_value() && b.pointer_to.has_value() )
    ptr_eq = a.pointer_to->surely_equal(*b.pointer_to);
  else
    ptr_eq = a.pointer_to.has_value() == b.pointer_to.has_value();
  return a.upper_bound_size == b.upper_bound_size
      && a.copy_sizes == b.copy_sizes
      && a.zero_comparable == b.zero_comparable
      && ptr_eq
      && a.observed_boolean == b.observed_boolean
      && a.integer_ops == b.integer_ops
      && a.boolean_ops == b.boolean_ops
      && a.float_ops == b.float_ops
      && a.observed_code == b.observed_code
      && a.colocated_struct_fields.size() == b.colocated_struct_fields.size()
      && a.observed_array == b.observed_array
      && a.is_type_for_il_constant_variable == b.is_type_for_il_constant_variable;
}

namespace {

template <typename OpT>
std::string fmt_ops(const std::set<std::pair<OpT, size_t>> &ops,
                    const char *(*name)(OpT))
{
  std::string s = "{";
  bool first = true;
  for ( auto &p : ops )
  {
    if ( !first ) s += ", ";
    s += name(p.first);
    s += std::to_string(p.second);
    first = false;
  }
  s += "}";
  return s;
}

}  // namespace

std::string StructuralType::debug_string() const
{
  if ( is_type_for_il_constant_variable )
    return "StructuralTypeForILConstantVariable";
  std::string s = "StructuralType {";
  if ( upper_bound_size.has_value() )
    s += " upper_bound_size=" + std::to_string(*upper_bound_size);
  if ( !copy_sizes.empty() )
  {
    s += " copy_sizes={";
    bool first = true;
    for ( size_t v : copy_sizes )
    {
      if ( !first ) s += ",";
      s += std::to_string(v);
      first = false;
    }
    s += "}";
  }
  if ( zero_comparable ) s += " zero_comparable=true";
  if ( pointer_to.has_value() )
    s += " pointer_to=" + pointer_to->to_string();
  if ( observed_boolean ) s += " observed_boolean=true";
  if ( !integer_ops.empty() ) s += " integer_ops=" + fmt_ops(integer_ops, integer_op_name);
  if ( !boolean_ops.empty() ) s += " boolean_ops=" + fmt_ops(boolean_ops, boolean_op_name);
  if ( !float_ops.empty()   ) s += " float_ops="   + fmt_ops(float_ops,   float_op_name);
  if ( observed_code ) s += " observed_code=true";
  if ( !colocated_struct_fields.empty() )
  {
    s += " colocated_struct_fields={";
    bool first = true;
    for ( auto &kv : colocated_struct_fields )
    {
      if ( !first ) s += ",";
      s += std::to_string(kv.first) + ":" + kv.second.to_string();
      first = false;
    }
    s += "}";
  }
  if ( observed_array ) s += " observed_array=true";
  s += " }";
  return s;
}

// ============================================================================
// StructuralTypes — construction + capability_*
// ============================================================================

StructuralTypes::StructuralTypes(std::shared_ptr<const ssa::SSA> ssa_)
    : ssa(std::move(ssa_))
{
  StructuralType il_const;
  il_const.is_type_for_il_constant_variable = true;
  Index idx = types.insert(std::move(il_const));
  type_map.emplace(ssa::Variable::value_irrelevant_constant(), idx);
}

Index StructuralTypes::get_typ_idx_or_default(const ssa::Variable &v)
{
  auto it = type_map.find(v);
  if ( it != type_map.end() )
  {
    return it->second;
  }
  Index new_idx = types.insert_default();
  type_map.emplace(v, new_idx);
  return new_idx;
}

Index StructuralTypes::get_pointer_to_or_default(Index typ_idx)
{
  // Upstream note: the index_map can shift underneath us. Loop until stable.
  while ( !types.get(typ_idx).pointer_to.has_value() )
  {
    types.get_mut(typ_idx).pointer_to = types.insert_default();
  }
  return *types.get(typ_idx).pointer_to;
}

void StructuralTypes::capability_deref(ssa::Variable v, size_t pointer_size,
                                       ssa::Variable deref_v, size_t deref_size)
{
  Index cur_typ_idx = get_typ_idx_or_default(v);
  Index deref_idx   = get_pointer_to_or_default(cur_typ_idx);

  types.get_mut(cur_typ_idx).set_upper_bound_size(pointer_size);
  types.get_mut(deref_idx).copy_sizes.insert(deref_size);

  auto it = type_map.find(deref_v);
  Index deref_loc_typ_idx;
  if ( it == type_map.end() )
  {
    deref_loc_typ_idx = deref_idx;
    type_map.emplace(deref_v, deref_loc_typ_idx);
  }
  else
  {
    deref_loc_typ_idx = it->second;
  }
  types.join(deref_loc_typ_idx, deref_idx);
}

void StructuralTypes::capability_compared_against_zero(ssa::Variable v, size_t size)
{
  Index cur_typ_idx = get_typ_idx_or_default(v);
  types.get_mut(cur_typ_idx).zero_comparable = true;
  types.get_mut(cur_typ_idx).integer_ops.insert({ IntegerOp::Eq, size });
}

void StructuralTypes::capability_phi_node(ssa::Variable v, ssa::Variable from_v)
{
  observed_same_type(v, from_v);
}

void StructuralTypes::capability_copied_from(ssa::Variable v, ssa::Variable from_v,
                                             size_t size)
{
  Index from_i = get_typ_idx_or_default(from_v);
  const StructuralType &from_t = types.get(from_i);
  std::optional<size_t> from_sz = from_t.observed_size();
  if ( from_sz.has_value() && from_t.upper_bound_size.has_value()
       && *from_t.upper_bound_size == *from_sz )
  {
    observed_same_type(v, from_v);
  }
  else if ( from_sz.has_value() && from_t.upper_bound_size.has_value() )
  {
    log::trace("TODO[sizedops] differing upper-bounded copy",
               { { "v", v.debug_string() },
                 { "from_v", from_v.debug_string() },
                 { "size", size },
                 { "sz", *from_sz },
                 { "mxsz", *from_t.upper_bound_size } });
    observed_same_type(v, from_v);
  }
  else if ( from_sz.has_value() )
  {
    log::trace("TODO[sizedops] non-upper-bounded copy",
               { { "v", v.debug_string() },
                 { "from_v", from_v.debug_string() },
                 { "size", size } });
    observed_same_type(v, from_v);
  }
  else
  {
    log::trace("TODO[sizedops] unsized-from-location copy",
               { { "v", v.debug_string() },
                 { "from_v", from_v.debug_string() },
                 { "size", size } });
    observed_same_type(v, from_v);
  }

  Index cur_typ_idx = get_typ_idx_or_default(v);
  types.get_mut(cur_typ_idx).copy_sizes.insert(size);
}

void StructuralTypes::observed_same_type(ssa::Variable v1, ssa::Variable v2)
{
  Index t1 = get_typ_idx_or_default(v1);
  Index t2 = get_typ_idx_or_default(v2);
  types.join(t1, t2);
}

void StructuralTypes::capability_gvn_congruent(const std::vector<ssa::Variable> &gvn_set)
{
  if ( gvn_set.empty() ) return;
  ssa::Variable rep = gvn_set.front();
  for ( size_t i = 1; i < gvn_set.size(); ++i )
    observed_same_type(rep, gvn_set[i]);
}

void StructuralTypes::capability_known_boolean(ssa::Variable v)
{
  Index cur_typ_idx = get_typ_idx_or_default(v);
  types.get_mut(cur_typ_idx).observed_boolean = true;
}

void StructuralTypes::capability_boolean_op(ssa::Variable v, BooleanOp op, size_t size)
{
  Index cur_typ_idx = get_typ_idx_or_default(v);
  types.get_mut(cur_typ_idx).boolean_ops.insert({ op, size });
}

void StructuralTypes::capability_integer_op(ssa::Variable v, IntegerOp op, size_t size)
{
  Index cur_typ_idx = get_typ_idx_or_default(v);
  types.get_mut(cur_typ_idx).integer_ops.insert({ op, size });
}

void StructuralTypes::capability_float_op(ssa::Variable v, FloatOp op, size_t size)
{
  Index cur_typ_idx = get_typ_idx_or_default(v);
  types.get_mut(cur_typ_idx).float_ops.insert({ op, size });
}

void StructuralTypes::capability_pointer_to_code(ssa::Variable v)
{
  Index cur_typ_idx = get_typ_idx_or_default(v);
  Index pointee = get_pointer_to_or_default(cur_typ_idx);
  types.get_mut(pointee).observed_code = true;
}

void StructuralTypes::capability_have_same_type(ssa::Variable v1, ssa::Variable v2)
{
  Index ti1 = get_typ_idx_or_default(v1);
  Index ti2 = get_typ_idx_or_default(v2);
  types.join(ti1, ti2);
}

// ============================================================================
// propagate_pointerness_through_arithmetic_constraints
// ============================================================================

void StructuralTypes::propagate_pointerness_through_arithmetic_constraints()
{
  bool changed = true;
  while ( changed )
  {
    changed = false;
    for ( size_t il_addr = 0; il_addr < ssa->program->instructions.size(); ++il_addr )
    {
      const Instruction &ins = ssa->program->instructions[il_addr];
      if ( ins.op.kind != OpKind::IntAdd && ins.op.kind != OpKind::IntSub )
        continue;
      bool inp0_const = ins.inputs[0].kind == VarKind::Constant;
      bool inp1_const = ins.inputs[1].kind == VarKind::Constant;
      size_t base_var_input_idx;
      if ( inp0_const && !inp1_const )
        base_var_input_idx = 1;
      else if ( !inp0_const && inp1_const )
        base_var_input_idx = 0;
      else
        continue;
      std::optional<ssa::Variable> base_ssa_var;
      try
      {
        base_ssa_var = ssa->get_input_variable(il_addr, base_var_input_idx);
      }
      catch ( const InvariantError & )
      {
        continue;
      }
      if ( !base_ssa_var.has_value() )
        continue;

      auto base_it = type_map.find(*base_ssa_var);
      if ( base_it == type_map.end() )
        continue;

      std::optional<ssa::Variable> result_var = ssa->get_output_impacted_variable(il_addr);
      if ( !result_var.has_value() )
        continue;
      auto result_it = type_map.find(*result_var);
      if ( result_it == type_map.end() )
        continue;

      if ( types.get(base_it->second).pointer_to.has_value()
           && !types.get(result_it->second).pointer_to.has_value() )
      {
        types.get_mut(result_it->second).pointer_to = types.insert_default();
        changed = true;
      }
      if ( types.get(result_it->second).pointer_to.has_value()
           && !types.get(base_it->second).pointer_to.has_value() )
      {
        types.get_mut(base_it->second).pointer_to = types.insert_default();
        changed = true;
      }
    }
  }
}

// ============================================================================
// canonicalize_indexes
// ============================================================================

void StructuralTypes::canonicalize_indexes()
{
  for ( auto &kv : type_map )
    kv.second = types.get_canonical_index(kv.second);

  std::vector<Index> roots;
  roots.reserve(type_map.size());
  for ( auto &kv : type_map )
    roots.push_back(kv.second);
  types.garbage_collect_with_roots(roots);

  std::vector<std::pair<Index, Index>> canon_idxs;
  for ( auto &obj : types.currently_alive_objects_iter() )
  {
    for ( Index idx : obj.get().refers_to() )
      canon_idxs.emplace_back(idx, types.get_canonical_index(idx));
  }
  std::reverse(canon_idxs.begin(), canon_idxs.end());
  for ( auto &obj : types.currently_alive_objects_iter_mut() )
  {
    for ( Index *idx : obj.get().refers_to_mut() )
    {
      auto p = canon_idxs.back();
      canon_idxs.pop_back();
      TREX_CHECK(idx->surely_equal(p.first),
                 "StructuralTypes::canonicalize_indexes: refers_to_mut returned unexpected index");
      *idx = p.second;
    }
  }
}

// ============================================================================
// Type/index queries + deep clone + conversions
// ============================================================================

std::optional<Index> StructuralTypes::get_type_index(const ssa::Variable &location) const
{
  auto it = type_map.find(location);
  if ( it == type_map.end() ) return std::nullopt;
  return it->second;
}

const StructuralType *StructuralTypes::get_type_from_index(Index idx) const
{
  return &types.get(idx);
}

const StructuralType *StructuralTypes::get_type_of(const ssa::Variable &v) const
{
  auto it = type_map.find(v);
  if ( it == type_map.end() ) return nullptr;
  return &types.get(it->second);
}

StructuralTypes StructuralTypes::deep_clone() const
{
  StructuralTypes r(ssa);
  r.type_map = type_map;
  std::vector<Index *> roots;
  roots.reserve(r.type_map.size());
  for ( auto &kv : r.type_map )
    roots.push_back(&kv.second);
  r.types = types.deep_clone(roots);
  return r;
}

bool StructuralTypes::are_equal_at_indexes(Index a, Index b) const
{
  return types.index_eq(a, b);
}

void StructuralTypes::convert_to_struct(
    Index idx,
    const std::vector<std::pair<size_t, Padding>> &member_sizes,
    bool has_unsized_array_at_end)
{
  TREX_CHECK(!member_sizes.empty(),
             "StructuralTypes::convert_to_struct: Must have at least one member in struct");
  size_t head_size = member_sizes.front().first;
  Padding head_pad  = member_sizes.front().second;
  if ( head_pad != Padding::IsValue )
  {
    log::debug("Padding head when converting to struct",
               { { "idx", idx.to_string() } });
  }

  if ( types.get(idx).observed_array )
  {
    log::debug("TODO: Converting an observed-array to a struct. Unclear implications.",
               { { "idx", idx.to_string() },
                 { "typ", types.get(idx).debug_string() } });
  }

  if ( trex::config().allow_aggregate_analysis_to_set_upper_bound_size )
  {
    if ( !types.get_mut(idx).set_upper_bound_size(head_size) )
    {
      log::debug("Head when converting to struct found to not have expected size",
                 { { "idx", idx.to_string() },
                   { "size", types.get(idx).observed_size().value_or(0) },
                   { "expected", head_size } });
    }
  }

  if ( !types.get(idx).colocated_struct_fields.empty() )
  {
    std::string sizes_dbg = "[";
    bool first_dbg = true;
    for ( auto &kv : types.get(idx).colocated_struct_fields )
    {
      if ( !first_dbg ) sizes_dbg += ",";
      sizes_dbg += "(\"" + std::to_string(kv.first) + "\",";
      sizes_dbg += types.get(kv.second).observed_size().has_value()
                       ? std::to_string(*types.get(kv.second).observed_size())
                       : "<none>";
      sizes_dbg += ")";
      first_dbg = false;
    }
    sizes_dbg += "]";

    std::string new_sizes_dbg = "[";
    bool first_dbg2 = true;
    for ( auto &p : member_sizes )
    {
      if ( !first_dbg2 ) new_sizes_dbg += ",";
      new_sizes_dbg += "(" + std::to_string(p.first) + ","
                       + std::to_string((uint8_t)p.second) + ")";
      first_dbg2 = false;
    }
    new_sizes_dbg += "]";

    log::info("Attempting to convert type to struct again",
              { { "idx", idx.to_string() },
                { "previous_colocated", std::string("...") },
                { "sizes", sizes_dbg },
                { "new_sizes", new_sizes_dbg } });

    if ( !types.get(idx).colocated_struct_fields.empty() )
    {
      auto last = types.get(idx).colocated_struct_fields.rbegin();
      size_t prev_unsized_posn = last->first;
      Index   last_field_idx   = last->second;
      if ( types.get(last_field_idx).observed_array )
      {
        if ( has_unsized_array_at_end )
        {
          size_t new_unsized_posn = 0;
          for ( auto &p : member_sizes ) new_unsized_posn += p.first;
          if ( prev_unsized_posn != new_unsized_posn )
          {
            log::debug("Inconsistent final unsized-array-at-end location. Using new.",
                       { { "prev", prev_unsized_posn }, { "new", new_unsized_posn } });
          }
        }
      }
    }
  }

  std::map<uint64_t, Index> members =
      std::move(types.get_mut(idx).colocated_struct_fields);

  size_t cur_size = head_size;
  for ( size_t mi = 1; mi < member_sizes.size(); ++mi )
  {
    size_t  size = member_sizes[mi].first;
    Padding pad  = member_sizes[mi].second;
    TREX_CHECK(cur_size != 0,
               "StructuralTypes::convert_to_struct: cur_size == 0 (NonZeroUsize)");
    auto it = members.find(cur_size);
    if ( pad == Padding::IsValue )
    {
      if ( it != members.end() )
      {
        Index typ = it->second;
        std::optional<size_t> os = types.get(typ).observed_size();
        if ( os.has_value() && *os != size )
        {
          log::debug("Marking type as a different split of previous known struct type",
                     { { "idx", idx.to_string() } });
        }
        else if ( !os.has_value() )
        {
          log::debug("No observed size on split of previous known struct type",
                     { { "idx", idx.to_string() } });
        }
      }
      else
      {
        Index new_typ = types.insert_default();
        if ( trex::config().allow_aggregate_analysis_to_set_upper_bound_size )
          types.get_mut(new_typ).set_upper_bound_size(size);
        members.emplace(cur_size, new_typ);
      }
    }
    cur_size += size;
  }
  if ( has_unsized_array_at_end )
  {
    TREX_CHECK(cur_size != 0,
               "StructuralTypes::convert_to_struct: unsized-array end at zero offset");
    Index typ = types.insert_default();
    types.get_mut(typ).observed_array = true;
    members.emplace(cur_size, typ);
  }

  types.get_mut(idx).colocated_struct_fields = std::move(members);
}

void StructuralTypes::convert_to_array(Index idx, size_t member_element_size)
{
  if ( !types.get(idx).colocated_struct_fields.empty() )
  {
    log::debug("TODO: Converting a struct to an array. Unclear implications",
               { { "idx", idx.to_string() },
                 { "typ", types.get(idx).debug_string() },
                 { "member_element_size", member_element_size } });
  }
  if ( types.get(idx).observed_array )
  {
    log::info("Nothing wrong in marking something as array twice, "
              "but I don't actually expect this to happen so this "
              "assert exists as a way to see if there are any "
              "invariants elsewhere in the code that I might've missed",
              { { "idx", idx.to_string() },
                { "typ", types.get(idx).debug_string() },
                { "member_element_size", member_element_size } });
  }
  if ( trex::config().allow_aggregate_analysis_to_set_upper_bound_size )
  {
    if ( !types.get_mut(idx).set_upper_bound_size(member_element_size) )
    {
      log::debug("Expected head type of array to contain element size",
                 { { "head_type", types.get(idx).debug_string() },
                   { "element_size", member_element_size } });
    }
  }
  types.get_mut(idx).observed_array = true;
}

void StructuralTypes::mark_types_as_equal(Index idx1, Index idx2)
{
  types.join(idx1, idx2);
}

std::string StructuralTypes::debug_string() const
{
  std::string s = "StructuralTypes { type_map={";
  bool first = true;
  for ( auto &kv : type_map )
  {
    if ( !first ) s += ", ";
    s += kv.first.debug_string() + " -> " + kv.second.to_string();
    first = false;
  }
  s += "}";
  s += " types=[";
  first = true;
  for ( auto &t : types.currently_alive_objects_iter() )
  {
    if ( !first ) s += ", ";
    s += t.get().debug_string();
    first = false;
  }
  s += "]";
  s += " }";
  return s;
}

// ============================================================================
// GraphViz generation (`generate_dot` / `write_dot`).
//
// Note: The text output of `generate_dot` is a debugging aid (and the
// `dump_inference_log_dot_files` driver in `infer_structural_types.cpp`
// writes it to a file when enabled). The format does not participate in the
// S7 differential gate; the textual output is reasonably close to upstream
// but the Node label rendering is necessarily minimal here.
// ============================================================================

namespace {

enum class DotNodeKind { Variable, Type, Program };

struct DotNode
{
  DotNodeKind kind = DotNodeKind::Variable;
  ssa::Variable var{};
  Index idx{};

  bool operator==(const DotNode &o) const
  {
    if ( kind != o.kind ) return false;
    if ( kind == DotNodeKind::Variable ) return var == o.var;
    if ( kind == DotNodeKind::Type )      return idx.surely_equal(o.idx);
    return true;
  }
  bool operator<(const DotNode &o) const
  {
    auto rank = [](DotNodeKind k)
    {
      return k == DotNodeKind::Program ? 0
           : k == DotNodeKind::Variable ? 1 : 2;
    };
    if ( rank(kind) != rank(o.kind) ) return rank(kind) < rank(o.kind);
    if ( kind == DotNodeKind::Variable ) return var < o.var;
    if ( kind == DotNodeKind::Type )
      return idx.some_consistent_ordering(o.idx) < 0;
    return false;
  }
};

std::string dot_node_id(const DotNode &n)
{
  if ( n.kind == DotNodeKind::Variable )
  {
    if ( n.var.kind == ssa::Variable::Kind::Variable )
      return std::string("v") + std::to_string(n.var.var.idx);
    if ( n.var.kind == ssa::Variable::Kind::ConstantValue )
      return std::string("c") + std::to_string(n.var.value);
    return "viConst";
  }
  if ( n.kind == DotNodeKind::Type )
    return std::string("t") + n.idx.to_string();
  return "program";
}

std::string dot_escape(std::string s)
{
  std::string out;
  out.reserve(s.size());
  for ( char c : s )
  {
    if ( c == '\\' || c == '"' ) { out.push_back('\\'); out.push_back(c); }
    else if ( c == '\n' )         { out += "\\l"; }
    else                          { out.push_back(c); }
  }
  return out;
}

std::string dot_node_label(const StructuralTypes &types, const DotNode &n)
{
  if ( n.kind == DotNodeKind::Variable )
  {
    if ( n.var.kind == ssa::Variable::Kind::Variable )
      return std::string("v") + std::to_string(n.var.var.idx);
    if ( n.var.kind == ssa::Variable::Kind::ConstantValue )
    {
      char buf[32];
      std::snprintf(buf, sizeof(buf), "$%" PRIx64, n.var.value);
      return buf;
    }
    return "viConst";
  }
  if ( n.kind == DotNodeKind::Type )
  {
    Index canon = types.types_ref().get_canonical_index(n.idx);
    std::string lbl = "t" + canon.to_string() + "\\n\\n";
    lbl += dot_escape(types.types_ref().get(n.idx).debug_string()) + "\\l";
    return lbl;
  }
  // Program node: render the debug-program string.
  ssa::DebugProgram dp(*types.ssa, true, std::nullopt);
  std::string escaped = dot_escape(format_debug_program(dp));
  // Replace the U+1D6DF (𝛟) Phi glyph with HTML entity for GraphViz.
  for ( size_t i = 0; i + 3 < escaped.size(); )
  {
    if ( (unsigned char)escaped[i]   == 0xF0
      && (unsigned char)escaped[i+1] == 0x9D
      && (unsigned char)escaped[i+2] == 0x9B
      && (unsigned char)escaped[i+3] == 0x9F )
    {
      escaped.replace(i, 4, "&#934;");
      i += 7;
    }
    else ++i;
  }
  return escaped;
}

std::pair<std::vector<DotNode>,
          std::vector<std::tuple<DotNode, DotNode, std::string>>>
dot_walk(const StructuralTypes &types, bool show_constants)
{
  std::vector<std::tuple<DotNode, DotNode, std::string>> edges;
  std::set<DotNode> visited;
  std::vector<DotNode> worklist;

  visited.insert(DotNode{DotNodeKind::Program, {}, {}});
  for ( auto &kv : types.type_map )
  {
    const ssa::Variable &v = kv.first;
    // Upstream: `ValueIrrelevantConstant => None`, `ConstantValue => show_constants.then(..)`,
    // `Variable => Some(..)`; `show_constants` is true only when a specific IL address is
    // highlighted (`generate_dot(Some(addr))`), so the plain dump has no constant nodes.
    if ( v.kind == ssa::Variable::Kind::ValueIrrelevantConstant )
      continue;
    if ( v.kind == ssa::Variable::Kind::ConstantValue && !show_constants )
      continue;
    worklist.push_back(DotNode{DotNodeKind::Variable, v, {}});
  }

  while ( !worklist.empty() )
  {
    DotNode n = worklist.back();
    worklist.pop_back();
    if ( !visited.insert(n).second ) continue;
    if ( n.kind == DotNodeKind::Variable )
    {
      auto it = types.type_map.find(n.var);
      Index t = types.types_ref().get_canonical_index(it->second);
      DotNode tn{DotNodeKind::Type, {}, t};
      worklist.push_back(tn);
      edges.emplace_back(n, tn, "has_type");
    }
    else if ( n.kind == DotNodeKind::Type )
    {
      const StructuralType &t = types.types_ref().get(n.idx);
      if ( t.pointer_to.has_value() )
      {
        Index pi = types.types_ref().get_canonical_index(*t.pointer_to);
        DotNode pn{DotNodeKind::Type, {}, pi};
        worklist.push_back(pn);
        edges.emplace_back(n, pn, "pointer_to");
      }
      for ( auto &kv : t.colocated_struct_fields )
      {
        Index fi = types.types_ref().get_canonical_index(kv.second);
        DotNode pn{DotNodeKind::Type, {}, fi};
        worklist.push_back(pn);
        edges.emplace_back(n, pn,
                           std::string("struct_field_") + std::to_string(kv.first));
      }
    }
  }
  std::vector<DotNode> nodes(visited.begin(), visited.end());
  return { nodes, edges };
}

}  // namespace

std::string generate_dot(const StructuralTypes &types,
                         std::optional<size_t> only_il_addr)
{
  auto [nodes, edges] = dot_walk(types, only_il_addr.has_value());
  std::ostringstream os;
  os << "digraph StructuralTypes {\n";
  for ( auto &n : nodes )
  {
    os << "  " << dot_node_id(n)
       << " [label=\"" << dot_escape(dot_node_label(types, n)) << "\"";
    if ( n.kind == DotNodeKind::Program )
      os << " shape=note";
    os << "];\n";
  }
  for ( auto &e : edges )
  {
    os << "  " << dot_node_id(std::get<0>(e))
       << " -> " << dot_node_id(std::get<1>(e))
       << " [label=\"" << std::get<2>(e) << "\"];\n";
  }
  os << "}\n";
  return os.str();
}

void write_dot(const StructuralTypes &types, const std::string &path,
               std::optional<size_t> only_il_addr)
{
  std::ofstream f(path);
  TREX_CHECK(f.is_open(),
             "StructuralTypes::write_dot: failed to open '%s' for writing",
             path.c_str());
  f << generate_dot(types, only_il_addr);
}

} // namespace trex
