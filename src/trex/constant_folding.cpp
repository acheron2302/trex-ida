// Definitions for `ConstFolded` (port of `constant_folding.rs`).

#include <trex/constant_folding.hpp>

#include <trex/error.hpp>
#include <trex/il.hpp>
#include <trex/log.hpp>
#include <trex/ssa.hpp>

namespace trex {

std::shared_ptr<ConstFolded> ConstFolded::from_ssa(std::shared_ptr<const ssa::SSA> ssa)
{
  auto out = std::make_shared<ConstFolded>();
  out->ssa_ = std::move(ssa);
  out->known_constants_.assign(out->ssa_->program->instructions.size(),
                               std::array<Memo, 2>{ Memo{}, Memo{} });
  return out;
}

std::optional<uint64_t> ConstFolded::output_at(size_t il_pc) const
{
  const Instruction &ins = ssa_->program->instructions[il_pc];

  // Helpers: fetch constants for inputs 0 and 1 (mirrors the `a!`/`b!` macros).
  auto a = [&]() -> std::optional<uint64_t> {
    return const_cast<ConstFolded *>(this)->input_at(il_pc, 0);
  };
  auto b = [&]() -> std::optional<uint64_t> {
    return const_cast<ConstFolded *>(this)->input_at(il_pc, 1);
  };

  using K = OpKind;
  switch ( ins.op.kind )
  {
    case K::Copy:
      return a();
    case K::IntAdd:
      if ( auto av = a(); av.has_value() )
        if ( auto bv = b(); bv.has_value() )
          return *av + *bv;
      return std::nullopt;
    case K::IntSub:
      if ( auto av = a(); av.has_value() )
        if ( auto bv = b(); bv.has_value() )
          return *av - *bv;
      return std::nullopt;
    case K::IntMult:
      if ( auto av = a(); av.has_value() )
        if ( auto bv = b(); bv.has_value() )
          return *av * *bv;
      return std::nullopt;
    case K::IntUDiv:
      if ( auto av = a(); av.has_value() )
        if ( auto bv = b(); bv.has_value() )
          return *av / *bv;
      return std::nullopt;
    case K::IntAnd:
      if ( auto av = a(); av.has_value() )
        if ( auto bv = b(); bv.has_value() )
          return *av & *bv;
      return std::nullopt;
    case K::IntOr:
      if ( auto av = a(); av.has_value() )
        if ( auto bv = b(); bv.has_value() )
          return *av | *bv;
      return std::nullopt;
    case K::IntZext:
      return a();
    case K::IntLeftShift:
      if ( auto av = a(); av.has_value() )
        if ( auto bv = b(); bv.has_value() )
          return *av << *bv;
      return std::nullopt;
    case K::IntSext:
    {
      auto av = a();
      if ( !av.has_value() )
        return std::nullopt;
      const Variable &v = ins.inputs[0];
      switch ( v.size )
      {
        case 1:
          return static_cast<uint64_t>(static_cast<int8_t>(*av));
        case 2:
          return static_cast<uint64_t>(static_cast<int16_t>(*av));
        case 4:
          return static_cast<uint64_t>(static_cast<int32_t>(*av));
        case 8:
          return *av;
        default:
          TREX_UNREACHABLE("ConstFolded::output_at: unexpected IntSext source size %zu",
                           v.size);
      }
      return std::nullopt;
    }
    case K::SubPiece:
    {
      auto av = a();
      auto bv = b();
      if ( !av.has_value() || !bv.has_value() )
        return std::nullopt;
      const uint64_t v = *av >> *bv;
      auto out_size = ins.output.try_size();
      if ( !out_size.has_value() )
        TREX_UNREACHABLE("ConstFolded::output_at: SubPiece output has no size");
      switch ( *out_size )
      {
        case 1:
          return static_cast<uint8_t>(v);
        case 2:
          return static_cast<uint16_t>(v);
        case 4:
          return static_cast<uint32_t>(v);
        case 8:
          return v;
        default:
          TREX_UNREACHABLE("ConstFolded::output_at: unexpected SubPiece output size %zu",
                           *out_size);
      }
      return std::nullopt;
    }
    case K::Load:
    case K::Store:
    case K::Branch:
    case K::BranchIndOffset:
    case K::FunctionStart:
    case K::CallWithFallthrough:
    case K::CallWithFallthroughIndirect:
    case K::CallWithNoFallthrough:
    case K::CallWithNoFallthroughIndirect:
      return std::nullopt;
    default:
      log::debug("TODO: Constant folding unimplemented for",
                 { { "op", ins.op.debug_string() } });
      return std::nullopt;
  }
}

std::optional<uint64_t> ConstFolded::input_at(size_t il_pc, size_t i)
{
  // Enter (potential) recursion, quit early if possible.
  Memo &memo = known_constants_[il_pc][i];
  switch ( memo.state )
  {
    case Value::Unknown:
      memo.state = Value::SentinelForRecursion;
      break;
    case Value::SentinelForRecursion:
      memo.state = Value::Dynamic;
      memo.constant.reset();
      return std::nullopt;
    case Value::Dynamic:
      memo.state = Value::Dynamic;
      memo.constant.reset();
      return std::nullopt;
    case Value::Constant:
      return memo.constant;
  }

  // Calculate the actual result.
  std::optional<uint64_t> res;
  const Variable &inp = ssa_->program->instructions[il_pc].inputs[i];
  switch ( inp.kind )
  {
    case VarKind::Constant:
      res = inp.value;
      break;
    case VarKind::Varnode:
    {
      const ssa::Variable v = ssa_->get_input_variable(il_pc, i);
      const std::vector<size_t> affecting =
          ssa_->get_all_immediately_affecting_instructions(v);
      TREX_CHECK(affecting.size() != 0,
                 "ConstFolded::input_at: variable has no affecting instruction "
                 "(unreachable upstream)");
      if ( affecting.size() == 1 )
      {
        res = output_at(affecting[0]);
      }
      else
      {
        res = std::nullopt;
      }
      break;
    }
    default:
      TREX_UNREACHABLE("ConstFolded::input_at: unexpected input kind: %s",
                       inp.debug_string().c_str());
  }

  // Exiting (potential) recursion, values are now known.
  if ( res.has_value() )
  {
    memo.state = Value::Constant;
    memo.constant = res;
  }
  else
  {
    memo.state = Value::Dynamic;
    memo.constant.reset();
  }
  return res;
}

} // namespace trex