// `Program::infer_structural_types` driver — port of upstream `il.rs`
// lines 1113-1712.
//
//   * Computes the SSA form from the lifted program.
//   * Seeds `StructuralTypes::new` (the IL-constant-variable sentinel is
//     pre-populated by the constructor itself).
//   * Joins phi-node variables (forces same type).
//   * Joins global-value-numbering congruence classes.
//   * For every IL instruction, dispatches on `Op` and emits the matching
//     `capability_*` calls into `StructuralTypes`.
//   * Writes `inference-log-IL_PC.dot` files when the corresponding
//     config flag is set (no `/usr/bin/diff` highlighting — that hack is
//     dropped).
//   * Calls `propagate_pointerness_through_arithmetic_constraints()` and
//     `canonicalize_indexes()` to fixpoint the structural types.
//
// This file is also the single seam exposed by `pipeline.hpp`:
// `trex::infer_structural_types(const std::shared_ptr<const Program>&)`.
// The main agent wires this into the end-to-end pipeline driver.

#include <trex/pipeline.hpp>

#include <trex/global_value_numbering.hpp>
#include <trex/inference_config.hpp>
#include <trex/il.hpp>
#include <trex/log.hpp>
#include <trex/ssa.hpp>
#include <trex/structural.hpp>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace trex {

namespace {

// Helper to format an `inference-log-IL_PC.dot` filename into a chosen
// directory (or the current working directory when none is configured).
std::string dot_log_path(size_t il_pc)
{
  char buf[64];
  std::snprintf(buf, sizeof(buf), "inference-log-%05zu.dot", il_pc);
  std::string name(buf);
  const std::string &dir = trex::config().dot_output_dir;
  if ( dir.empty() )
    return name;
  return (std::filesystem::path(dir) / name).string();
}

// One arm of the per-Op dispatch loop. Most arms use a small switch over the
// downstream operation kind; a few require additional `assert_eq!`s on
// operand sizes (mirroring the upstream's `unwrap_or` fallbacks). The body is
// long, so it's broken into per-Op lambdas below for readability.

inline std::optional<size_t> ins_inp_size(const Instruction &ins, size_t i)
{
  return ins.inputs[i].try_size();
}

inline size_t ins_out_size(const Instruction &ins)
{
  return ins.output.try_size().value();
}

}  // namespace

StructuralTypes infer_structural_types(const std::shared_ptr<const Program> &program)
{
  ssa::SSA ssa_inst = ssa::SSA::compute_from(program);
  std::shared_ptr<const ssa::SSA> ssa_sp =
      std::make_shared<const ssa::SSA>(std::move(ssa_inst));

  StructuralTypes types(ssa_sp);

  // Phi-node capability loop. Matches upstream: `for (v, vs) in phi_nodes_iter`
  for ( auto &p : ssa_sp->phi_nodes_iter() )
  {
    ssa::SSAVariable v = p.first;
    const unordered::UnorderedSet<ssa::SSAVariable> *phi_set = p.second;
    for ( auto &from_sv : phi_set->iter() )
    {
      types.capability_phi_node(ssa::Variable::variable(v),
                                 ssa::Variable::variable(from_sv));
    }
  }

  // GVN congruence: every class collapses to one type.
  GlobalValueNumbering gvn = GlobalValueNumbering::analyze_from(ssa_sp);
  for ( auto &cls : gvn.congruent_sets_iter() )
  {
    std::vector<ssa::Variable> vs;
    for ( auto &v : cls.iter() )
      vs.push_back(v);
    types.capability_gvn_congruent(vs);
  }

  const bool emit_dots = trex::config().dump_inference_log_dot_files;

  for ( size_t il_addr = 0; il_addr < program->instructions.size(); ++il_addr )
  {
    const Instruction &ins = program->instructions[il_addr];

    if ( emit_dots )
    {
      const Instruction &prev = (il_addr == 0)
          ? ins
          : program->instructions[il_addr - 1];
      if ( il_addr == 0 || ins.address != prev.address )
      {
        std::ofstream f(dot_log_path(il_addr));
        if ( f.is_open() )
        {
          f << generate_dot(types, std::optional<size_t>(il_addr));
        }
      }
    }

    auto inp_sz = [&](size_t i) { return ins_inp_size(ins, i); };
    auto out_sz = [&] { return ins_out_size(ins); };

    switch ( ins.op.kind )
    {
      case OpKind::Nop:
      case OpKind::ProcessorException:
      case OpKind::UnderspecifiedOutputModification:
      case OpKind::UnderspecifiedNoOutput:
      case OpKind::FunctionStart:
      case OpKind::FunctionEnd:
      case OpKind::Branch:
      case OpKind::CallWithFallthrough:
      case OpKind::CallWithNoFallthrough:
      case OpKind::CallWithFallthroughIndirect:
      case OpKind::CallWithNoFallthroughIndirect:
        break;

      case OpKind::BranchIndOffset:
      case OpKind::Return:
        types.capability_pointer_to_code(ssa_sp->get_input_variable(il_addr, 0));
        break;

      case OpKind::Cbranch:
      {
        const Variable &cond = ins.inputs[1];
        switch ( cond.kind )
        {
          case VarKind::Unused:
          case VarKind::DerefVarnode:
          case VarKind::ILAddress:
          case VarKind::ILOffset:
          case VarKind::MachineAddress:
          case VarKind::StackVariable:
            TREX_UNREACHABLE("Cbranch: non-value condition operand");
          case VarKind::Constant:
            // XXX: nothing to do here per upstream.
            break;
          case VarKind::Varnode:
            types.capability_compared_against_zero(
                ssa_sp->get_input_variable(il_addr, 1),
                cond.try_size().value());
            break;
        }
        break;
      }

      case OpKind::Copy:
      {
        const Variable &src = ins.inputs[0];
        switch ( src.kind )
        {
          case VarKind::Unused:
          case VarKind::DerefVarnode:
          case VarKind::ILAddress:
          case VarKind::ILOffset:
          case VarKind::MachineAddress:
          case VarKind::StackVariable:
            TREX_UNREACHABLE("Copy: source must be a value");
          case VarKind::Constant:
            // XXX: nothing to do here per upstream.
            break;
          case VarKind::Varnode:
          {
            size_t sz = out_sz();
            TREX_CHECK(inp_sz(0).value_or(sz) == sz,
                       "Copy: input size %zu vs output size %zu",
                       inp_sz(0).value_or(sz), sz);
            types.capability_copied_from(
                ssa_sp->get_output_impacted_variable(il_addr).value(),
                ssa_sp->get_input_variable(il_addr, 0), sz);
            break;
          }
        }
        break;
      }

      case OpKind::Piece:
      case OpKind::SubPiece:
      {
        if ( ins.op.kind == OpKind::SubPiece
             && ins.inputs[1].kind == VarKind::Constant
             && ins.inputs[1].value == 0 )
        {
          types.capability_have_same_type(
              ssa_sp->get_output_impacted_variable(il_addr).value(),
              ssa_sp->get_input_variable(il_addr, 0));
        }
        break;
      }

      case OpKind::BoolNegate:
      {
        size_t sz = out_sz();
        TREX_CHECK(inp_sz(0).value_or(sz) == sz,
                   "BoolNegate: input/output size mismatch");
        (void)sz;
        BooleanOp op = BooleanOp::Negate;
        ssa::Variable v = ssa_sp->get_output_impacted_variable(il_addr).value();
        types.capability_known_boolean(v);
        types.capability_boolean_op(v, op, sz);
        ssa::Variable a = ssa_sp->get_input_variable(il_addr, 0);
        types.capability_known_boolean(a);
        types.capability_boolean_op(a, op, sz);
        break;
      }

      case OpKind::BoolAnd:
      case OpKind::BoolOr:
      case OpKind::BoolXor:
      {
        BooleanOp op =
            ins.op.kind == OpKind::BoolAnd ? BooleanOp::And
            : ins.op.kind == OpKind::BoolOr  ? BooleanOp::Or
                                            : BooleanOp::Xor;
        size_t sz = out_sz();
        TREX_CHECK(inp_sz(0).value_or(sz) == sz,
                   "Bool{And,Or,Xor}: input[0] size mismatch");
        TREX_CHECK(inp_sz(1).value_or(sz) == sz,
                   "Bool{And,Or,Xor}: input[1] size mismatch");
        (void)sz;
        ssa::Variable v = ssa_sp->get_output_impacted_variable(il_addr).value();
        types.capability_known_boolean(v);
        types.capability_boolean_op(v, op, sz);
        ssa::Variable a = ssa_sp->get_input_variable(il_addr, 0);
        types.capability_known_boolean(a);
        types.capability_boolean_op(a, op, sz);
        ssa::Variable b = ssa_sp->get_input_variable(il_addr, 1);
        types.capability_known_boolean(b);
        types.capability_boolean_op(b, op, sz);
        break;
      }

      case OpKind::FloatAdd:
      case OpKind::FloatSub:
      case OpKind::FloatMult:
      case OpKind::FloatDiv:
      {
        FloatOp op =
            ins.op.kind == OpKind::FloatAdd ? FloatOp::Add
            : ins.op.kind == OpKind::FloatSub ? FloatOp::Sub
            : ins.op.kind == OpKind::FloatMult ? FloatOp::Mult
                                               : FloatOp::Div;
        size_t sz = out_sz();
        TREX_CHECK(inp_sz(0).value_or(sz) == sz,
                   "FloatArith: input[0] size mismatch");
        TREX_CHECK(inp_sz(1).value_or(sz) == sz,
                   "FloatArith: input[1] size mismatch");
        (void)sz;
        types.capability_float_op(
            ssa_sp->get_output_impacted_variable(il_addr).value(), op, sz);
        types.capability_float_op(ssa_sp->get_input_variable(il_addr, 0), op, sz);
        types.capability_float_op(ssa_sp->get_input_variable(il_addr, 1), op, sz);
        break;
      }

      case OpKind::ScalarLowerOp:
      case OpKind::PackedVectorOp:
      {
        uint8_t n = ins.op.scalar_bits;
        VectorScalarOp vsop = ins.op.vsop;
        switch ( vsop )
        {
          case VectorScalarOp::FloatAdd:
          case VectorScalarOp::FloatSub:
          case VectorScalarOp::FloatMul:
          case VectorScalarOp::FloatDiv:
          {
            FloatOp fop =
                vsop == VectorScalarOp::FloatAdd ? FloatOp::Add
                : vsop == VectorScalarOp::FloatSub ? FloatOp::Sub
                : vsop == VectorScalarOp::FloatMul ? FloatOp::Mult
                                                   : FloatOp::Div;
            size_t sz = static_cast<size_t>(n);
            size_t vsz = out_sz();
            TREX_CHECK(sz < vsz,
                       "VectorOp: scalar size %zu >= vector size %zu",
                       sz, vsz);
            TREX_CHECK(inp_sz(0).value_or(vsz) == vsz,
                       "VectorOp: input[0] size mismatch");
            TREX_CHECK(inp_sz(1).value_or(vsz) == vsz,
                       "VectorOp: input[1] size mismatch");
            (void)vsz;
            types.capability_float_op(
                ssa_sp->get_output_impacted_variable(il_addr).value(), fop, sz);
            types.capability_float_op(ssa_sp->get_input_variable(il_addr, 0), fop, sz);
            types.capability_float_op(ssa_sp->get_input_variable(il_addr, 1), fop, sz);
            break;
          }
          case VectorScalarOp::LogicalShiftLeft:
          {
            size_t sz = static_cast<size_t>(n);
            size_t vsz = out_sz();
            TREX_CHECK(sz < vsz,
                       "VectorOp ShiftLeft: scalar size %zu >= vector size %zu",
                       sz, vsz);
            TREX_CHECK(inp_sz(0).value_or(vsz) == vsz,
                       "VectorOp ShiftLeft: input[0] size mismatch");
            (void)vsz;
            IntegerOp op = IntegerOp::LeftShift;
            types.capability_integer_op(
                ssa_sp->get_output_impacted_variable(il_addr).value(), op, sz);
            types.capability_integer_op(ssa_sp->get_input_variable(il_addr, 0), op, sz);
            types.capability_integer_op(ssa_sp->get_input_variable(il_addr, 1),
                                        IntegerOp::ShiftAmount,
                                        inp_sz(1).value());
            break;
          }
        }
        break;
      }

      case OpKind::ScalarUpperOp:
        // XXX/TODO: havoc the output (safe, conservative).
        break;

      case OpKind::Float2IntTrunc:
      {
        ssa::Variable v = ssa_sp->get_output_impacted_variable(il_addr).value();
        types.capability_integer_op(v, IntegerOp::ConvertFromFloatTrunc, out_sz());
        ssa::Variable a = ssa_sp->get_input_variable(il_addr, 0);
        types.capability_float_op(a, FloatOp::ConvertToIntTrunc, inp_sz(0).value());
        break;
      }

      case OpKind::Int2Float:
      {
        ssa::Variable v = ssa_sp->get_output_impacted_variable(il_addr).value();
        types.capability_float_op(v, FloatOp::ConvertFromInt, out_sz());
        ssa::Variable a = ssa_sp->get_input_variable(il_addr, 0);
        types.capability_integer_op(a, IntegerOp::ConvertToFloat, inp_sz(0).value());
        break;
      }

      case OpKind::FloatIsNan:
      {
        size_t sz = inp_sz(0).value();
        types.capability_known_boolean(
            ssa_sp->get_output_impacted_variable(il_addr).value());
        types.capability_float_op(ssa_sp->get_input_variable(il_addr, 0), FloatOp::Eq, sz);
        break;
      }

      case OpKind::FloatEqual:
      case OpKind::FloatNotEqual:
      case OpKind::FloatLess:
      case OpKind::FloatLessEqual:
      {
        FloatOp op =
            ins.op.kind == OpKind::FloatEqual     ? FloatOp::Eq
            : ins.op.kind == OpKind::FloatNotEqual ? FloatOp::Neq
            : ins.op.kind == OpKind::FloatLess     ? FloatOp::Lt
                                                  : FloatOp::LEq;
        size_t sz = inp_sz(0) ? *inp_sz(0) : inp_sz(1).value();
        TREX_CHECK(inp_sz(1).value_or(sz) == sz,
                   "FloatCmp: input[1] size mismatch");
        types.capability_known_boolean(
            ssa_sp->get_output_impacted_variable(il_addr).value());
        ssa::Variable a = ssa_sp->get_input_variable(il_addr, 0);
        ssa::Variable b = ssa_sp->get_input_variable(il_addr, 1);
        if ( trex::config().unify_types_on_comparison_ops )
          types.capability_have_same_type(a, b);
        types.capability_float_op(a, op, sz);
        types.capability_float_op(b, op, sz);
        break;
      }

      case OpKind::IntAdd:
      case OpKind::IntSub:
      case OpKind::IntMult:
      case OpKind::IntUDiv:
      case OpKind::IntURem:
      case OpKind::IntSDiv:
      case OpKind::IntSRem:
      case OpKind::IntAnd:
      case OpKind::IntOr:
      case OpKind::IntXor:
      {
        IntegerOp op =
            ins.op.kind == OpKind::IntAdd ? IntegerOp::Add
            : ins.op.kind == OpKind::IntSub ? IntegerOp::Sub
            : ins.op.kind == OpKind::IntMult ? IntegerOp::Mult
            : ins.op.kind == OpKind::IntUDiv ? IntegerOp::UDiv
            : ins.op.kind == OpKind::IntURem ? IntegerOp::URem
            : ins.op.kind == OpKind::IntSDiv ? IntegerOp::SDiv
            : ins.op.kind == OpKind::IntSRem ? IntegerOp::SRem
            : ins.op.kind == OpKind::IntAnd  ? IntegerOp::And
            : ins.op.kind == OpKind::IntOr   ? IntegerOp::Or
                                             : IntegerOp::Xor;
        size_t sz = out_sz();
        TREX_CHECK(inp_sz(0).value_or(sz) == sz,
                   "IntBinOp: input[0] size mismatch");
        TREX_CHECK(inp_sz(1).value_or(sz) == sz,
                   "IntBinOp: input[1] size mismatch");
        (void)sz;
        types.capability_integer_op(
            ssa_sp->get_output_impacted_variable(il_addr).value(), op, sz);
        types.capability_integer_op(ssa_sp->get_input_variable(il_addr, 0), op, sz);
        types.capability_integer_op(ssa_sp->get_input_variable(il_addr, 1), op, sz);
        break;
      }

      case OpKind::IntLeftShift:
      case OpKind::IntURightShift:
      case OpKind::IntSRightShift:
      {
        IntegerOp op =
            ins.op.kind == OpKind::IntLeftShift ? IntegerOp::LeftShift
            : ins.op.kind == OpKind::IntURightShift ? IntegerOp::URightShift
                                                    : IntegerOp::SRightShift;
        types.capability_integer_op(
            ssa_sp->get_output_impacted_variable(il_addr).value(), op, out_sz());
        types.capability_integer_op(ssa_sp->get_input_variable(il_addr, 0),
                                    op, inp_sz(0).value());
        types.capability_integer_op(ssa_sp->get_input_variable(il_addr, 1),
                                    IntegerOp::ShiftAmount, out_sz());
        break;
      }

      case OpKind::IntEqual:
      case OpKind::IntNotEqual:
      case OpKind::IntLess:
      case OpKind::IntSLess:
      {
        IntegerOp op =
            ins.op.kind == OpKind::IntEqual  ? IntegerOp::Eq
            : ins.op.kind == OpKind::IntNotEqual ? IntegerOp::Neq
            : ins.op.kind == OpKind::IntLess ? IntegerOp::ULt
                                             : IntegerOp::SLt;
        size_t sz = inp_sz(0).has_value() ? *inp_sz(0) : inp_sz(1).value();
        TREX_CHECK(inp_sz(1).value_or(sz) == sz,
                   "IntCmp: input[1] size mismatch");
        types.capability_known_boolean(
            ssa_sp->get_output_impacted_variable(il_addr).value());
        ssa::Variable a = ssa_sp->get_input_variable(il_addr, 0);
        ssa::Variable b = ssa_sp->get_input_variable(il_addr, 1);
        if ( trex::config().unify_types_on_comparison_ops )
          types.capability_have_same_type(a, b);
        types.capability_integer_op(a, op, sz);
        types.capability_integer_op(b, op, sz);
        break;
      }

      case OpKind::IntCarry:
      case OpKind::IntSCarry:
      case OpKind::IntSBorrow:
      {
        IntegerOp op =
            ins.op.kind == OpKind::IntCarry ? IntegerOp::UCarry
            : ins.op.kind == OpKind::IntSCarry ? IntegerOp::SCarry
                                               : IntegerOp::SBorrow;
        size_t sz = inp_sz(0).has_value() ? *inp_sz(0) : inp_sz(1).value();
        TREX_CHECK(inp_sz(0).value_or(sz) == sz,
                   "Carry/Borrow: input[0] size mismatch");
        TREX_CHECK(inp_sz(1).value_or(sz) == sz,
                   "Carry/Borrow: input[1] size mismatch");
        types.capability_known_boolean(
            ssa_sp->get_output_impacted_variable(il_addr).value());
        ssa::Variable a = ssa_sp->get_input_variable(il_addr, 0);
        ssa::Variable b = ssa_sp->get_input_variable(il_addr, 1);
        if ( trex::config().unify_types_on_carry_or_borrow_ops )
          types.capability_have_same_type(a, b);
        types.capability_integer_op(a, op, sz);
        types.capability_integer_op(b, op, sz);
        break;
      }

      case OpKind::IntOnesComp:
      case OpKind::IntTwosComp:
      {
        IntegerOp op = ins.op.kind == OpKind::IntOnesComp
                           ? IntegerOp::OnesComplement
                           : IntegerOp::TwosComplement;
        size_t sz = out_sz();
        TREX_CHECK(inp_sz(0).value_or(sz) == sz,
                   "IntOnesComp/TwosComp: input[0] size mismatch");
        (void)sz;
        types.capability_integer_op(
            ssa_sp->get_output_impacted_variable(il_addr).value(), op, sz);
        types.capability_integer_op(ssa_sp->get_input_variable(il_addr, 0), op, sz);
        break;
      }

      case OpKind::FloatRound:
      case OpKind::FloatNeg:
      case OpKind::FloatAbs:
      case OpKind::FloatSqrt:
      {
        FloatOp op =
            ins.op.kind == OpKind::FloatRound ? FloatOp::Round
            : ins.op.kind == OpKind::FloatNeg  ? FloatOp::Neg
            : ins.op.kind == OpKind::FloatAbs  ? FloatOp::Abs
                                               : FloatOp::Sqrt;
        size_t sz = out_sz();
        TREX_CHECK(inp_sz(0).value_or(sz) == sz,
                   "FloatUnary: input[0] size mismatch");
        (void)sz;
        types.capability_float_op(
            ssa_sp->get_output_impacted_variable(il_addr).value(), op, sz);
        types.capability_float_op(ssa_sp->get_input_variable(il_addr, 0), op, sz);
        break;
      }

      case OpKind::Float2Float:
      {
        size_t tgt_sz = out_sz();
        size_t src_sz = inp_sz(0).value();
        types.capability_float_op(
            ssa_sp->get_output_impacted_variable(il_addr).value(),
            FloatOp::ConvertFromDifferentSizedFloat, tgt_sz);
        types.capability_float_op(ssa_sp->get_input_variable(il_addr, 0),
                                  FloatOp::ConvertToDifferentSizedFloat, src_sz);
        break;
      }

      case OpKind::IntZext:
      case OpKind::IntSext:
      {
        IntegerOp src_op = ins.op.kind == OpKind::IntZext
                               ? IntegerOp::ZeroExtendSrc
                               : IntegerOp::SignExtendSrc;
        IntegerOp tgt_op = ins.op.kind == OpKind::IntZext
                               ? IntegerOp::ZeroExtendTgt
                               : IntegerOp::SignExtendTgt;
        size_t tgt_sz = out_sz();
        size_t src_sz = inp_sz(0).value();
        TREX_CHECK(src_sz < tgt_sz,
                   "Int{S,Z}ext: src size %zu >= tgt size %zu",
                   src_sz, tgt_sz);
        types.capability_integer_op(
            ssa_sp->get_output_impacted_variable(il_addr).value(), tgt_op, tgt_sz);
        types.capability_integer_op(ssa_sp->get_input_variable(il_addr, 0),
                                    src_op, src_sz);
        break;
      }

      case OpKind::Popcount:
        types.capability_integer_op(ssa_sp->get_input_variable(il_addr, 0),
                                    IntegerOp::Popcount, inp_sz(0).value());
        break;

      case OpKind::Load:
      {
        const Variable &src = ins.inputs[0];
        switch ( src.kind )
        {
          case VarKind::Unused:
          case VarKind::Constant:
          case VarKind::ILAddress:
          case VarKind::ILOffset:
          case VarKind::MachineAddress:
          case VarKind::Varnode:
          case VarKind::StackVariable:
            TREX_UNREACHABLE("Load: source must be a DerefVarnode");
          case VarKind::DerefVarnode:
          {
            size_t derefval_size = src.derefval_size;
            size_t addr_as = src.addr_address_space_idx;
            TREX_CHECK(ins.output.try_size().value() == derefval_size,
                       "Load: output size %zu != derefval size %zu ({})",
                       ins.output.try_size().value_or(0), derefval_size, ins.debug_string());
            TREX_CHECK(program->address_spaces[addr_as].wordsize
                         == program->pointer_size,
                       "Load: deref address space wordsize %zu != pointer size %zu",
                       program->address_spaces[addr_as].wordsize,
                       program->pointer_size);
            ssa::Variable to_loc = ssa_sp->get_output_impacted_variable(il_addr).value();
            types.capability_deref(ssa_sp->get_input_variable(il_addr, 0),
                                   program->pointer_size, to_loc, derefval_size);
            break;
          }
        }
        break;
      }

      case OpKind::Store:
      {
        const Variable &store_value = ins.inputs[1];
        const Variable &dst = ins.inputs[0];
        switch ( dst.kind )
        {
          case VarKind::Unused:
          case VarKind::Constant:
          case VarKind::ILAddress:
          case VarKind::ILOffset:
          case VarKind::MachineAddress:
          case VarKind::Varnode:
            TREX_UNREACHABLE("Store: destination must be a DerefVarnode");
          case VarKind::StackVariable:
            TREX_UNREACHABLE("Store: destination must be a DerefVarnode");
          case VarKind::DerefVarnode:
          {
            size_t derefval_size = dst.derefval_size;
            if ( auto s = store_value.try_size() )
            {
              TREX_CHECK(derefval_size == *s,
                         "Store: derefval size %zu != store-value size %zu ({})",
                         derefval_size, *s, ins.debug_string());
            }
            size_t addr_as = dst.addr_address_space_idx;
            TREX_CHECK(program->address_spaces[addr_as].wordsize
                         == program->pointer_size,
                       "Store: deref address space wordsize %zu != pointer size %zu",
                       program->address_spaces[addr_as].wordsize,
                       program->pointer_size);
            types.capability_deref(ssa_sp->get_input_variable(il_addr, 0),
                                   program->pointer_size,
                                   ssa_sp->get_input_variable(il_addr, 1),
                                   derefval_size);
            break;
          }
        }
        break;
      }
    }
  }

  types.propagate_pointerness_through_arithmetic_constraints();
  types.canonicalize_indexes();
  return types;
}

} // namespace trex
