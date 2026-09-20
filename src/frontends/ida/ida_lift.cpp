// IDA (Hex-Rays microcode) frontend for TRex - see ida_lift.hpp for the contract.
//
// Design summary:
//  * One IL instruction group per microinstruction, keyed by a unique machine address so branch
//    targets resolve; a block's first microinstruction is keyed at the block start, which is what
//    makes the entry block's key equal the function entry address (required so that
//    Program::end_function sees an ILAddress on FunctionStart).
//  * Register operands become varnodes in the `register` space (offset = processor register
//    number), stack slots in the `stack` space (offset = decompiler stack offset), computed
//    temporaries in the `unique` space.
//  * Address expressions are materialised as location varnodes so Load/Store always see a
//    DerefVarnode; `base + constant` shapes survive into IntAdd/IntSub, which is exactly the
//    pattern the co-location analysis walks back through.
//  * Callee-saved ("unaffected") sets come from the call sites' `mcallinfo_t::spoiled` lists,
//    restricted to the registers the lifted program actually uses.

#include "ida_lift.hpp"

#include <algorithm>
#include <chrono>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <trex/error.hpp>
#include <trex/inference_config.hpp>
#include <trex/log.hpp>

namespace trex::ida {

namespace {

/// Ids for pseudo-registers (kernel registers, condition codes, temp regs).
constexpr size_t kPseudoRegBase = (size_t)1 << 48;
/// Ids for the per-function "return address" placeholder used by Op::Return.
constexpr size_t kReturnAddressBase = (size_t)1 << 40;

using RegKey = std::pair<int, int>; // (processor register number, size in bytes)

/// A group of IL instructions that came from one microinstruction.
struct Group
{
  uint64_t key = 0;
  /// False when `key` is a synthetic (fictional) address we invented: `mba_t::alloc_fict_ea()`
  /// is only unique within one `mba_t`, so synthetic keys are re-uniquified program-wide before
  /// the groups are handed to the Program (real machine addresses are never remapped, since
  /// branch targets resolve through them).
  bool real_key = true;
  std::vector<Instruction> insns;
};

struct CallSite
{
  ea_t target = BADADDR;
  const minsn_t *insn = nullptr;
  mba_t *mba = nullptr;
  bool analyzed = false;
};

bool is_register_location(const mop_t &op)
{
  return op.t == mop_r || op.t == mop_l || op.t == mop_S;
}

bool is_jcc(mcode_t op)
{
  return op >= m_jcnd && op <= m_jle;
}

/// True for addresses that exist in the IDB (and are therefore stable program-wide).
///
/// The decompiler hands out fictional addresses for instructions it synthesised itself
/// (propagated/inlined code); those are only unique within one function's microcode, so they must
/// be treated like the addresses we allocate with `mba_t::alloc_fict_ea`.
bool is_real_ea(ea_t ea)
{
  return ea != BADADDR && ea != (ea_t)-1 && get_func(ea) != nullptr;
}

/// One function's lifting state.
class Lifter
{
public:
  Lifter(mba_t *mba, std::string name, size_t function_index)
    : mba_(mba), name_(std::move(name)), function_index_(function_index), ptr_size_(inf_is_64bit() ? 8 : 4)
  {
  }

  void lift_all();
  void collect_variables(bool variables_only_args);
  /// Record a call site (callee identity + caller-side argument/result variables) for
  /// inter-procedural type propagation. `direct_target` is the call's machine address for a direct
  /// call, `BADADDR` for an indirect one.
  void record_call_site(const minsn_t &ins, ea_t direct_target);

  const std::vector<Group> &groups() const { return groups_; }
  /// This function's call interface (parameters and returned value).
  const trex::interproc::FunctionInterface &interface_record() const { return interface_; }
  /// This function's call sites, for inter-procedural type propagation.
  const std::vector<trex::interproc::CallSite> &interproc_sites() const { return interproc_sites_; }
  const std::vector<VariableRow> &rows() const { return rows_; }
  const std::set<RegKey> &regs_used() const { return regs_used_; }
  const std::vector<CallSite> &call_sites() const { return call_sites_; }
  int fallback_count() const { return fallback_count_; }
  const std::map<std::string, int> &fallback_histogram() const { return fallback_histogram_; }

private:
  // ---------------------------------------------------------------- variables

  Variable pseudo_varnode(mreg_t reg, int size)
  {
    std::pair<mreg_t, int> key(reg, size);
    std::map<std::pair<mreg_t, int>, size_t>::iterator it = pseudo_.find(key);
    if ( it == pseudo_.end() )
    {
      size_t id = kPseudoRegBase + pseudo_.size();
      it = pseudo_.emplace(key, id).first;
    }
    return Variable::varnode(SPACE_UNIQUE, it->second, (size_t)size);
  }

  Variable varnode_for_mreg(mreg_t reg, int size)
  {
    if ( size <= 0 )
      return Variable::unused();
    int preg = mreg2reg(reg, size);
    if ( preg < 0 )
      return pseudo_varnode(reg, size);
    regs_used_.insert(RegKey(preg, size));
    return Variable::varnode(SPACE_REGISTER, (size_t)preg, (size_t)size);
  }

  size_t new_temp() { return next_temp_++; }

  Variable temp_varnode(size_t id, int size)
  {
    return Variable::varnode(SPACE_UNIQUE, id, (size_t)(size > 0 ? size : 1));
  }

  /// Location of an lvar reference (register- or stack-located).
  std::optional<Variable> lvar_location(const mop_t &op, int size)
  {
    if ( op.t != mop_l || op.l == nullptr )
      return std::nullopt;
    // `size` may be NOSIZE when the reference was reached through an `mop_a` wrapper (the wrapped
    // operand does not always carry a size); fall back to the reference's own size, and give up if
    // neither is usable.
    const int sz = size > 0 ? size : op.size;
    if ( sz <= 0 )
      return std::nullopt;
    const lvar_t &v = op.l->var();
    if ( v.is_stk_var() )
      return Variable::varnode(SPACE_STACK, (size_t)(v.get_stkoff() + op.l->off), (size_t)sz);
    if ( v.is_reg_var() )
    {
      int preg = mreg2reg(v.get_reg1(), sz);
      if ( preg < 0 )
        return pseudo_varnode(v.get_reg1(), sz);
      regs_used_.insert(RegKey(preg, sz));
      return Variable::varnode(SPACE_REGISTER, (size_t)preg, (size_t)sz);
    }
    return std::nullopt;
  }

  /// Destination varnode for instructions that write a simple location.
  std::optional<Variable> dest_varnode(const mop_t &d)
  {
    switch ( d.t )
    {
      case mop_r:
        return varnode_for_mreg(d.r, d.size);
      case mop_l:
        return lvar_location(d, d.size);
      case mop_S:
      {
        const int sz = d.size > 0 ? d.size : -1;
        if ( sz <= 0 )
          return std::nullopt;
        return Variable::varnode(SPACE_STACK, (size_t)d.s->off, (size_t)sz);
      }
      default:
        return std::nullopt;
    }
  }

  // ---------------------------------------------------------------- emission

  void emit(const Op &op, Variable out, Variable in0 = Variable::unused(), Variable in1 = Variable::unused())
  {
    Instruction ins;
    ins.address = cur_key_;
    ins.op = op;
    ins.output = out;
    ins.inputs[0] = in0;
    ins.inputs[1] = in1;
    cur_.push_back(ins);
  }

  void emit(OpKind kind, Variable out, Variable in0 = Variable::unused(), Variable in1 = Variable::unused())
  {
    emit(Op(kind), out, in0, in1);
  }

  void emit_nop() { emit(OpKind::Nop, Variable::unused()); }

  void note_fallback(const char *why)
  {
    ++fallback_count_;
    ++fallback_histogram_[why];
    log::trace("IDA frontend fallback", { { "why", why }, { "func", name_ } });
  }

  void log_insn(const char *why, const minsn_t &ins)
  {
    log::trace("IDA frontend instruction detail",
               { { "why", why },
                 { "func", name_ },
                 { "opc", (int)ins.opcode },
                 { "l", ins.l.t == mop_z ? "<z>" : ins.l.dstr() },
                 { "r", ins.r.t == mop_z ? "<z>" : ins.r.dstr() },
                 { "d", ins.d.t == mop_z ? "<z>" : ins.d.dstr() } });
  }

  /// Universal fallback: the destination is marked as non-deterministically modified.
  void fallback(const minsn_t *ins, const char *why)
  {
    note_fallback(why);
    if ( ins != nullptr )
    {
      std::optional<Variable> out = resolve_destination(ins->d);
      if ( out.has_value() )
      {
        emit(OpKind::UnderspecifiedOutputModification, *out);
        return;
      }
    }
    emit_nop();
  }

  Variable constant_temp(uint64_t value, int size)
  {
    size_t id = new_temp();
    Variable t = temp_varnode(id, size);
    emit(OpKind::Copy, t, Variable::constant(value, (size_t)(size > 0 ? size : 1)));
    return t;
  }

  /// Destination of a value-producing instruction.
  ///
  /// When the decompiler inlines an instruction into an operand (`mop_d`) it often leaves the
  /// nested instruction's destination empty; `forced_dest_` carries the temporary that the
  /// nested lift must write into instead.
  std::optional<Variable> resolve_destination(const mop_t &d)
  {
    std::optional<Variable> v = dest_varnode(d);
    if ( v.has_value() )
      return v;
    if ( forced_dest_.has_value() && (d.t == mop_z || d.t == mop_d || d.t == mop_p) )
      return forced_dest_;
    return std::nullopt;
  }

  std::optional<ASLocation> address_location(const mop_t &op, bool *ok);
  Variable load_value(const mop_t &op);
  void assign_value(const mop_t &d, const Variable &value, int size);
  std::optional<Variable> target_operand(const mop_t &op) const;
  Variable lift_subinstruction(const minsn_t &sub, int out_size);
  void lift_set_or_jcc(const minsn_t &ins);

  void lift_insn(const minsn_t &ins);
  /// Emits a binary op whose destination may be a location or memory.
  void lift_binary(const minsn_t &ins, OpKind kind);

  mba_t *mba_;
  std::string name_;
  size_t function_index_;
  int ptr_size_;

  std::vector<Group> groups_;
  std::vector<Instruction> cur_;
  uint64_t cur_key_ = 0;

  std::map<ea_t, uint64_t> real_to_key_;
  std::map<std::pair<mreg_t, int>, size_t> pseudo_;
  size_t next_temp_ = 0;

  std::set<RegKey> regs_used_;
  std::vector<CallSite> call_sites_;
  std::vector<VariableRow> rows_;
  /// This function's call interface (parameters, returned value).
  trex::interproc::FunctionInterface interface_;
  /// Call sites of this function, for inter-procedural type propagation.
  std::vector<trex::interproc::CallSite> interproc_sites_;

  std::map<std::string, int> fallback_histogram_;
  int fallback_count_ = 0;
  std::optional<Variable> forced_dest_;
};

//--------------------------------------------------------------------------
// Operand mapping
//--------------------------------------------------------------------------

std::optional<ASLocation> Lifter::address_location(const mop_t &op, bool *ok)
{
  *ok = true;
  switch ( op.t )
  {
    case mop_r:
    {
      Variable v = varnode_for_mreg(op.r, op.size);
      return ASLocation(v.address_space_idx, v.offset);
    }
    case mop_l:
    case mop_S:
    {
      std::optional<Variable> v = dest_varnode(op);
      if ( v.has_value() )
        return ASLocation(v->address_space_idx, v->offset);
      break;
    }
    case mop_a:
    {
      const mop_t &wrapped = *op.a;
      if ( wrapped.is_glbvar() )
      {
        Variable t = constant_temp(wrapped.g, (int)ptr_size_);
        return ASLocation(SPACE_UNIQUE, t.offset);
      }
      std::optional<Variable> v = dest_varnode(wrapped);
      if ( v.has_value() )
        return ASLocation(v->address_space_idx, v->offset);
      break;
    }
    case mop_n:
    {
      Variable t = constant_temp(op.nnn->value, (int)ptr_size_);
      return ASLocation(SPACE_UNIQUE, t.offset);
    }
    case mop_v:
    {
      Variable t = constant_temp(op.g, (int)ptr_size_);
      return ASLocation(SPACE_UNIQUE, t.offset);
    }
    case mop_d:
    {
      Variable t = lift_subinstruction(*op.d, (int)ptr_size_);
      return ASLocation(SPACE_UNIQUE, t.offset);
    }
    default:
      break;
  }
  *ok = false;
  return std::nullopt;
}

Variable Lifter::load_value(const mop_t &op)
{
  switch ( op.t )
  {
    case mop_z:
      return Variable::unused();

    case mop_n:
      return Variable::constant(op.nnn->value, (size_t)(op.size > 0 ? op.size : 1));

    case mop_r:
      return varnode_for_mreg(op.r, op.size);

    case mop_l:
    case mop_S:
    {
      std::optional<Variable> v = dest_varnode(op);
      if ( v.has_value() )
        return *v;
      break;
    }

    case mop_a:
    {
      const mop_t &wrapped = *op.a;
      if ( wrapped.is_glbvar() )
        return constant_temp(wrapped.g, op.size > 0 ? op.size : (int)ptr_size_);
      std::optional<Variable> v = dest_varnode(wrapped);
      if ( v.has_value() )
        return *v;
      break;
    }

    case mop_v:
    {
      // A bare global operand is an implicit load from that address.
      bool ok = false;
      std::optional<ASLocation> loc = address_location(op, &ok);
      if ( ok && loc.has_value() )
      {
        size_t id = new_temp();
        Variable t = temp_varnode(id, op.size);
        emit(OpKind::Load,
             t,
             Variable::deref_varnode(SPACE_RAM,
                                     (size_t)(op.size > 0 ? op.size : 1),
                                     loc->address_space_idx,
                                     loc->offset));
        return t;
      }
      break;
    }

    case mop_d:
      return lift_subinstruction(*op.d, op.size);

    case mop_p:
    {
      Variable lo = load_value(op.pair->lop);
      Variable hi = load_value(op.pair->hop);
      int total = op.pair->lop.size + op.pair->hop.size;
      size_t id = new_temp();
      Variable t = temp_varnode(id, total);
      emit(OpKind::Piece, t, lo, hi);
      return t;
    }

    default:
      break;
  }

  note_fallback("unmappable operand");
  size_t id = new_temp();
  Variable t = temp_varnode(id, op.size);
  emit(OpKind::UnderspecifiedOutputModification, t);
  return t;
}

void Lifter::assign_value(const mop_t &d, const Variable &value, int size)
{
  if ( d.t == mop_v || d.t == mop_a )
  {
    bool ok = false;
    std::optional<ASLocation> loc = address_location(d, &ok);
    if ( !ok || !loc.has_value() )
    {
      note_fallback("unmappable store address");
      return;
    }
    emit(OpKind::Store,
         Variable::unused(),
         Variable::deref_varnode(SPACE_RAM, (size_t)(size > 0 ? size : 1), loc->address_space_idx, loc->offset),
         value);
    return;
  }

  std::optional<Variable> out = resolve_destination(d);
  if ( out.has_value() )
  {
    if ( !value.is_used() )
    {
      // A Copy with no source is not valid IL; the destination is simply not defined here.
      note_fallback("assignment from an unmappable source");
      return;
    }
    const std::optional<size_t> vsz = value.try_size();
    if ( !vsz.has_value() || *vsz == out->size )
    {
      emit(OpKind::Copy, *out, value);
    }
    else if ( out->size > *vsz )
    {
      // Widening write (e.g. `mov rax.8, ecx.4`): zero-extend, which is what the IL validator
      // requires (plain Copy demands equal sizes).
      emit(OpKind::IntZext, *out, value);
    }
    else
    {
      // Narrowing write: keep the low bytes.
      emit(OpKind::SubPiece, *out, value, Variable::constant(0, 4));
    }
    return;
  }
  note_fallback("unmappable assignment destination");
}

std::optional<Variable> Lifter::target_operand(const mop_t &op) const
{
  switch ( op.t )
  {
    case mop_v:
      return Variable::machine_address(op.g);
    case mop_n:
      return Variable::machine_address(op.nnn->value);
    case mop_b:
    {
      mblock_t *blk = mba_->get_mblock(op.b);
      if ( blk == nullptr || blk->start == BADADDR || blk->start == (ea_t)-1 )
        return std::nullopt;
      return Variable::machine_address(blk->start);
    }
    default:
      return std::nullopt;
  }
}

Variable Lifter::lift_subinstruction(const minsn_t &sub, int out_size)
{
  size_t id = new_temp();
  Variable out = temp_varnode(id, out_size > 0 ? out_size : sub.d.size);

  const size_t before = cur_.size();

  std::optional<Variable> saved = forced_dest_;
  forced_dest_ = out;
  lift_insn(sub);
  forced_dest_ = saved;

  // The nested instruction wrote to our temporary: that temporary is the operand's value.
  for ( size_t i = cur_.size(); i-- > before; )
  {
    if ( cur_[i].output == out )
      return out;
  }

  // Otherwise it wrote to its own destination (a register or stack slot); the parent operand then
  // reads that location, which is exactly what the IL expresses by naming it.
  std::optional<Variable> own_dest = dest_varnode(sub.d);
  if ( own_dest.has_value() )
  {
    for ( size_t i = cur_.size(); i-- > before; )
    {
      if ( cur_[i].output == *own_dest )
        return *own_dest;
    }
  }

  log_insn("nested instruction produced no output", sub);
  note_fallback("nested instruction without a detectable output");
  emit(OpKind::UnderspecifiedOutputModification, out);
  return out;
}

//--------------------------------------------------------------------------
// Opcode mapping
//--------------------------------------------------------------------------

void Lifter::lift_binary(const minsn_t &ins, OpKind kind)
{
  const int size = ins.d.size > 0 ? ins.d.size : ins.l.size;
  Variable a = load_value(ins.l);
  Variable b = load_value(ins.r);

  // Most microcode ops require operands of equal size; if the sizes disagree the instruction
  // cannot be expressed in the IL and is reported instead of emitting invalid IL.
  {
    const std::optional<size_t> sa = a.try_size();
    const std::optional<size_t> sb = b.try_size();
    if ( sa.has_value() && sb.has_value() && *sa != *sb )
    {
      log_insn("operand size mismatch", ins);
      fallback(&ins, "operand size mismatch");
      return;
    }
  }

  std::optional<Variable> out = resolve_destination(ins.d);
  if ( out.has_value() )
  {
    emit(kind, *out, a, b);
    return;
  }

  size_t id = new_temp();
  Variable t = temp_varnode(id, size);
  emit(kind, t, a, b);
  assign_value(ins.d, t, size);
}

void Lifter::lift_set_or_jcc(const minsn_t &ins)
{
  const int size = ins.l.size > 0 ? ins.l.size : ins.d.size;
  Variable a = load_value(ins.l);
  Variable b = load_value(ins.r);

  Op cmp(OpKind::IntEqual);
  bool swap = false;
  bool negate = false;
  bool one_operand = false;

  switch ( ins.opcode )
  {
    case m_setz:
    case m_jz:
      cmp = Op(OpKind::IntEqual);
      break;
    case m_setnz:
    case m_jnz:
      cmp = Op(OpKind::IntNotEqual);
      break;
    case m_setb:
    case m_jb:
      cmp = Op(OpKind::IntLess);
      break;
    case m_setae:
    case m_jae:
      cmp = Op(OpKind::IntLess);
      negate = true;
      break;
    case m_seta:
    case m_ja:
      cmp = Op(OpKind::IntLess);
      swap = true;
      break;
    case m_setbe:
    case m_jbe:
      cmp = Op(OpKind::IntLess);
      swap = true;
      negate = true;
      break;
    case m_setl:
    case m_jl:
      cmp = Op(OpKind::IntSLess);
      break;
    case m_setge:
    case m_jge:
      cmp = Op(OpKind::IntSLess);
      negate = true;
      break;
    case m_setg:
    case m_jg:
      cmp = Op(OpKind::IntSLess);
      swap = true;
      break;
    case m_setle:
    case m_jle:
      cmp = Op(OpKind::IntSLess);
      swap = true;
      negate = true;
      break;
    case m_sets:
      cmp = Op(OpKind::IntSLess);
      b = Variable::constant(0, (size_t)(size > 0 ? size : 1));
      one_operand = true;
      break;
    default:
      fallback(&ins, "unmappable condition code operation");
      return;
  }

  std::optional<Variable> target;
  if ( is_jcc(ins.opcode) )
  {
    target = target_operand(ins.d);
    if ( !target.has_value() )
    {
      fallback(&ins, "unmappable branch target");
      return;
    }
  }

  Variable cond;
  {
    size_t id = new_temp();
    cond = temp_varnode(id, 1);
    emit(cmp, cond, swap && !one_operand ? b : a, swap && !one_operand ? a : b);
  }
  if ( negate )
  {
    size_t id = new_temp();
    Variable neg = temp_varnode(id, 1);
    emit(OpKind::BoolNegate, neg, cond);
    cond = neg;
  }

  if ( is_jcc(ins.opcode) )
    emit(OpKind::Cbranch, Variable::unused(), *target, cond);
  else
    assign_value(ins.d, cond, 1);
}

void Lifter::lift_insn(const minsn_t &ins)
{
  const int dsize = ins.d.size;
  const int lsize = ins.l.size;

  // The decompiler sometimes leaves an operand's size as NOSIZE (-1) for things it could not
  // size. Such an operand cannot be represented in the IL (`Variable` sizes are byte counts), and
  // letting one through would corrupt every size-based invariant downstream.
  {
    // Only *value* operands must carry a size. Control-flow targets (`mop_b` blocks, `mop_c`
    // cases), call infos (`mop_f`), helpers (`mop_h`), strings and `mop_z` legitimately have
    // NOSIZE; rejecting those would degrade every branch to a fallback and destroy the CFG.
    auto is_value_operand = [](const mop_t &op) {
      switch ( op.t )
      {
        case mop_z:
        case mop_b:
        case mop_c:
        case mop_f:
        case mop_h:
        case mop_str:
          return false;
        default:
          return true;
      }
    };
    auto bad_size = [&](const mop_t &op) { return is_value_operand(op) && op.size <= 0; };
    // A direct call's `l` operand is the callee address (`mop_v`) and, like a branch target, it
    // legitimately carries no size. Rejecting it here dropped *every* call to an address into a
    // fallback, so the IL contained no `CallWithFallthrough` for them at all.
    const bool call_target = ins.opcode == m_call;
    if ( ( bad_size(ins.l) && !call_target ) || bad_size(ins.r) || bad_size(ins.d) )
    {
      log_insn("operand with unknown size", ins);
      fallback(&ins, "operand with unknown size");
      return;
    }
  }

  switch ( ins.opcode )
  {
    case m_nop:
      emit_nop();
      break;

    case m_mov:
      assign_value(ins.d, load_value(ins.l), dsize > 0 ? dsize : lsize);
      break;

    case m_ldc:
      assign_value(ins.d, Variable::constant(ins.l.nnn->value, (size_t)(lsize > 0 ? lsize : 1)), lsize);
      break;

    case m_ldx:
    {
      bool ok = false;
      std::optional<ASLocation> loc = address_location(ins.r, &ok);
      std::optional<Variable> out = resolve_destination(ins.d);
      if ( !ok || !loc.has_value() || !out.has_value() )
      {
        log_insn("unmappable load", ins);
        fallback(&ins, "unmappable load");
        break;
      }
      emit(OpKind::Load,
           *out,
           Variable::deref_varnode(SPACE_RAM, (size_t)(dsize > 0 ? dsize : 1), loc->address_space_idx, loc->offset));
      break;
    }

    case m_stx:
    {
      bool ok = false;
      std::optional<ASLocation> loc = address_location(ins.d, &ok);
      if ( !ok || !loc.has_value() )
      {
        fallback(&ins, "unmappable store address");
        break;
      }
      Variable value = load_value(ins.l);
      emit(OpKind::Store,
           Variable::unused(),
           Variable::deref_varnode(SPACE_RAM, (size_t)(lsize > 0 ? lsize : 1), loc->address_space_idx, loc->offset),
           value);
      break;
    }

    case m_neg:
    case m_lnot:
    case m_bnot:
    case m_xds:
    case m_xdu:
    case m_low:
    case m_high:
    {
      Variable a = load_value(ins.l);
      Variable out;
      Op op(OpKind::Nop);
      switch ( ins.opcode )
      {
        case m_neg: op = Op(OpKind::IntTwosComp); break;
        case m_lnot: op = Op(OpKind::BoolNegate); break;
        case m_bnot: op = Op(OpKind::IntOnesComp); break;
        case m_xds: op = Op(OpKind::IntSext); break;
        case m_xdu: op = Op(OpKind::IntZext); break;
        case m_low: op = Op(OpKind::SubPiece); break;
        case m_high: op = Op(OpKind::SubPiece); break;
        default: break;
      }
      if ( ins.opcode == m_low || ins.opcode == m_high )
      {
        int shift = ins.opcode == m_low ? 0 : 8 * (lsize - dsize);
        if ( shift < 0 )
          shift = 0;
        size_t id = new_temp();
        Variable t = temp_varnode(id, dsize);
        emit(op, t, a, Variable::constant((uint64_t)shift, 4));
        assign_value(ins.d, t, dsize);
        break;
      }
      if ( ins.opcode == m_lnot && ( dsize != 1 || lsize != 1 ) )
      {
        fallback(&ins, "logical not with non-boolean operands");
        break;
      }
      std::optional<Variable> dest = resolve_destination(ins.d);
      if ( dest.has_value() )
      {
        emit(op, *dest, a);
      }
      else
      {
        size_t id = new_temp();
        Variable t = temp_varnode(id, dsize);
        emit(op, t, a);
        assign_value(ins.d, t, dsize);
      }
      break;
    }

    case m_add:
      lift_binary(ins, OpKind::IntAdd);
      break;
    case m_sub:
      lift_binary(ins, OpKind::IntSub);
      break;
    case m_mul:
      lift_binary(ins, OpKind::IntMult);
      break;
    case m_udiv:
      lift_binary(ins, OpKind::IntUDiv);
      break;
    case m_sdiv:
      lift_binary(ins, OpKind::IntSDiv);
      break;
    case m_umod:
      lift_binary(ins, OpKind::IntURem);
      break;
    case m_smod:
      lift_binary(ins, OpKind::IntSRem);
      break;
    case m_or:
      lift_binary(ins, OpKind::IntOr);
      break;
    case m_and:
      lift_binary(ins, OpKind::IntAnd);
      break;
    case m_xor:
      lift_binary(ins, OpKind::IntXor);
      break;
    case m_shl:
      lift_binary(ins, OpKind::IntLeftShift);
      break;
    case m_shr:
      lift_binary(ins, OpKind::IntURightShift);
      break;
    case m_sar:
      lift_binary(ins, OpKind::IntSRightShift);
      break;

    case m_cfadd:
    {
      // carry of (l + r): modelled as the unsigned addition carry observation on both inputs
      Variable a = load_value(ins.l);
      Variable b = load_value(ins.r);
      std::optional<Variable> out = resolve_destination(ins.d);
      if ( out.has_value() )
        emit(OpKind::IntCarry, *out, a, b);
      else
        fallback(&ins, "carry with non-register destination");
      break;
    }

    case m_ofadd:
    {
      Variable a = load_value(ins.l);
      Variable b = load_value(ins.r);
      std::optional<Variable> out = resolve_destination(ins.d);
      if ( out.has_value() )
        emit(OpKind::IntSCarry, *out, a, b);
      else
        fallback(&ins, "overflow with non-register destination");
      break;
    }

    case m_cfshl:
    case m_cfshr:
      fallback(&ins, "carry of shift");
      break;

    case m_sets:
    case m_seto:
    case m_setp:
    case m_setnz:
    case m_setz:
    case m_setae:
    case m_setb:
    case m_seta:
    case m_setbe:
    case m_setg:
    case m_setge:
    case m_setl:
    case m_setle:
    case m_jcnd:
    case m_jnz:
    case m_jz:
    case m_jae:
    case m_jb:
    case m_ja:
    case m_jbe:
    case m_jg:
    case m_jge:
    case m_jl:
    case m_jle:
      if ( ins.opcode == m_seto || ins.opcode == m_setp )
        fallback(&ins, "overflow/parity condition");
      else
        lift_set_or_jcc(ins);
      break;

    case m_jtbl:
    {
      // Switch statement: an indirect branch whose targets are known.
      Variable idx = load_value(ins.l);
      Instruction branch;
      branch.address = cur_key_;
      branch.op = Op(OpKind::BranchIndOffset);
      branch.output = Variable::unused();
      branch.inputs[0] = idx;
      branch.inputs[1] = Variable::unused();
      if ( ins.r.t == mop_c && ins.r.c != nullptr )
      {
        for ( size_t i = 0; i < ins.r.c->targets.size(); ++i )
        {
          mblock_t *blk = mba_->get_mblock(ins.r.c->targets[i]);
          if ( blk != nullptr && blk->start != BADADDR && blk->start != (ea_t)-1 )
            branch.indirect_targets.push_back(Variable::machine_address(blk->start));
        }
      }
      cur_.push_back(branch);
      break;
    }

    case m_ijmp:
    {
      Variable addr = load_value(ins.r);
      emit(OpKind::BranchIndOffset, Variable::unused(), addr);
      break;
    }

    case m_goto:
    {
      std::optional<Variable> target = target_operand(ins.l);
      if ( !target.has_value() )
      {
        fallback(&ins, "unmappable goto target");
        break;
      }
      emit(OpKind::Branch, Variable::unused(), *target);
      break;
    }

    case m_call:
    {
      const bool noret = const_cast<minsn_t *>(&ins)->is_noret_call(NORET_IGNORE_WAS_NORET_ICALL) != 0;
      if ( ins.l.t == mop_v )
      {
        CallSite site;
        site.target = ins.l.g;
        site.insn = &ins;
        site.mba = mba_;
        site.analyzed = ins.d.t == mop_f && ins.d.f != nullptr;
        call_sites_.push_back(site);

        record_call_site(ins, ins.l.g);

        emit(noret ? OpKind::CallWithNoFallthrough : OpKind::CallWithFallthrough,
             Variable::unused(),
             Variable::machine_address(ins.l.g));
      }
      else
      {
        // A call to a *named* function (IDA prints these as `call $name`) still has a real
        // callee and real arguments; only genuine block/helper calls have neither.
        if ( ins.l.t == mop_h )
          record_call_site(ins, BADADDR);

        // Helper or block call: model as an indirect call so the call's clobbering effect is
        // still visible to the dataflow (it kills every variable, which is conservative).
        size_t id = new_temp();
        Variable phantom = temp_varnode(id, (int)ptr_size_);
        emit(noret ? OpKind::CallWithNoFallthroughIndirect : OpKind::CallWithFallthroughIndirect,
             Variable::unused(),
             phantom);
        note_fallback("call to helper or block");
      }
      break;
    }

    case m_icall:
    {
      const bool noret = const_cast<minsn_t *>(&ins)->is_noret_call(NORET_IGNORE_WAS_NORET_ICALL) != 0;
      record_call_site(ins, BADADDR);
      Variable target = load_value(ins.r);
      if ( !target.is_used() || target.kind == VarKind::Constant )
      {
        fallback(&ins, "indirect call without a target varnode");
        break;
      }
      emit(noret ? OpKind::CallWithNoFallthroughIndirect : OpKind::CallWithFallthroughIndirect,
           Variable::unused(),
           target);
      break;
    }

    case m_ret:
    {
      // Op::Return demands a plain varnode; the return value itself travels through the explicit
      // `mov` into the return register that precedes `ret`.
      Variable retaddr = Variable::varnode(SPACE_UNIQUE, kReturnAddressBase + function_index_, ptr_size_);
      emit(OpKind::Return, Variable::unused(), retaddr);
      break;
    }

    case m_push:
    case m_pop:
    case m_und:
    case m_ext:
      fallback(&ins, "unsupported microcode opcode");
      break;

    case m_f2i:
    case m_f2u:
      lift_binary(ins, OpKind::Float2IntTrunc);
      break;
    case m_i2f:
    case m_u2f:
      lift_binary(ins, OpKind::Int2Float);
      break;
    case m_f2f:
      lift_binary(ins, OpKind::Float2Float);
      break;
    case m_fneg:
    {
      Variable a = load_value(ins.l);
      std::optional<Variable> dest = resolve_destination(ins.d);
      if ( dest.has_value() )
        emit(OpKind::FloatNeg, *dest, a);
      else
        fallback(&ins, "float unary with non-register destination");
      break;
    }
    case m_fadd:
      lift_binary(ins, OpKind::FloatAdd);
      break;
    case m_fsub:
      lift_binary(ins, OpKind::FloatSub);
      break;
    case m_fmul:
      lift_binary(ins, OpKind::FloatMult);
      break;
    case m_fdiv:
      lift_binary(ins, OpKind::FloatDiv);
      break;

    default:
      fallback(&ins, "unmapped microcode opcode");
      break;
  }
}

//--------------------------------------------------------------------------
// Per-function driver
//--------------------------------------------------------------------------

void Lifter::lift_all()
{
  const ea_t entry = mba_->entry_ea;
  std::set<uint64_t> used_keys;

  for ( int bi = 0; bi < mba_->qty; ++bi )
  {
    mblock_t *blk = mba_->get_mblock(bi);
    // A block start is only usable as a program-wide key if it really exists in the IDB: the
    // decompiler creates synthetic blocks (inlined/propagated code) whose starts are fictional
    // addresses that repeat across functions.
    const bool block_start_usable = is_real_ea(blk->start);
    bool first = true;
    for ( minsn_t *mi = blk->head; mi != nullptr; mi = mi->next )
    {
      uint64_t key;
      bool real_key = false;
      if ( first && block_start_usable && used_keys.find(blk->start) == used_keys.end() )
      {
        key = blk->start;
        real_key = true;
      }
      else if ( is_real_ea(mi->ea) && used_keys.find(mi->ea) == used_keys.end()
             && real_to_key_.find(mi->ea) == real_to_key_.end() )
      {
        key = mi->ea;
        real_key = true;
      }
      else
      {
        do
        {
          key = (uint64_t)mba_->alloc_fict_ea(mi->ea);
        } while ( used_keys.find(key) != used_keys.end() );
      }

      if ( mi->ea != BADADDR )
        real_to_key_.insert(std::make_pair(mi->ea, key));
      if ( first && block_start_usable )
        real_to_key_.insert(std::make_pair(blk->start, key));
      used_keys.insert(key);

      cur_key_ = key;
      cur_.clear();
      lift_insn(*mi);
      if ( cur_.empty() )
        emit_nop();

      // Safety net: every instruction handed to the IL must satisfy the ported validator. If a
      // mapping produced something malformed, the whole microinstruction degrades to the universal
      // fallback instead of poisoning the analysis downstream.
      for ( const Instruction &emitted : cur_ )
      {
        std::optional<std::string> err = emitted.try_confirm_valid();
        if ( err.has_value() )
        {
          log_insn("emitted invalid IL", *mi);
          log::debug("IDA frontend: replacing invalid IL with a fallback",
                     { { "func", name_ }, { "err", *err } });
          note_fallback("invalid IL replaced by fallback");
          cur_.clear();
          std::optional<Variable> out = resolve_destination(mi->d);
          if ( out.has_value() )
            emit(OpKind::UnderspecifiedOutputModification, *out);
          else
            emit_nop();
          break;
        }
      }

      Group g;
      g.key = key;
      g.real_key = real_key;
      g.insns = cur_;
      groups_.push_back(std::move(g));
      first = false;
    }

    if ( first && block_start_usable && used_keys.find(blk->start) == used_keys.end() )
    {
      // Empty block: still give its start an address so branches to it resolve.
      used_keys.insert(blk->start);
      real_to_key_.insert(std::make_pair(blk->start, (uint64_t)blk->start));
      cur_key_ = blk->start;
      cur_.clear();
      emit_nop();
      Group g;
      g.key = blk->start;
      g.real_key = true;
      g.insns = cur_;
      groups_.push_back(std::move(g));
    }
  }

  // The function entry must own a group (Program::end_function requires FunctionStart to point at
  // an IL address once the function has instructions).
  bool entry_present = false;
  for ( const Group &g : groups_ )
  {
    if ( g.key == (uint64_t)entry )
    {
      entry_present = true;
      break;
    }
  }
  if ( !entry_present && used_keys.find((uint64_t)entry) == used_keys.end() )
  {
    Group g;
    g.key = entry;
    g.real_key = true;
    cur_key_ = entry;
    cur_.clear();
    emit_nop();
    g.insns = cur_;
    groups_.insert(groups_.begin(), std::move(g));
    real_to_key_.insert(std::make_pair(entry, (uint64_t)entry));
  }
}

void Lifter::collect_variables(bool variables_only_args)
{
  interface_.params.clear();
  interface_.result.reset();
  // IL variable of each lvar, by index into `mba_->vars`; `nullopt` for lvars this frontend cannot
  // place. Needed to express the function's call interface (parameters and the returned value).
  std::vector<std::optional<Variable>> lvar_vars((size_t)mba_->vars.size());

  for ( int i = 0; i < mba_->vars.size(); ++i )
  {
    const lvar_t &v = mba_->vars[i];
    if ( !v.used() || v.name.empty() )
      continue;
    if ( variables_only_args && !v.is_arg_var() && !v.is_result_var() )
      continue;

    VariableRow row;
    row.func_ea = mba_->entry_ea;
    row.func_name = name_;
    row.lvar_name = v.name.c_str();
    row.width = v.width;
    row.kind = v.is_arg_var() ? "arg" : (v.is_result_var() ? "result" : (v.is_stk_var() ? "stack" : "local"));
    row.ida_type = dstr(&v.tif);
    row.ll = v;  // `lvar_t` derives from `lvar_locator_t`
    row.func_index = function_index_;

    if ( v.is_stk_var() )
    {
      row.il_variable = Variable::varnode(SPACE_STACK, (size_t)v.get_stkoff(), (size_t)v.width);
    }
    else if ( v.is_reg_var() )
    {
      int preg = mreg2reg(v.get_reg1(), v.width);
      if ( preg < 0 )
      {
        note_fallback("lvar in a non-processor register");
        continue;
      }
      row.il_variable = Variable::varnode(SPACE_REGISTER, (size_t)preg, (size_t)v.width);
    }
    else
    {
      note_fallback("lvar with an unsupported location");
      continue;
    }

    lvar_vars[(size_t)i] = row.il_variable;
    rows_.push_back(std::move(row));
  }

  // The call interface: parameter i is `mba_->argidx[i]`, the returned value is `retvaridx`
  // (`-1` when there is none).
  interface_.func = function_index_;
  for ( size_t i = 0; i < (size_t)mba_->argidx.size(); ++i )
  {
    const int vi = mba_->argidx[(int)i];
    interface_.params.push_back(vi >= 0 && (size_t)vi < lvar_vars.size() ? lvar_vars[(size_t)vi]
                                                                         : std::nullopt);
  }
  if ( mba_->retvaridx >= 0 && (size_t)mba_->retvaridx < lvar_vars.size() )
    interface_.result = lvar_vars[(size_t)mba_->retvaridx];
}

void Lifter::record_call_site(const minsn_t &ins, ea_t direct_target)
{
  // The callee: the call info knows it for analysed calls; otherwise it has to come from the
  // target operand. IDA emits a call to a *named* function as a helper call (`call $pass`, the
  // operand is `mop_h` with the function's name), which is the common case in microcode, so the
  // name is resolved back to an address.
  ea_t callee_ea = BADADDR;
  if ( ins.d.t == mop_f && ins.d.f != nullptr && ins.d.f->callee != BADADDR )
    callee_ea = ins.d.f->callee;
  else if ( direct_target != BADADDR )
    callee_ea = direct_target;
  else if ( ins.l.t == mop_h && ins.l.helper != nullptr )
    callee_ea = get_name_ea(BADADDR, ins.l.helper);

  // Without call info there is no argument list and no callee: nothing to bind.
  if ( ins.d.t != mop_f || ins.d.f == nullptr )
    return;
  const mcallinfo_t &ci = *ins.d.f;

  // A call whose target is neither known nor name-resolvable is not recorded at all: it is not a
  // source-level call (an IDA pseudo-helper) and counting it as "unresolved" would only add noise.
  if ( callee_ea == BADADDR && ins.opcode != m_icall )
    return;

  trex::interproc::CallSite site;
  site.caller = function_index_;
  if ( callee_ea != BADADDR )
    site.callee_ea = (uint64_t)callee_ea;

  site.args.reserve((size_t)ci.args.size());
  site.arg_pointees.reserve((size_t)ci.args.size());
  for ( const mcallarg_t &a : ci.args )
  {
    // lvar / register / stack slot argument; `&local` (mop_a) is recorded as the addressed
    // variable, because the parameter then points *at* it rather than holding its value.
    if ( a.t == mop_a && a.a != nullptr )
    {
      site.args.push_back(std::nullopt);
      site.arg_pointees.push_back(dest_varnode(*a.a));
    }
    else
    {
      site.args.push_back(dest_varnode(a));
      site.arg_pointees.push_back(std::nullopt);
    }
  }

  // The returned value lands in the enclosing instruction's destination (a nested call) or in the
  // return register. `forced_dest_` is the temporary this frontend assigned to the nested call, so
  // it is the variable the call's value flows out of.
  if ( forced_dest_.has_value() )
    site.result = forced_dest_;
  else
  {
    for ( const mop_t &r : ci.retregs )
    {
      std::optional<Variable> v = dest_varnode(r);
      if ( v.has_value() )
      {
        site.result = v;
        break;  // two-register returns bind the first one only
      }
    }
  }
  interproc_sites_.push_back(std::move(site));
}

//--------------------------------------------------------------------------
// Program assembly
//--------------------------------------------------------------------------
struct LiftedFunction
{
  func_t *pfn = nullptr;
  ea_t entry_ea = BADADDR;
  std::string name;
  std::vector<Group> groups;
  std::vector<VariableRow> rows;
  std::set<RegKey> regs_used;
  std::vector<CallSite> call_sites;
  /// Call interface and call sites for inter-procedural type propagation.
  trex::interproc::FunctionInterface interface;
  std::vector<trex::interproc::CallSite> interproc_sites;
  mba_t *mba = nullptr;
  int fallback_count = 0;
  std::map<std::string, int> fallback_histogram;
};

std::string function_name_for(ea_t ea)
{
  qstring name;
  if ( get_func_name(&name, ea) > 0 )
    return name.c_str();
  char buf[32];
  qsnprintf(buf, sizeof(buf), "sub_%llX", (unsigned long long)ea);
  return buf;
}

/// `00123456` - the address spelling used in external-variable names (matches the Ghidra .vars
/// exporter, which writes 8 lowercase hex digits).
std::string hex8(ea_t ea)
{
  char buf[32];
  qsnprintf(buf, sizeof(buf), "%08llx", (unsigned long long)ea);
  return buf;
}

std::string to_string_ea(ea_t ea)
{
  char buf[32];
  qsnprintf(buf, sizeof(buf), "%llX", (unsigned long long)ea);
  return buf;
}

size_t pointer_size_for_ida()
{
  return inf_is_64bit() ? 8 : 4;
}

Endian endianness_for_ida()
{
  return inf_is_be() ? Endian::Big : Endian::Little;
}

} // namespace

//--------------------------------------------------------------------------
// Public entry point
//--------------------------------------------------------------------------

IdaLiftResult lift_microcode(const IdaLiftOptions &options)
{
  IdaLiftResult result;
  const size_t ptr_size = pointer_size_for_ida();
  const Endian endian = endianness_for_ida();

  std::vector<func_t *> functions = options.functions;
  std::sort(functions.begin(),
            functions.end(),
            [](func_t *a, func_t *b) { return a->start_ea < b->start_ea; });

  // ---------------------------------------------------------------- phase A
  std::vector<LiftedFunction> lifted;
  lifted.reserve(functions.size());

  for ( func_t *pfn : functions )
  {
    if ( options.progress != nullptr
      && !options.progress(lifted.size(), functions.size(),
                           function_name_for(pfn->start_ea).c_str()) )
    {
      result.cancelled = true;
      result.log_text += "trexida: lift cancelled after " + std::to_string(lifted.size())
                       + " function(s)\n";
      return result;
    }

    hexrays_failure_t hf;
    const auto t_microcode = std::chrono::steady_clock::now();
    mba_t *mba = gen_microcode(mba_ranges_t(pfn), &hf, nullptr, DECOMP_WARNINGS, options.maturity);
    result.microcode_seconds +=
      std::chrono::duration<double>(std::chrono::steady_clock::now() - t_microcode).count();
    if ( mba == nullptr )
    {
      ++result.functions_failed;
      result.log_text += "trexida: could not generate microcode for " + to_string_ea(pfn->start_ea)
                       + ": " + hf.desc().c_str() + "\n";
      log::warn("Could not generate microcode",
                { { "func", to_string_ea(pfn->start_ea) }, { "err", hf.desc().c_str() } });
      continue;
    }

    LiftedFunction lf;
    lf.pfn = pfn;
    lf.entry_ea = pfn->start_ea;
    lf.name = function_name_for(pfn->start_ea);
    lf.mba = mba;

    const auto t_lift = std::chrono::steady_clock::now();
    Lifter lifter(mba, lf.name, lifted.size());
    lifter.lift_all();
    lifter.collect_variables(options.variables_only_args);
    result.lifting_seconds +=
      std::chrono::duration<double>(std::chrono::steady_clock::now() - t_lift).count();

    lf.groups = lifter.groups();
    lf.rows = lifter.rows();
    lf.regs_used = lifter.regs_used();
    lf.call_sites = lifter.call_sites();
    lf.interface = lifter.interface_record();
    lf.interproc_sites = lifter.interproc_sites();
    lf.fallback_count = lifter.fallback_count();
    lf.fallback_histogram = lifter.fallback_histogram();

    result.fallback_instructions += lf.fallback_count;
    for ( const auto &kv : lf.fallback_histogram )
      result.fallback_histogram.push_back(kv);

    ++result.functions_lifted;
    lifted.push_back(std::move(lf));
  }

  // ---------------------------------------------------------------- register universe
  std::set<RegKey> all_regs;
  for ( const LiftedFunction &lf : lifted )
    all_regs.insert(lf.regs_used.begin(), lf.regs_used.end());

  // ---------------------------------------------------------------- clobber sets
  std::map<ea_t, std::set<RegKey>> clobbered;
  for ( const LiftedFunction &lf : lifted )
  {
    for ( const CallSite &cs : lf.call_sites )
    {
      std::set<RegKey> &cl = clobbered[cs.target];
      if ( !cs.analyzed || cs.insn == nullptr || cs.insn->d.t != mop_f || cs.insn->d.f == nullptr )
      {
        cl.insert(all_regs.begin(), all_regs.end());
        continue;
      }
      const mlist_t &spoiled = cs.insn->d.f->spoiled;
      for ( const RegKey &rk : all_regs )
      {
        mreg_t mreg = reg2mreg(rk.first);
        if ( mreg != mr_none && spoiled.has_any(mreg, rk.second) )
          cl.insert(rk);
      }
    }
  }

  auto unaffected_for = [&](ea_t target) {
    std::set<Variable> unaff;
    std::map<ea_t, std::set<RegKey>>::const_iterator it = clobbered.find(target);
    for ( const RegKey &rk : all_regs )
    {
      bool is_clobbered = it != clobbered.end() && it->second.find(rk) != it->second.end();
      if ( !is_clobbered )
        unaff.insert(Variable::varnode(SPACE_REGISTER, (size_t)rk.first, (size_t)rk.second));
    }
    return unaff;
  };

  // ---------------------------------------------------------------- phase B
  std::vector<AddressSpace> spaces = {
    AddressSpace("register", endian, ptr_size),
    AddressSpace("ram", endian, ptr_size),
    AddressSpace("stack", endian, ptr_size),
    AddressSpace("unique", endian, ptr_size),
  };
  std::shared_ptr<Program> program = std::make_shared<Program>(Program::create(spaces));

  // `mba_t::alloc_fict_ea()` only guarantees uniqueness within one function's microcode, so a
  // synthetic key may repeat across functions. Real machine addresses are left alone (branch
  // targets resolve through them).
  std::set<uint64_t> program_keys;
  size_t next_synthetic = 0;
  const uint64_t kSyntheticBase = (uint64_t)1 << 56;

  for ( LiftedFunction &lf : lifted )
  {
    std::set<Variable> unaff = unaffected_for(lf.entry_ea);
    program->begin_function(lf.name,
                            std::vector<Variable>(unaff.begin(), unaff.end()),
                            (uint64_t)lf.entry_ea);
    const size_t fn_start_il_pc = program->functions.back().entry.second;
    const size_t first_il_pc = program->instructions.size();
    size_t added_groups = 0;

    for ( Group &g : lf.groups )
    {
      if ( program_keys.find(g.key) != program_keys.end() )
      {
        if ( g.real_key )
        {
          // Two IDB functions overlap (chunks, outlined/inlined copies): the IL is per-address,
          // so the first function owns the address and this duplicate is dropped. The data-flow
          // analysis ignores cross-function CFG edges, so the remaining IL stays consistent.
          log::trace("IDA frontend: dropping a group whose machine address another function owns",
                     { { "func", lf.name }, { "addr", g.key } });
          continue;
        }
        uint64_t replacement = kSyntheticBase + next_synthetic++;
        while ( program_keys.find(replacement) != program_keys.end() )
          replacement = kSyntheticBase + next_synthetic++;
        log::trace("IDA frontend: re-uniquifying a synthetic machine address",
                   { { "func", lf.name }, { "old", g.key }, { "new", replacement } });
        for ( Instruction &ins : g.insns )
          ins.address = replacement;
        g.key = replacement;
      }
      program_keys.insert(g.key);
      program->add_one_machine_instruction(std::move(g.insns));
      ++added_groups;
    }

    // If this function's entry group was dropped, point FunctionStart at its first surviving
    // instruction so `end_function`'s invariant still holds.
    if ( added_groups != 0
      && program->instructions[fn_start_il_pc].inputs[0].kind != VarKind::ILAddress )
    {
      program->instructions[fn_start_il_pc].inputs[0] = Variable::iladdress(first_il_pc);
    }

    program->end_function();
  }

  // External callees: register the ones IDA knows about so `unaffected` lookups stay precise.
  if ( options.include_external_callees )
  {
    std::set<ea_t> lifted_entries;
    for ( const LiftedFunction &lf : lifted )
      lifted_entries.insert(lf.entry_ea);

    std::set<ea_t> targets;
    for ( const LiftedFunction &lf : lifted )
    {
      for ( const CallSite &cs : lf.call_sites )
      {
        if ( cs.target != BADADDR && lifted_entries.find(cs.target) == lifted_entries.end() )
          targets.insert(cs.target);
      }
    }

    for ( ea_t target : targets )
    {
      if ( get_func(target) == nullptr && clobbered.find(target) == clobbered.end() )
        continue; // unknown address: rely on the caller's calling convention fallback
      std::set<Variable> unaff = unaffected_for(target);
      std::vector<Variable> unaff_vec(unaff.begin(), unaff.end());
      program->begin_function(function_name_for(target), unaff_vec, (uint64_t)target);
      program->end_function();
    }
  }

  // ---------------------------------------------------------------- variables + report
  for ( LiftedFunction &lf : lifted )
  {
    result.interfaces.push_back(lf.interface);
    result.calls.insert(result.calls.end(), lf.interproc_sites.begin(), lf.interproc_sites.end());
    for ( VariableRow &row : lf.rows )
    {
      std::string key = row.lvar_name + "@" + row.func_name + "@" + hex8(row.func_ea);
      ExternalVariable ext(key);
      std::map<ExternalVariable, std::pair<size_t, std::vector<Variable>>>::iterator it
        = result.variables.varmap.find(ext);
      if ( it == result.variables.varmap.end() )
        result.variables.varmap[ext] = std::make_pair(row.func_index, std::vector<Variable>{ row.il_variable });
      else
        it->second.second.push_back(row.il_variable);
      result.report.push_back(row);
    }
  }

  // `Program::functions` is what the SSA and the analysis number functions by; the machine entry
  // address is `FunctionInfo::entry.first`. Includes the external-callee stubs added above, so a
  // call site into a known-but-unlifted callee still resolves to a function index.
  // ---------------------------------------------------------------- function index table
  // `Program::functions` is what the SSA and the analysis number functions by; the machine entry
  // address is `FunctionInfo::entry.first`. Includes the external-callee stubs added above, so a
  // call site into a known-but-unlifted callee still resolves to a function index.
  for ( size_t i = 0; i < program->functions.size(); ++i )
    result.function_index[(ea_t)program->functions[i].entry.first] = i;


  // Never emit a stack-relative external variable from this frontend, so the stack pointer entry
  // exists only to satisfy the structure: point it at an id the lifter can never allocate.
  result.variables.stack_pointer
    = std::make_pair(std::string("$TREX_NO_STACK_POINTER"),
                     Variable::varnode(SPACE_UNIQUE, kPseudoRegBase - 1, ptr_size));

  // The mbases are no longer needed: call sites have been consumed.
  for ( LiftedFunction &lf : lifted )
  {
    delete lf.mba;
    lf.mba = nullptr;
  }

  result.program = program;
  return result;
}

} // namespace trex::ida
