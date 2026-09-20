// Definitions for `GlobalValueNumbering` (port of `global_value_numbering.rs`).
#include <iterator>
#include <map>
#include <set>
#include <utility>
#include <vector>
#include <algorithm>
#include <trex/global_value_numbering.hpp>

#include <trex/containers.hpp>
#include <trex/il.hpp>
#include <trex/ssa.hpp>

namespace trex {

namespace {

// ---------------------------------------------------------------------------
// `Value` — the internal node type for congruence.
//
// Upstream: `enum Value { Var(Variable), Op1(Op, Variable), Op2(Op, Variable, Variable) }`.
// We keep it as a tagged struct so the disjoint-set hash/equality is straightforward.
struct Value
{
  enum class Kind : uint8_t
  {
    Var = 0,
    Op1,
    Op2,
  };

  Kind kind = Kind::Var;
  trex::Op op;
  ssa::Variable v1;
  ssa::Variable v2;

  Value() = default;

  static Value var(ssa::Variable v)
  {
    Value x;
    x.kind = Kind::Var;
    x.v1 = v;
    return x;
  }
  static Value op1(trex::Op o, ssa::Variable v)
  {
    Value x;
    x.kind = Kind::Op1;
    x.op = o;
    x.v1 = v;
    return x;
  }
  static Value op2(trex::Op o, ssa::Variable a, ssa::Variable b)
  {
    Value x;
    x.kind = Kind::Op2;
    x.op = o;
    x.v1 = a;
    x.v2 = b;
    return x;
  }

  friend bool operator==(const Value &a, const Value &b)
  {
    if ( a.kind != b.kind )
      return false;
    switch ( a.kind )
    {
      case Kind::Var:
        return a.v1 == b.v1;
      case Kind::Op1:
        return a.op == b.op && a.v1 == b.v1;
      case Kind::Op2:
        return a.op == b.op && a.v1 == b.v1 && a.v2 == b.v2;
    }
    return false;
  }
  // friend bool operator!=(const Value &a, const Value &b) { return !(a == b); }
  friend bool operator<(const Value &a, const Value &b)
  {
    if ( a.kind != b.kind )
      return (uint8_t)a.kind < (uint8_t)b.kind;
    switch ( a.kind )
    {
      case Kind::Var:
        return a.v1 < b.v1;
      case Kind::Op1:
        if ( a.op != b.op )
          return a.op < b.op;
        return a.v1 < b.v1;
      case Kind::Op2:
        if ( a.op != b.op )
          return a.op < b.op;
        if ( a.v1 != b.v1 )
          return a.v1 < b.v1;
        return a.v2 < b.v2;
    }
    return false;
  }
};

// Disjoint sets of `Value`s with *stable* element indices.
//
// Upstream uses `DisjointSet<Value>`, whose storage is an `InsertionOrderedSet` (a Vec), so an
// element keeps the same index for its whole lifetime. Indexing by position in a *sorted*
// container instead would shift the indices of every later element whenever one is inserted in the
// middle, silently corrupting the parent array (and previously crashed here).
class ValueDisjointSet
{
public:
  ValueDisjointSet() = default;

  /// Get (and if absent, insert) the representative of `v`.
  const Value &representative(const Value &v)
  {
    const std::size_t idx = index_of_or_insert(v);
    return values_[rep(idx)];
  }

  /// Merge the two sets containing `parent` and `child` (the parent's representative wins).
  void merge(const Value &parent, const Value &child)
  {
    const std::size_t parent_idx = index_of_or_insert(parent);
    const std::size_t child_idx = index_of_or_insert(child);
    const std::size_t rparent = rep(parent_idx);
    const std::size_t rchild = rep(child_idx);
    parents_[rchild] = rparent;
  }

  /// Iterate over the disjoint sets, each as a `std::set<const Value *>`.
  ///
  /// Ordering mirrors upstream: the outer map is keyed by the representative's storage position
  /// (upstream keys by `&T`, i.e. by address within a Vec, which is the same order), and each
  /// inner set is in address order.
  std::vector<std::set<const Value *>> disjoint_sets_iter() const
  {
    std::map<std::size_t, std::set<const Value *>> by_rep;
    for ( std::size_t i = 0; i < values_.size(); ++i )
      by_rep[rep(i)].insert(&values_[i]);

    std::vector<std::set<const Value *>> out;
    out.reserve(by_rep.size());
    for ( auto &kv : by_rep )
      out.push_back(std::move(kv.second));
    return out;
  }

private:
  std::size_t index_of_or_insert(const Value &v)
  {
    std::map<Value, std::size_t>::iterator it = index_.find(v);
    if ( it != index_.end() )
      return it->second;
    const std::size_t idx = values_.size();
    values_.push_back(v);
    index_.emplace(v, idx);
    parents_.push_back(idx);
    return idx;
  }

  std::size_t rep(std::size_t x) const
  {
    std::vector<std::size_t> path;
    while ( parents_[x] != x )
    {
      path.push_back(x);
      x = parents_[x];
    }
    for ( std::size_t m : path )
      parents_[m] = x;
    return x;
  }

  std::vector<Value> values_;
  std::map<Value, std::size_t> index_;
  mutable std::vector<std::size_t> parents_;
};

} // namespace

// ---------------------------------------------------------------------------
// OpSummary::of

OpSummary op_summary_of(const trex::Op &op)
{
  using K = OpKind;
  switch ( op.kind )
  {
    case K::Branch:
    case K::CallWithFallthrough:
    case K::CallWithNoFallthrough:
    case K::BranchIndOffset:
    case K::Return:
    case K::CallWithFallthroughIndirect:
    case K::CallWithNoFallthroughIndirect:
    case K::Cbranch:
    case K::Store:
    case K::FunctionStart:
    case K::FunctionEnd:
    case K::Nop:
    case K::UnderspecifiedNoOutput:
    case K::ProcessorException:
      return OpSummary::HasNoOutput;

    case K::UnderspecifiedOutputModification:
      return OpSummary::MustNotMerge;

    case K::Copy:
      return OpSummary::MergeCopy;

    case K::BoolNegate:
    case K::IntOnesComp:
    case K::IntTwosComp:
    case K::Popcount:
      return OpSummary::MergeResultSingleArgument;

    case K::FloatIsNan:
    case K::FloatAdd:
    case K::FloatSub:
    case K::FloatMult:
    case K::FloatDiv:
    case K::Float2Float:
      return OpSummary::MightBeMergedInFutureButDoNotMergeNow;

    case K::Int2Float:
    case K::Float2IntTrunc:
      return OpSummary::MergeResultSingleArgument;

    case K::FloatRound:
    case K::FloatNeg:
    case K::FloatAbs:
    case K::FloatSqrt:
      return OpSummary::MergeResultSingleArgument;

    case K::IntAdd:
    case K::IntMult:
    case K::IntAnd:
    case K::IntOr:
    case K::IntXor:
    case K::BoolAnd:
    case K::BoolOr:
    case K::BoolXor:
    case K::IntEqual:
    case K::IntNotEqual:
    case K::IntCarry:
    case K::IntSCarry:
    case K::FloatEqual:
    case K::FloatNotEqual:
      return OpSummary::MergeResultWithCommutativity;

    case K::IntSub:
    case K::IntUDiv:
    case K::IntURem:
    case K::IntSDiv:
    case K::IntSRem:
    case K::IntSBorrow:
    case K::IntSLess:
    case K::IntLess:
    case K::FloatLess:
    case K::FloatLessEqual:
    case K::IntLeftShift:
    case K::IntURightShift:
    case K::IntSRightShift:
      return OpSummary::MergeResultButNoCommutativity;

    case K::Load:
      return OpSummary::MustNotMerge;

    case K::IntZext:
    case K::IntSext:
    case K::Piece:
    case K::SubPiece:
      return OpSummary::MightBeMergedInFutureButDoNotMergeNow;

    case K::ScalarLowerOp:
    case K::ScalarUpperOp:
    case K::PackedVectorOp:
      return OpSummary::MightBeMergedInFutureButDoNotMergeNow;
  }
  return OpSummary::HasNoOutput;
}

// ---------------------------------------------------------------------------
// GlobalValueNumbering::analyze_from

GlobalValueNumbering GlobalValueNumbering::analyze_from(std::shared_ptr<const ssa::SSA> ssa)
{
  ValueDisjointSet congruent;

  for ( size_t il_pc = 0; il_pc < ssa->program->instructions.size(); ++il_pc )
  {
    const trex::Op &op = ssa->program->instructions[il_pc].op;
    switch ( op_summary_of(op) )
    {
      case OpSummary::HasNoOutput:
      case OpSummary::MustNotMerge:
      case OpSummary::MightBeMergedInFutureButDoNotMergeNow:
        break;
      case OpSummary::MergeCopy:
        congruent.merge(Value::var(ssa->get_output_variable(il_pc)),
                        Value::var(ssa->get_input_variable(il_pc, 0)
                                       .normalize_program_point_for_const(*ssa->program)));
        break;
      case OpSummary::MergeResultSingleArgument:
        congruent.merge(
            Value::var(ssa->get_output_variable(il_pc)),
            Value::op1(op, ssa->get_input_variable(il_pc, 0)
                                .normalize_program_point_for_const(*ssa->program)));
        break;
      case OpSummary::MergeResultButNoCommutativity:
        congruent.merge(
            Value::var(ssa->get_output_variable(il_pc)),
            Value::op2(op,
                        ssa->get_input_variable(il_pc, 0)
                            .normalize_program_point_for_const(*ssa->program),
                        ssa->get_input_variable(il_pc, 1)
                            .normalize_program_point_for_const(*ssa->program)));
        break;
      case OpSummary::MergeResultWithCommutativity:
      {
        const ssa::Variable a =
            ssa->get_input_variable(il_pc, 0).normalize_program_point_for_const(*ssa->program);
        const ssa::Variable b =
            ssa->get_input_variable(il_pc, 1).normalize_program_point_for_const(*ssa->program);
        congruent.merge(
            Value::var(ssa->get_output_variable(il_pc)),
            (a <= b) ? Value::op2(op, a, b) : Value::op2(op, b, a));
        break;
      }
    }
  }

  // Drain the disjoint-set into a representative→set map for storage.
  GlobalValueNumbering r;
  r.ssa = std::move(ssa);
  for ( const auto &grp : congruent.disjoint_sets_iter() )
  {
    unordered::UnorderedSet<ssa::Variable> out;
    for ( const Value *v : grp )
    {
      if ( v->kind == Value::Kind::Var )
        out.insert(v->v1);
    }
    if ( out.len() >= 2 )
      r.congruent.push_back(std::move(out));
  }
  return r;
}

std::vector<unordered::UnorderedSet<ssa::Variable>>
GlobalValueNumbering::congruent_sets_iter() const
{
  // Already stored in upstream's iteration order.
  return congruent;
}

} // namespace trex