// Definitions for `ReachingDefinitionsElement` (port of `reaching_definitions.rs`).

#include <trex/reaching_definitions.hpp>

#include <memory>

#include <trex/error.hpp>
#include <trex/log.hpp>

namespace trex {

std::shared_ptr<unordered::UnorderedSet<ProgPoint>>
ReachingDefinitionsElement::singleton_ppset(size_t il_pc)
{
  auto s = std::make_shared<unordered::UnorderedSet<ProgPoint>>();
  s->insert(ProgPoint::insn(il_pc));
  return s;
}

std::unique_ptr<DataFlowElement> ReachingDefinitionsElement::make_init() const
{
  return std::make_unique<ReachingDefinitionsElement>(); // empty defs map
}

void ReachingDefinitionsElement::join_from(const DataFlowElement &other)
{
  const auto &o = static_cast<const ReachingDefinitionsElement &>(other);
  for ( const auto &kv : o.defs )
  {
    const ASLocation &loc = kv.first;
    const auto &other_set = kv.second;
    auto it = defs.find(loc);
    if ( it == defs.end() )
    {
      defs.emplace(loc, other_set);
    }
    else
    {
      // Union: clone other_set and add everything from it (and from it->second).
      auto merged = std::make_shared<unordered::UnorderedSet<ProgPoint>>(*other_set);
      for ( const ProgPoint &pp : it->second->iter() )
        merged->insert(pp);
      it->second = std::move(merged);
    }
  }
}

std::unique_ptr<DataFlowElement> ReachingDefinitionsElement::make_init_func_start(
    const ProgramSummary &summary, size_t fn_start) const
{
  const size_t func_id = summary.fn_of_ilpc[fn_start];
  auto out = std::make_unique<ReachingDefinitionsElement>();
  for ( const ASLocation &v : summary.all_variables_of_fn[func_id].iter() )
  {
    out->defs.emplace(v, singleton_ppset(fn_start));
  }
  return out;
}

std::unique_ptr<DataFlowElement> ReachingDefinitionsElement::make_transfer_function(
    size_t il_pc, const ProgramSummary &summary) const
{
  const Instruction &ins = summary.program->instructions[il_pc];
  TREX_CHECK(summary.outputs[il_pc].size() <= 1,
             "Currently, the reaching-definitions analysis assumes that each "
             "instruction has at max one output. For some reason, this is not true: "
             "[...]. Either that must be fixed, or the whole reaching-definitions "
             "analysis needs to be re-checked to find all required changes");

  // OUT[n] = GEN[n] Union (IN[n] -KILL[n]).
  auto ret = std::make_unique<ReachingDefinitionsElement>(*this);

  // KILL side: branch on the call shape.
  switch ( ins.op.kind )
  {
    case OpKind::CallWithFallthroughIndirect:
    {
      // Can't be sure, just kill everything.
      for ( auto &kv : ret->defs )
      {
        kv.second = singleton_ppset(il_pc);
      }
      break;
    }
    case OpKind::CallWithFallthrough:
    {
      // Look up the callee, and kill everything not in the callee's unaffected list.
      std::map<ASLocation, bool> affected;
      for ( const auto &kv : ret->defs )
        affected[kv.first] = true;

      const Variable &target = ins.inputs[0];
      for ( const Variable &v :
            summary.program->get_unaffected_variables_for_call_to(target, il_pc) )
      {
        auto opt_loc = v.try_to_aslocation();
        if ( opt_loc.has_value() )
          affected.erase(*opt_loc);
      }

      for ( auto &kv : ret->defs )
      {
        if ( affected.find(kv.first) != affected.end() )
          kv.second = singleton_ppset(il_pc);
      }
      break;
    }
    case OpKind::CallWithNoFallthrough:
    case OpKind::CallWithNoFallthroughIndirect:
    {
      // Nothing to do for no-fallthrough calls.
      break;
    }
    default:
    {
      // Not a call, do nothing.
      break;
    }
  }

  // GEN side: every output of this instruction is now defined by `il_pc`.
  for ( const auto &d : summary.outputs[il_pc] )
  {
    if ( !d.has_value() )
      continue;
    ret->defs[*d] = singleton_ppset(il_pc);
  }

  return ret;
}

std::unique_ptr<DataFlowElement> ReachingDefinitionsElement::clone() const
{
  return std::make_unique<ReachingDefinitionsElement>(*this);
}

bool ReachingDefinitionsElement::equals(const DataFlowElement &other) const
{
  const auto &o = static_cast<const ReachingDefinitionsElement &>(other);
  return *this == o;
}

} // namespace trex