// Definitions for `SSA`, `ssa::Variable`, `ssa::SSAVariable`, `ssa::SSAVarDefinition`,
// and `format_debug_program`. Port of `third_party/trex/trex/src/ssa.rs` (946 lines).

#include <trex/ssa.hpp>

#include <cstddef>
#include <cstdio>
#include <deque>
#include <set>
#include <unordered_set>

#include <trex/containers.hpp>
#include <trex/error.hpp>
#include <trex/log.hpp>
#include <trex/reaching_definitions.hpp>
namespace trex {
namespace ssa {

// ---------------------------------------------------------------------------
// SSAVariable

std::string SSAVariable::debug_string() const
{
  char buf[32];
  std::snprintf(buf, sizeof(buf), "v%zu", idx);
  return buf;
}

std::string SSAVariable::to_string() const { return debug_string(); }

// ---------------------------------------------------------------------------
// Variable (SSA-side) debug printing

namespace {
// Reusable shared empty `std::unordered_set<ProgPoint>` for `ValueIrrelevantConstant`
// debug text, etc. (Currently unused; kept for symmetry with future needs.)
} // namespace

std::string Variable::debug_string() const
{
  switch ( kind )
  {
    case Kind::Variable:
    {
      if ( var.idx == 0 )
        return "<uninit SSA variable>";
      return var.debug_string();
    }
    case Kind::ConstantValue:
    {
      char buf[96];
      const size_t il_pc =
          (progpoint.kind == ProgPoint::Kind::Insn) ? progpoint.il_pc : 0;
      std::snprintf(buf, sizeof(buf),
                    "const(v=%#llx, prog_point=Insn(%zu), posn=%zu)",
                    (unsigned long long)value, il_pc, input_posn_in_il_insn);
      return buf;
    }
    case Kind::ValueIrrelevantConstant:
    {
      return "ValIrrelConst";
    }
  }
  return "<ssa::Variable?>";
}

Variable Variable::normalize_program_point_for_const(const Program &program) const
{
  if ( kind == Kind::ConstantValue && progpoint.kind == ProgPoint::Kind::Insn )
  {
    Variable v;
    v.kind = Kind::ConstantValue;
    v.progpoint = ProgPoint::insn(program.function_start_il_ip_for_il_ip(progpoint.il_pc));
    v.input_posn_in_il_insn = (size_t)-1;
    v.value = value;
    return v;
  }
  return *this;
}

// ---------------------------------------------------------------------------
// SSAVarDefinition

std::string SSAVarDefinition::debug_string() const
{
  switch ( kind )
  {
    case Kind::PhiNode:
    {
      std::string s = "PhiNode([";
      bool first = true;
      for ( const SSAVariable &v : phi.iter() )
      {
        if ( !first )
          s += ", ";
        first = false;
        s += v.debug_string();
      }
      s += "])";
      return s;
    }
    case Kind::ILInstruction:
    {
      char buf[128];
      std::snprintf(buf, sizeof(buf),
                    "ILInstruction(ilpc=%zu, asloc=(as=%zu, off=%#llx))",
                    il_pc, asloc.address_space_idx, (unsigned long long)asloc.offset);
      return buf;
    }
    case Kind::ValueAtFunctionStart:
    {
      char buf[128];
      std::snprintf(buf, sizeof(buf),
                    "ValueAtFunctionStart(ilpc=%zu, asloc=(as=%zu, off=%#llx))",
                    il_pc, asloc.address_space_idx, (unsigned long long)asloc.offset);
      return buf;
    }
  }
  return "<SSAVarDefinition?>";
}

bool operator<(const SSAVarDefinition &a, const SSAVarDefinition &b)
{
  // Discriminant first (PhiNode=0 < ILInstruction=1 < ValueAtFunctionStart=2).
  if ( a.kind != b.kind )
    return (uint8_t)a.kind < (uint8_t)b.kind;
  switch ( a.kind )
  {
    case SSAVarDefinition::Kind::PhiNode:
    {
      if ( a.phi.len() != b.phi.len() )
        return a.phi.len() < b.phi.len();
      // BTree-ordered element set comparison (upstream uses BTreeSet<SSAVariable>).
      std::set<SSAVariable> sa, sb;
      for ( const auto &v : a.phi.iter() )
        sa.insert(v);
      for ( const auto &v : b.phi.iter() )
        sb.insert(v);
      return sa < sb;
    }
    case SSAVarDefinition::Kind::ILInstruction:
    {
      if ( a.il_pc != b.il_pc )
        return a.il_pc < b.il_pc;
      return a.asloc < b.asloc;
    }
    case SSAVarDefinition::Kind::ValueAtFunctionStart:
    {
      if ( a.il_pc != b.il_pc )
        return a.il_pc < b.il_pc;
      return a.asloc < b.asloc;
    }
  }
  return false; // unreachable
}

// ---------------------------------------------------------------------------
// SSA::compute_from

SSA SSA::compute_from(std::shared_ptr<const Program> program)
{
  const std::shared_ptr<const ProgramSummary> summary =
      ProgramSummary::compute_from(program);

  // We use a local InsertionOrderedSet-like pattern: a vector for insertion order plus
  // a map for membership. Mirrors `InsertionOrderedSet<SSAVarDefinition>::insert`.
  std::vector<SSAVarDefinition> ssa_vars_storage;
  std::map<SSAVarDefinition, size_t> ssa_vars_revmap;

  auto ssa_vars_insert = [&](const SSAVarDefinition &d) -> size_t {
    auto it = ssa_vars_revmap.find(d);
    if ( it != ssa_vars_revmap.end() )
      return it->second;
    const size_t idx = ssa_vars_storage.size();
    ssa_vars_storage.push_back(d);
    ssa_vars_revmap.emplace(d, idx);
    return idx;
  };

  std::vector<std::vector<Variable>> ins_inputs(program->instructions.size());
  std::vector<std::optional<Variable>> ins_output(program->instructions.size());

  for ( size_t func_id = 0; func_id < program->functions.size(); ++func_id )
  {
    const FunctionInfo &fi = program->functions[func_id];
    log::debug("Computing SSA IR for function",
               { { "func_id", (size_t)func_id }, { "func_name", fi.name } });

    const DataFlow reaching =
        DataFlow::analyze<ReachingDefinitionsElement>(summary, func_id);

    // Collect all IL PCs in the function (in BB-order, as upstream does).
    std::vector<size_t> func_il_addrs;
    for ( size_t bb : fi.basic_blocks )
    {
      for ( size_t ins : program->basic_blocks[bb] )
        func_il_addrs.push_back(ins);
    }

    for ( size_t il_pc : func_il_addrs )
    {
      // 1. Inputs.
      const auto &summary_inputs = summary->inputs[il_pc];
      for ( size_t inpidx = 0; inpidx < summary_inputs.size(); ++inpidx )
      {
        const std::optional<ASLocation> &v_opt = summary_inputs[inpidx];
        if ( v_opt.has_value() )
        {
          const ASLocation &v = *v_opt;
          // Walk reaching-defs for `il_pc` to find the IL PCs defining `v`.
          const DataFlowElement *ins_elt = reaching.ins.get(il_pc)->get();
          TREX_CHECK(ins_elt != nullptr,
                     "SSA::compute_from: no DataFlowElement for il_pc=%zu",
                     il_pc);
          const auto &rde = static_cast<const ReachingDefinitionsElement &>(*ins_elt);
          unordered::UnorderedSet<SSAVariable> phi_set;
          auto def_it = rde.defs.find(v);
          if ( def_it == rde.defs.end() )
          {
            // No reaching definition: the instruction is only reachable through code that the
            // data-flow never visits (dead loops, code after a no-return call, chunks). Upstream
            // cannot hit this because it only ever analyses Ghidra's p-code, where the entry block
            // dominates everything it emits. Treat the location as holding its value at function
            // start, which is exactly what the seeding pass would have produced.
            const size_t fn_start_pc = program->function_start_il_ip_for_il_ip(il_pc);
            log::debug("SSA: no reaching definition; assuming the value at function start",
                       { { "asloc", v.debug_string() },
                         { "ilpc", il_pc },
                         { "func_start", fn_start_pc },
                         { "ins", program->instructions[il_pc].debug_string() } });
            phi_set.insert(
                SSAVariable(ssa_vars_insert(SSAVarDefinition::make_value_at_function_start(fn_start_pc, v))));
            continue;
          }
          for ( const ProgPoint &pp : def_it->second->iter() )
          {
            TREX_CHECK(pp.kind == ProgPoint::Kind::Insn,
                       "SSA::compute_from: unexpected ProgPoint kind in reaching defs");
            const size_t iladdr = pp.il_pc;
            const SSAVarDefinition def =
                ( program->instructions[iladdr].op.kind == OpKind::FunctionStart )
                    ? SSAVarDefinition::make_value_at_function_start(iladdr, v)
                    : SSAVarDefinition::make_il_instruction(iladdr, v);
            phi_set.insert(SSAVariable(ssa_vars_insert(def)));
          }

          // Wrap as a phi-node; collapse single-element phi to the inner var.
          SSAVarDefinition phi_node = SSAVarDefinition::make_phi(phi_set);
          if ( phi_node.phi.len() == 1 )
          {
            SSAVariable inner = *phi_node.phi.iter().begin();
            // `phi_node` is unused (we collapse). Dangle its `phi` set without copying.
            ins_inputs[il_pc].push_back(Variable::variable(SSAVariable(inner.idx)));
          }
          else
          {
            const size_t new_idx = ssa_vars_insert(phi_node);
            ins_inputs[il_pc].push_back(
                Variable::variable(SSAVariable(new_idx)));
          }
        }
        else
        {
          // Upstream translation: handle the case where the IL input is a constant or
          // address (which produces a `None` ASLocation in the summary).
          const ::trex::Variable &il_inp = program->instructions[il_pc].inputs[inpidx];
          Variable v;
          switch ( il_inp.kind )
          {
            case VarKind::Constant:
              v = Variable::constant_value(ProgPoint::insn(il_pc), inpidx, il_inp.value);
              break;
            case VarKind::MachineAddress:
            case VarKind::ILAddress:
            case VarKind::ILOffset:
              v = Variable::value_irrelevant_constant();
              break;
            default:
              TREX_UNREACHABLE("SSA::compute_from: unexpected unused input kind: %s",
                               il_inp.debug_string().c_str());
          }
          ins_inputs[il_pc].push_back(v);
        }
      }

      // 2. Outputs.
      for ( const std::optional<ASLocation> &v_opt : summary->outputs[il_pc] )
      {
        if ( !v_opt.has_value() )
          continue;
        const SSAVarDefinition def =
            SSAVarDefinition::make_il_instruction(il_pc, *v_opt);
        const size_t new_idx = ssa_vars_insert(def);
        Variable v = Variable::variable(SSAVariable(new_idx));
        ins_output[il_pc] = v;
      }
    }
  }

  SSA r;
  r.ssa_vars = std::move(ssa_vars_storage);
  r.ins_inputs = std::move(ins_inputs);
  r.ins_output = std::move(ins_output);
  r.program = std::move(program);

  // SSA debug dump is hooked to the global log level: only emit at Trace.
  if ( log::enabled(log::Level::Trace) )
  {
    log::trace("Computed SSA form", {});
    for ( size_t i = 0; i < r.ssa_vars.size(); ++i )
    {
      log::trace("SSA Variable Definition",
                 { { "definition", r.ssa_vars[i].debug_string() },
                   { "ssa_var", SSAVariable(i).debug_string() } });
    }
    std::unordered_set<size_t> traced_phi_nodes;
    std::string current_func = "<<<undefined>>>";
    for ( size_t pc = 0; pc < r.program->instructions.size(); ++pc )
    {
      const Instruction &ins = r.program->instructions[pc];
      if ( ins.op.kind == OpKind::FunctionStart )
      {
        // Find the function names whose bbs contain `pc`.
        std::string names;
        for ( size_t f = 0; f < r.program->functions.size(); ++f )
        {
          const auto &bb = r.program->functions[f].basic_blocks;
          for ( size_t b : bb )
          {
            const auto &ilist = r.program->basic_blocks[b];
            if ( std::find(ilist.begin(), ilist.end(), pc) != ilist.end() )
            {
              if ( !names.empty() )
                names += ", ";
              names += r.program->functions[f].name;
            }
          }
        }
        current_func = names.empty() ? "<<<undefined>>>" : names;

        std::vector<std::string> new_defs;
        for ( size_t i = 0; i < r.ssa_vars.size(); ++i )
        {
          if ( r.ssa_vars[i].kind == SSAVarDefinition::Kind::ValueAtFunctionStart
               && r.ssa_vars[i].il_pc == pc )
            new_defs.push_back(SSAVariable(i).debug_string());
        }
        log::trace("Function Definition",
                   { { "input_vars", std::string("[") + [&] {
                                          std::string r2;
                                          for ( size_t i = 0; i < new_defs.size(); ++i )
                                          {
                                            if ( i )
                                              r2 += ", ";
                                            r2 += new_defs[i];
                                          }
                                          return r2 + "]";
                                        }() } });
      }

      auto var_with_phi = [&](SSAVariable v) -> std::string {
        if ( traced_phi_nodes.insert(v.idx).second )
        {
          const SSAVarDefinition &d = r.ssa_vars[v.idx];
          if ( d.kind == SSAVarDefinition::Kind::PhiNode )
          {
            for ( const SSAVariable &x : d.phi.iter() )
            {
              TREX_CHECK(r.ssa_vars[x.idx].kind != SSAVarDefinition::Kind::PhiNode,
                         "SSA::dump_to_trace: phi nodes that join phi nodes are not "
                         "supported in the trace dumper");
            }
            std::string s;
            for ( const SSAVariable &x : d.phi.iter() )
            {
              if ( !s.empty() )
                s += ", ";
              s += SSAVariable(x.idx).debug_string();
            }
            log::trace("Phi Node",
                       { { "func", current_func },
                         { "output", SSAVariable(v.idx).debug_string() },
                         { "phi_of", s } });
          }
        }
        return SSAVariable(v.idx).debug_string();
      };

      std::string output_str;
      if ( ins_output[pc].has_value() )
      {
        const Variable &o = *ins_output[pc];
        if ( o.kind == Variable::Kind::Variable )
          output_str = var_with_phi(o.var) + " = ";
        else
          TREX_UNREACHABLE("SSA::dump_to_trace: output should be a Variable");
      }

      auto format_input = [&](size_t i) -> std::string {
        if ( i >= ins_inputs[pc].size() )
          return std::string();
        const Variable &v = ins_inputs[pc][i];
        switch ( v.kind )
        {
          case Variable::Kind::Variable:
            return var_with_phi(v.var);
          case Variable::Kind::ConstantValue:
          {
            char buf[64];
            if ( v.value == 0 )
        std::snprintf(buf, sizeof(buf), "$0x0");
      else
        std::snprintf(buf, sizeof(buf), "$%#llx", (unsigned long long)v.value);
            return buf;
          }
          case Variable::Kind::ValueIrrelevantConstant:
          {
            const ::trex::Variable &il_v = r.program->instructions[pc].inputs[i];
            return il_v.machine_addr_to_il_if_possible(*r.program).debug_string();
          }
        }
        return std::string();
      };
      const std::string input0 = format_input(0);
      const std::string input1 = format_input(1);
      TREX_CHECK(ins_inputs[pc].size() <= 2, "SSA::dump_to_trace: too many inputs");

      char ma_buf[32];
      std::snprintf(ma_buf, sizeof(ma_buf), "%#llx", (unsigned long long)ins.address);

      log::trace("IL Instruction",
                 { { "func", current_func },
                   { "machine_addr", ma_buf },
                   { "pc", (size_t)pc },
                   { "op", ins.op.debug_string() },
                   { "output", output_str },
                   { "input0", input0 },
                   { "input1", input1 } });
    }
  }

  return r;
}

// ---------------------------------------------------------------------------
// SSA iteration helpers

std::vector<std::pair<SSAVariable, const unordered::UnorderedSet<SSAVariable> *>>
SSA::phi_nodes_iter() const
{
  std::vector<std::pair<SSAVariable, const unordered::UnorderedSet<SSAVariable> *>> out;
  for ( size_t i = 0; i < ssa_vars.size(); ++i )
  {
    if ( ssa_vars[i].kind == SSAVarDefinition::Kind::PhiNode )
      out.emplace_back(SSAVariable(i), &ssa_vars[i].phi);
  }
  return out;
}

std::vector<Variable> SSA::get_function_inputs(size_t il_pc) const
{
  TREX_CHECK(program->instructions[il_pc].op.kind == OpKind::FunctionStart,
             "SSA::get_function_inputs: il_pc=%zu is not a FunctionStart",
             il_pc);
  std::vector<Variable> out;
  for ( size_t i = 0; i < ssa_vars.size(); ++i )
  {
    if ( ssa_vars[i].kind == SSAVarDefinition::Kind::ValueAtFunctionStart
         && ssa_vars[i].il_pc == il_pc )
    {
      Variable v = Variable::variable(SSAVariable(i));
      out.push_back(v);
    }
  }
  return out;
}

Variable SSA::get_input_variable(size_t il_pc, size_t i) const { return ins_inputs[il_pc][i]; }

std::optional<Variable> SSA::get_output_impacted_variable(size_t il_pc) const
{
  return ins_output[il_pc];
}

Variable SSA::get_output_variable(size_t il_pc) const
{
  return get_output_impacted_variable(il_pc).value();
}

bool SSA::is_effectively_constant(Variable v) const
{
  std::set<size_t> checked;
  std::vector<size_t> yet_to_check;
  for ( size_t il_pc : get_all_immediately_affecting_instructions(v) )
    yet_to_check.push_back(il_pc);

  while ( !yet_to_check.empty() )
  {
    const size_t il_pc = yet_to_check.back();
    yet_to_check.pop_back();
    if ( !checked.insert(il_pc).second )
    {
      // Already checked, some recursion; cannot be constant.
      return false;
    }
    const OpKind op = program->instructions[il_pc].op.kind;
    if ( op == OpKind::FunctionStart || op == OpKind::CallWithFallthrough
         || op == OpKind::CallWithFallthroughIndirect || op == OpKind::CallWithNoFallthrough
         || op == OpKind::CallWithNoFallthroughIndirect )
    {
      return false;
    }
    for ( size_t i = 0; i < ins_inputs[il_pc].size(); ++i )
    {
      const Variable &inp = ins_inputs[il_pc][i];
      for ( size_t aff : get_all_immediately_affecting_instructions(inp) )
        yet_to_check.push_back(aff);
    }
  }
  return true;
}

std::vector<size_t> SSA::get_all_immediately_affecting_instructions(Variable v) const
{
  std::vector<size_t> out;
  switch ( v.kind )
  {
    case Variable::Kind::ConstantValue:
    case Variable::Kind::ValueIrrelevantConstant:
      break;
    case Variable::Kind::Variable:
    {
      const SSAVarDefinition &d = ssa_vars[v.var.idx];
      switch ( d.kind )
      {
        case SSAVarDefinition::Kind::ILInstruction:
        case SSAVarDefinition::Kind::ValueAtFunctionStart:
          out.push_back(d.il_pc);
          break;
        case SSAVarDefinition::Kind::PhiNode:
        {
          for ( const SSAVariable &inner : d.phi.iter() )
          {
            Variable iv = Variable::variable(SSAVariable(inner.idx));
            for ( size_t aff : get_all_immediately_affecting_instructions(iv) )
              out.push_back(aff);
          }
          break;
        }
      }
      break;
    }
  }
  return out;
}

std::optional<std::vector<Variable>> SSA::get_first_matching_variables_for(
    const ::trex::Variable &il_var, size_t func_id) const
{
  return get_matching_variables_for(il_var, func_id, true);
}

std::optional<std::vector<Variable>> SSA::get_all_matching_variables_for(
    const ::trex::Variable &il_var, size_t func_id) const
{
  return get_matching_variables_for(il_var, func_id, false);
}

std::optional<std::vector<Variable>> SSA::get_matching_variables_for(
    const ::trex::Variable &il_var, size_t func_id, bool first_only) const
{
  std::vector<Variable> result;
  for ( const auto &kv : get_all_normal_vars_of_function(func_id) )
  {
    if ( kv.first == il_var )
      result.push_back(kv.second);
  }
  if ( result.empty() )
    return std::nullopt;
  if ( first_only )
    return std::vector<Variable>{ result.front() };
  return result;
}

std::vector<std::pair<::trex::Variable, Variable>>
SSA::get_all_normal_vars_of_function(size_t func_id) const
{
  const FunctionInfo &fi = program->functions[func_id];

  std::set<size_t> func_il_addrs_set;
  for ( size_t bb : fi.basic_blocks )
  {
    for ( size_t ins : program->basic_blocks[bb] )
      func_il_addrs_set.insert(ins);
  }
  TREX_CHECK(!func_il_addrs_set.empty(),
             "SSA::get_all_normal_vars_of_function: function has no instructions");

  size_t func_start_il_addr = 0;
  for ( size_t il_addr : func_il_addrs_set )
  {
    if ( program->instructions[il_addr].op.kind == OpKind::FunctionStart )
    {
      func_start_il_addr = il_addr;
      break;
    }
  }

  std::vector<std::pair<::trex::Variable, Variable>> result;

  std::set<size_t> remaining = func_il_addrs_set;
  std::deque<size_t> queue;
  queue.push_back(func_start_il_addr);
  while ( !queue.empty() )
  {
    const size_t il_addr = queue.front();
    queue.pop_front();
    if ( remaining.find(il_addr) == remaining.end() )
      continue;
    remaining.erase(il_addr);

    // Inputs first (per upstream ordering comment).
    const Instruction &ins = program->instructions[il_addr];
    for ( size_t i = 0; i < 2; ++i )
    {
      if ( ins.inputs[i].kind != VarKind::Unused )
        result.emplace_back(ins.inputs[i], get_input_variable(il_addr, i));
    }
    if ( auto out_v = get_output_impacted_variable(il_addr); out_v.has_value() )
      result.emplace_back(ins.output, *out_v);

    for ( size_t succ : program->get_successor_instruction_addresses_for(il_addr) )
      queue.push_back(succ);
  }
  return result;
}

bool SSA::is_variable_effectively_equal_to_sp_offset(Variable v, Variable sp,
                                                     int64_t offset) const
{
  // Bounded search; matches upstream's "100 here is an arbitrary upper bound".
  Variable orig_v = v;
  Variable cur_v = v;
  int64_t cur_offset = offset;

  for ( int iter = 0; iter < 100; ++iter )
  {
    if ( cur_offset == 0 && cur_v == sp )
      return true;
    SSAVariable svp{};
    switch ( cur_v.kind )
    {
      case Variable::Kind::ValueIrrelevantConstant:
      case Variable::Kind::ConstantValue:
        return false;
      case Variable::Kind::Variable:
        svp = cur_v.var;
        break;
    }
    const SSAVarDefinition &d = ssa_vars[svp.idx];
    size_t ilpc;
    if ( d.kind == SSAVarDefinition::Kind::PhiNode
         || d.kind == SSAVarDefinition::Kind::ValueAtFunctionStart )
    {
      return false;
    }
    ilpc = d.il_pc;
    const OpKind op = program->instructions[ilpc].op.kind;
    if ( op == OpKind::Copy )
    {
      cur_v = get_input_variable(ilpc, 0);
      continue;
    }
    if ( op != OpKind::IntAdd && op != OpKind::IntSub )
      return false;
    Variable a = get_input_variable(ilpc, 0);
    Variable b = get_input_variable(ilpc, 1);
    if ( a.kind == Variable::Kind::Variable
         && b.kind == Variable::Kind::ConstantValue )
    {
      if ( op == OpKind::IntAdd )
        cur_offset = cur_offset - (int64_t)b.value;
      else
        cur_offset = cur_offset + (int64_t)b.value;
      cur_v = a;
    }
    else if ( a.kind == Variable::Kind::ConstantValue
              && b.kind == Variable::Kind::Variable )
    {
      if ( op == OpKind::IntAdd )
        cur_offset = cur_offset - (int64_t)a.value;
      else
        return false; // IntSub with (constant, var) is not representable.
      cur_v = b;
    }
    else
    {
      return false;
    }
  }
  log::debug("Excessively long chain when trying to check SP+offset",
             { { "orig_v", orig_v.debug_string() },
             { "v", cur_v.debug_string() },
             { "sp", sp.debug_string() } });
  return false;
}

std::vector<Variable> SSA::get_stack_involved_ssa_variables(size_t func_id,
                                                            Variable initial_sp,
                                                            int64_t offset) const
{
  const FunctionInfo &fi = program->functions[func_id];
  std::set<size_t> func_il_addrs;
  for ( size_t bb : fi.basic_blocks )
  {
    for ( size_t ins : program->basic_blocks[bb] )
      func_il_addrs.insert(ins);
  }

  std::vector<Variable> out;
  for ( size_t il_pc : func_il_addrs )
  {
    const OpKind op = program->instructions[il_pc].op.kind;
    Variable v;
    Variable p;
    if ( op == OpKind::Load )
    {
      v = get_output_impacted_variable(il_pc).value();
      p = get_input_variable(il_pc, 0);
    }
    else if ( op == OpKind::Store )
    {
      v = get_input_variable(il_pc, 1);
      p = get_input_variable(il_pc, 0);
    }
    else
    {
      continue;
    }
    if ( is_variable_effectively_equal_to_sp_offset(p, initial_sp, offset) )
      out.push_back(v);
  }
  return out;
}

} // namespace ssa

// ---------------------------------------------------------------------------
// format_debug_program
//
// Minimal textual rendering of `DebugProgram`. The upstream uses `slog` with manual
// `writeln!` calls; we reproduce the body as a single string so callers can render it
// into the IDA Output window, a file, etc. The format is not part of the compared
// output (it is a debugging aid), so we keep it close to upstream but don't reproduce
// every comma-exact formatting detail.

std::string format_debug_program(const ssa::DebugProgram &dp)
{
  const ssa::SSA &this_ = dp.ssa;
  std::string out;
  std::unordered_set<size_t> printed_phi_nodes;

  auto var_with_phi = [&](ssa::SSAVariable v) -> std::string {
    if ( printed_phi_nodes.insert(v.idx).second )
    {
      const ssa::SSAVarDefinition &d = this_.ssa_vars[v.idx];
      if ( d.kind == ssa::SSAVarDefinition::Kind::PhiNode )
      {
        for ( const auto &x : d.phi.iter() )
        {
          TREX_CHECK(this_.ssa_vars[x.idx].kind != ssa::SSAVarDefinition::Kind::PhiNode,
                     "ssa::DebugProgram: phi nodes that join phi nodes are not "
                     "supported in the debug dumper");
        }
        std::string s = "        ...  " + v.debug_string() + " = 𝛟(";
        bool first = true;
        for ( const auto &x : d.phi.iter() )
        {
          if ( !first )
            s += ", ";
          first = false;
          s += ssa::SSAVariable(x.idx).debug_string();
        }
        s += ")\n";
        out += s;
      }
    }
    return v.debug_string();
  };

  out += "DebugProgram(\n\n";
  for ( size_t pc = 0; pc < this_.program->instructions.size(); ++pc )
  {
    if ( dp.highlight_il_addr.has_value() && *dp.highlight_il_addr == pc )
      out += "*******************\n";

    const Instruction &ins = this_.program->instructions[pc];
    if ( ins.op.kind == OpKind::FunctionStart )
    {
      std::string names;
      for ( size_t f = 0; f < this_.program->functions.size(); ++f )
      {
        const auto &bb = this_.program->functions[f].basic_blocks;
        for ( size_t b : bb )
        {
          const auto &ilist = this_.program->basic_blocks[b];
          if ( std::find(ilist.begin(), ilist.end(), pc) != ilist.end() )
          {
            if ( !names.empty() )
              names += ":\n";
            names += this_.program->functions[f].name;
          }
        }
      }
      out += names + ":\n";

      std::vector<std::string> new_defs;
      for ( size_t i = 0; i < this_.ssa_vars.size(); ++i )
      {
        if ( this_.ssa_vars[i].kind == ssa::SSAVarDefinition::Kind::ValueAtFunctionStart
             && this_.ssa_vars[i].il_pc == pc )
          new_defs.push_back(ssa::SSAVariable(i).debug_string());
      }
      if ( !new_defs.empty() )
      {
        out += "    input_vars: ";
        for ( size_t i = 0; i < new_defs.size(); ++i )
        {
          if ( i )
            out += ", ";
          out += new_defs[i];
        }
        out += "\n";
      }
    }

    char ma_buf[32];
    ma_buf[0] = 0;
    if ( dp.show_machine_addr )
      std::snprintf(ma_buf, sizeof(ma_buf), " [%#llx]", (unsigned long long)ins.address);

    std::string output_str;
    auto oit = this_.ins_output[pc];
    if ( oit.has_value() )
    {
      const ssa::Variable &o = *oit;
      if ( o.kind == ssa::Variable::Kind::Variable )
        output_str = var_with_phi(o.var) + " = ";
      else
        TREX_UNREACHABLE("ssa::DebugProgram: output should be a Variable");
    }

    char pcbuf[16];
    std::snprintf(pcbuf, sizeof(pcbuf), "%8zu", pc);
    out += pcbuf;
    out += ma_buf;
    out += ": ";
    out += output_str;

    std::string args;
    for ( size_t i = 0; i < this_.ins_inputs[pc].size(); ++i )
    {
      const ssa::Variable &inp = this_.ins_inputs[pc][i];
      if ( i )
        args += ", ";
      switch ( inp.kind )
      {
        case ssa::Variable::Kind::Variable:
          args += var_with_phi(inp.var);
          break;
        case ssa::Variable::Kind::ConstantValue:
        {
          char buf[64];
          if ( inp.value == 0 )
        std::snprintf(buf, sizeof(buf), "$0x0");
      else
        std::snprintf(buf, sizeof(buf), "$%#llx", (unsigned long long)inp.value);
          args += buf;
          break;
        }
        case ssa::Variable::Kind::ValueIrrelevantConstant:
          args += this_.program->instructions[pc].inputs[i]
                        .machine_addr_to_il_if_possible(*this_.program)
                        .debug_string();
          break;
      }
    }
    char insbuf[16];
    switch ( ins.op.kind )
    {
      case OpKind::Copy:
        out += args;
        out += "\n";
        break;
      case OpKind::Load:
      case OpKind::Store:
      {
        const ::trex::Variable &addr = this_.program->instructions[pc].inputs[0];
        size_t derefval_size = 0;
        if ( addr.kind == VarKind::DerefVarnode )
          derefval_size = addr.derefval_size;
        out += ins.op.name() + std::to_string(derefval_size) + "(" + args + ")\n";
        break;
      }
      case OpKind::FunctionEnd:
        out += "FunctionEnd\n\n";
        break;
      default:
      {
        std::snprintf(insbuf, sizeof(insbuf), "%s", "");
        out += ins.op.debug_string() + "(" + args + ")\n";
        break;
      }
    }
  }
  out += ")\n";
  return out;
}

} // namespace trex