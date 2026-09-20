// Definitions for `ProgPoint::debug_string` and `ProgramSummary::compute_from`.
// The worklist algorithm itself is inlined in `DataFlow::analyze<T>` (header) because it
// is templated on the concrete `T` element type.

#include <trex/dataflow.hpp>

#include <cstdio>
#include <optional>

#include <trex/log.hpp>

namespace trex {

std::string ProgPoint::debug_string() const
{
  switch ( kind )
  {
    case Kind::Insn:
    {
      char buf[32];
      std::snprintf(buf, sizeof(buf), "Insn(%zu)", il_pc);
      return buf;
    }
  }
  return "<ProgPoint?>";
}

namespace {

// Helper mirroring the upstream `no_overlaps_amongst_functions` closure.
bool no_overlaps_amongst_functions(const Program &program)
{
  std::vector<bool> seen(program.instructions.size(), false);
  for ( const FunctionInfo &fi : program.functions )
  {
    for ( size_t bb : fi.basic_blocks )
    {
      for ( size_t ins : program.basic_blocks[bb] )
      {
        if ( seen[ins] )
          return false;
        seen[ins] = true;
      }
    }
  }
  return true;
}

} // namespace

std::shared_ptr<const ProgramSummary> ProgramSummary::compute_from(
    std::shared_ptr<const Program> program)
{
  const size_t l = program->instructions.size();

  auto r = std::make_shared<ProgramSummary>();
  r->program = program;
  r->predecessors.assign(l, unordered::UnorderedSet<ProgPoint>{});
  r->successors.assign(l, unordered::UnorderedSet<ProgPoint>{});
  r->fn_of_ilpc.assign(l, 0);
  r->start_of_fn.assign(program->functions.size(), 0);
  r->end_of_fn.assign(program->functions.size(), 0);
  r->outputs.assign(l, std::vector<std::optional<ASLocation>>{});
  r->inputs.assign(l, std::vector<std::optional<ASLocation>>{});
  r->all_variables_of_fn.assign(program->functions.size(), unordered::UnorderedSet<ASLocation>{});

  TREX_CHECK(no_overlaps_amongst_functions(*program),
             "As a whole, data flow analysis and anything that uses it makes assumptions "
             "that functions do not share code. If this assumption is ever broken, then "
             "a non-trivial part of the analyses might need updates.");

  // First pass: assign each IL PC to its function, plus start/end sentinels.
  {
    std::vector<std::optional<size_t>> fnmap(program->instructions.size());
    std::vector<std::optional<size_t>> fnend(program->functions.size());
    std::vector<std::optional<size_t>> fnstart(program->functions.size());
    for ( size_t func_id = 0; func_id < program->functions.size(); ++func_id )
    {
      const FunctionInfo &fi = program->functions[func_id];
      for ( size_t bb : fi.basic_blocks )
      {
        for ( size_t ins : program->basic_blocks[bb] )
        {
          TREX_CHECK(!fnmap[ins].has_value(),
                     "ProgramSummary::compute_from: instruction appears in multiple functions");
          fnmap[ins] = func_id;
          const Instruction &i = program->instructions[ins];
          if ( i.op.kind == OpKind::FunctionStart )
          {
            TREX_CHECK(!fnstart[func_id].has_value(),
                       "ProgramSummary::compute_from: FunctionStart appears twice in one function");
            fnstart[func_id] = ins;
          }
          else if ( i.op.kind == OpKind::FunctionEnd )
          {
            TREX_CHECK(!fnend[func_id].has_value(),
                       "ProgramSummary::compute_from: FunctionEnd appears twice in one function");
            fnend[func_id] = ins;
          }
        }
      }
    }

    // Fill fn_of_ilpc (must succeed for every IL PC).
    for ( size_t i = 0; i < program->instructions.size(); ++i )
    {
      std::optional<size_t> v = fnmap[i];
      TREX_CHECK(v.has_value(),
                 "Instruction %zu: `%s` found to have no function",
                 i,
                 program->instructions[i].debug_string().c_str());
      r->fn_of_ilpc[i] = *v;
    }
    // start/end must succeed for every function.
    for ( size_t f = 0; f < program->functions.size(); ++f )
    {
      TREX_CHECK(fnstart[f].has_value(),
                 "ProgramSummary::compute_from: function %zu has no FunctionStart", f);
      TREX_CHECK(fnend[f].has_value(),
                 "ProgramSummary::compute_from: function %zu has no FunctionEnd", f);
      r->start_of_fn[f] = *fnstart[f];
      r->end_of_fn[f] = *fnend[f];
    }
  }

  // Second pass: predecessors / successors / per-instruction inputs / outputs.
  for ( size_t i = 0; i < program->instructions.size(); ++i )
  {
    const std::vector<size_t> succs = program->get_successor_instruction_addresses_for(i);
    if ( !succs.empty() )
    {
      for ( size_t j : succs )
      {
        if ( r->fn_of_ilpc[j] == r->fn_of_ilpc[i] )
        {
          r->successors[i].insert(ProgPoint::insn(j));
          r->predecessors[j].insert(ProgPoint::insn(i));
        }
        else
        {
          // Cross-function branch is logged and ignored (upstream `debug!`).
          log::debug("Found branch across functions, ignoring in success/predecessor calculation",
                     { { "fn_of_ilpc[j]", program->functions[r->fn_of_ilpc[j]].name },
                       { "j", (size_t)j },
                       { "fn_of_ilpc[i]", program->functions[r->fn_of_ilpc[i]].name },
                       { "i", (size_t)i } });
        }
      }
    }
    else
    {
      const size_t fnend = r->end_of_fn[r->fn_of_ilpc[i]];
      r->successors[i].insert(ProgPoint::insn(fnend));
      r->predecessors[fnend].insert(ProgPoint::insn(i));
    }

    // Per-instruction outputs / inputs.
    r->outputs[i].clear();
    if ( program->instructions[i].output.is_used() )
    {
      r->outputs[i].push_back(program->instructions[i].output.try_to_aslocation());
    }
    r->inputs[i].clear();
    for ( const Variable &inp : program->instructions[i].inputs )
    {
      if ( inp.is_used() )
        r->inputs[i].push_back(inp.try_to_aslocation());
    }

    // All variables of the function (drives init_func_start for reaching definitions).
    for ( const std::optional<ASLocation> &v : r->outputs[i] )
    {
      if ( v.has_value() )
        r->all_variables_of_fn[r->fn_of_ilpc[i]].insert(*v);
    }

    for ( const std::optional<ASLocation> &v : r->inputs[i] )
    {
      if ( v.has_value() )
        r->all_variables_of_fn[r->fn_of_ilpc[i]].insert(*v);
    }
  }

  return r;
}

} // namespace trex