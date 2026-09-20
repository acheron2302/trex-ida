// Unit tests for inter-procedural type propagation (src/analysis/interproc.cpp).
//
// The tests build a two-function program from lifted text (the same format the reference frontend
// parses), then drive `trex::interproc::propagate` with hand-written call sites and interfaces: the
// module only needs variable identities, so the IL has to be real enough for the analysis to
// constrain the variables, nothing more.

#include <optional>
#include <string>
#include <vector>

#include <analysis/interproc.hpp>
#include <trex/il.hpp>
#include <trex/lifted_frontend.hpp>
#include <trex/pipeline.hpp>
#include <trex/structural.hpp>

#include "harness.hpp"

namespace {

using trex::Variable;

/// `caller` writes two registers (one from a constant, one by loading through the other) and calls
/// `callee`, which loads through a third register. The three registers therefore start out with
/// different types: an 8-byte integer, a pointer to 4 bytes, and another pointer.
const char *kLifted =
"PROGRAM\n\
name interproc-test\n\
big_endian false\n\
\n\
ADDRESS_SPACES\n\
        0 ram 8\n\
\n\
PCODE_LISTING\n\
        00100000 caller\n\
                Unaffected:\n\
                00100000 (register, 0x80, 8) COPY (const, 0x0, 8)\n\
                00100000 (register, 0x90, 8) LOAD (const, 0x0, 4) , (register, 0x80, 8)\n\
                00100000  ---  CALLWITHFALLTHROUGH (ram, 0x100010, 8)\n\
\n\
        00100010 callee\n\
                Unaffected:\n\
                00100010 (register, 0xb0, 8) LOAD (const, 0x0, 4) , (register, 0x80, 8)\n";

std::shared_ptr<trex::Program> make_program()
{
  return trex::lift_program_from_lifted_text(kLifted);
}

/// The address-space id the lifted text uses for registers.
size_t register_space(const trex::Program &program)
{
  for ( size_t i = 0; i < program.address_spaces.size(); ++i )
  {
    if ( program.address_spaces[i].name == "register" )
      return i;
  }
  return 0;
}

/// The type index of an IL variable in a solved program, or nullopt when it has none.
std::optional<trex::Index> type_of(const trex::StructuralTypes &types, size_t func,
                                   const trex::Variable &var)
{
  if ( types.ssa == nullptr )
    return std::nullopt;
  std::optional<std::vector<trex::ssa::Variable>> matching
    = types.ssa->get_first_matching_variables_for(var, func);
  if ( !matching.has_value() || matching->empty() )
    return std::nullopt;
  return types.get_type_index((*matching)[0]);
}

} // namespace

// Two functions, one call site: the caller's argument and the callee's parameter must end up with
// one type, and they must not have one before the propagation (otherwise the test proves nothing).
TEST(interproc_links_caller_and_callee)
{
  std::shared_ptr<trex::Program> program = make_program();
  trex::StructuralTypes types = trex::infer_structural_types(program);
  const size_t reg = register_space(*program);
  const Variable caller_arg = Variable::varnode(reg, 0x80, 8);
  const Variable callee_param = Variable::varnode(reg, 0xb0, 8);

  std::optional<trex::Index> before_a = type_of(types, 0, caller_arg);
  std::optional<trex::Index> before_b = type_of(types, 1, callee_param);
  CHECK(before_a.has_value());
  CHECK(before_b.has_value());
  CHECK(!types.are_equal_at_indexes(*before_a, *before_b));

  std::vector<trex::interproc::FunctionInterface> interfaces;
  trex::interproc::FunctionInterface callee;
  callee.func = 1;
  callee.params.push_back(callee_param);
  interfaces.push_back(callee);

  std::vector<trex::interproc::CallSite> sites;
  trex::interproc::CallSite site;
  site.caller = 0;
  site.callee_ea = 0x100010;
  site.callee_func = 1;
  site.args.push_back(caller_arg);
  sites.push_back(site);

  trex::StructuralTypes merged = types.deep_clone();
  trex::interproc::Stats stats;
  trex::interproc::propagate(merged, interfaces, sites, /*aggregate_sites=*/false, stats);
  CHECK_EQ(stats.sites, (size_t)1);
  CHECK_EQ(stats.param_binds, (size_t)1);

  std::optional<trex::Index> after_a = type_of(merged, 0, caller_arg);
  std::optional<trex::Index> after_b = type_of(merged, 1, callee_param);
  CHECK(after_a.has_value());
  CHECK(after_b.has_value());
  CHECK(merged.are_equal_at_indexes(*after_a, *after_b));
}

// An empty site list must take exactly the plain pipeline's path: the driver repeats the phase
// order of `run_trex_pipeline`, so this is the guard against the two drifting apart.
TEST(interproc_pipeline_matches_plain_pipeline)
{
  std::shared_ptr<trex::Program> program = make_program();
  std::optional<trex::ILVariableMap> vars = std::nullopt;

  trex::TrexPipelineResult plain = trex::run_trex_pipeline(program, vars);
  trex::interproc::Stats stats;
  trex::interproc::InterprocResult with_pass
    = trex::interproc::run_trex_pipeline_interproc(program, vars, {}, {}, false, stats);

  CHECK(with_pass.propagated);
  CHECK_EQ(plain.structural_text, with_pass.pipeline.structural_text);
  CHECK_EQ(plain.c_like_text, with_pass.pipeline.c_like_text);
  CHECK_EQ(plain.colocation_analysis_ran, with_pass.pipeline.colocation_analysis_ran);
}

// Two call sites of the same callee: the values handed to it at the same argument index share one
// type when sites are aggregated (the paper's "multiple paths through a single void* produce
// precise unions"), and stay apart when the aggregation is off.
TEST(interproc_aggregates_sites)
{
  std::shared_ptr<trex::Program> program = make_program();
  trex::StructuralTypes types = trex::infer_structural_types(program);
  const size_t reg = register_space(*program);
  const Variable first = Variable::varnode(reg, 0x80, 8);
  const Variable second = Variable::varnode(reg, 0x90, 8);

  std::optional<trex::Index> idx_first = type_of(types, 0, first);
  std::optional<trex::Index> idx_second = type_of(types, 0, second);
  CHECK(idx_first.has_value());
  CHECK(idx_second.has_value());

  std::vector<trex::interproc::CallSite> sites;
  for ( const Variable &arg : { first, second } )
  {
    trex::interproc::CallSite site;
    site.caller = 0;
    site.callee_ea = 0x100010;
    site.args.push_back(arg);
    sites.push_back(site);
  }

  {
    trex::StructuralTypes merged = types.deep_clone();
    trex::interproc::Stats stats;
    trex::interproc::propagate(merged, {}, sites, /*aggregate_sites=*/true, stats);
    CHECK_EQ(stats.site_groups, (size_t)1);
    std::optional<trex::Index> a = type_of(merged, 0, first);
    std::optional<trex::Index> b = type_of(merged, 0, second);
    CHECK(a.has_value());
    CHECK(b.has_value());
    CHECK(merged.are_equal_at_indexes(*a, *b));
  }

  {
    trex::StructuralTypes merged = types.deep_clone();
    trex::interproc::Stats stats;
    trex::interproc::propagate(merged, {}, sites, /*aggregate_sites=*/false, stats);
    CHECK_EQ(stats.site_groups, (size_t)0);
    std::optional<trex::Index> a = type_of(merged, 0, first);
    std::optional<trex::Index> b = type_of(merged, 0, second);
    CHECK(a.has_value());
    CHECK(b.has_value());
    CHECK(!merged.are_equal_at_indexes(*a, *b));
  }
}

// An unresolved indirect call must not bind anything and must be counted.
TEST(interproc_skips_unresolved_indirect_calls)
{
  std::shared_ptr<trex::Program> program = make_program();
  trex::StructuralTypes types = trex::infer_structural_types(program);
  const size_t reg = register_space(*program);
  const Variable arg = Variable::varnode(reg, 0x80, 8);

  trex::interproc::CallSite site;
  site.caller = 0;
  site.callee_ea = trex::interproc::kNoAddress;
  site.args.push_back(arg);

  trex::StructuralTypes merged = types.deep_clone();
  trex::interproc::Stats stats;
  trex::interproc::propagate(merged, {}, { site }, true, stats);
  CHECK_EQ(stats.sites, (size_t)0);
  CHECK_EQ(stats.unresolved, (size_t)1);
  CHECK_EQ(stats.param_binds, (size_t)0);
  CHECK_EQ(stats.result_binds, (size_t)0);
  CHECK_EQ(stats.site_groups, (size_t)0);
}
