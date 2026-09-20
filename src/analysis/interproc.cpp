// Inter-procedural type propagation across call edges - see analysis/interproc.hpp.
//
// `run_trex_pipeline_interproc` mirrors the phase order of `src/trex/pipeline.cpp` verbatim, with
// the call-edge joins inserted between structural inference and the aggregate analysis. Because the
// join happens in the program-wide type container and every later phase reads that container, no
// re-analysis round is needed: a merged pointee already carries the colocated fields observed on
// both sides of the call, which is exactly what the aggregate analysis needs to see.

#include <analysis/interproc.hpp>

#include <algorithm>
#include <map>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include <trex/aggregate_types.hpp>
#include <trex/c_type_printer.hpp>
#include <trex/inference_config.hpp>
#include <trex/serialize_structural.hpp>
#include <trex/starts_at_analysis.hpp>
#include <trex/type_rounding.hpp>

namespace trex::interproc {

namespace {

using ::trex::Index;
using ::trex::StructuralTypes;

/// The SSA variable of the IL variable `var` inside function `func`, if the analysis has one.
std::optional<trex::ssa::Variable> ssa_var_of(const StructuralTypes &types, size_t func,
                                              const trex::Variable &var)
{
  if ( types.ssa == nullptr )
    return std::nullopt;
  std::optional<std::vector<trex::ssa::Variable>> matching
    = types.ssa->get_first_matching_variables_for(var, func);
  if ( !matching.has_value() )
    return std::nullopt;
  for ( const trex::ssa::Variable &sv : *matching )
  {
    if ( types.get_type_index(sv).has_value() )
      return sv;
  }
  return std::nullopt;
}

/// The type index of the IL variable `var` inside function `func`, if the analysis gave it one.
std::optional<Index> index_of(const StructuralTypes &types, size_t func,
                              const trex::Variable &var, Stats &stats)
{
  std::optional<trex::ssa::Variable> sv = ssa_var_of(types, func, var);
  if ( sv.has_value() )
    return types.get_type_index(*sv);
  ++stats.missing_values;
  return std::nullopt;
}

/// Join the types of two caller/callee values. Returns false when either side has no type yet.
bool bind_values(StructuralTypes &types, size_t a_func, const std::optional<trex::Variable> &a,
                 size_t b_func, const std::optional<trex::Variable> &b, Stats &stats)
{
  if ( !a.has_value() || !b.has_value() )
    return false;
  std::optional<Index> ia = index_of(types, a_func, *a, stats);
  std::optional<Index> ib = index_of(types, b_func, *b, stats);
  if ( !ia.has_value() || !ib.has_value() )
    return false;
  types.types.join(*ia, *ib);
  return true;
}

/// `param` is a pointer that points at `pointee` (an argument was passed by address). Expressed as
/// the analysis' own dereference constraint, which merges the pointee of the parameter's type with
/// the addressed variable's type and marks the parameter as a pointer.
bool bind_pointee(StructuralTypes &types, size_t callee_func, const std::optional<trex::Variable> &param,
                  size_t caller_func, const std::optional<trex::Variable> &pointee, Stats &stats)
{
  if ( !param.has_value() || !pointee.has_value() || types.ssa == nullptr )
    return false;
  std::optional<trex::ssa::Variable> p = ssa_var_of(types, callee_func, *param);
  std::optional<trex::ssa::Variable> q = ssa_var_of(types, caller_func, *pointee);
  if ( !p.has_value() || !q.has_value() )
  {
    ++stats.missing_values;
    return false;
  }
  const size_t pointer_size = types.ssa->program->pointer_size;
  const std::optional<size_t> pointee_size = pointee->try_size();
  if ( pointer_size == 0 || !pointee_size.has_value() || *pointee_size == 0 )
  {
    ++stats.missing_values;
    return false;
  }
  types.capability_deref(*p, pointer_size, *q, *pointee_size);
  return true;
}

} // namespace

void propagate(StructuralTypes &types,
               const std::vector<FunctionInterface> &interfaces,
               const std::vector<CallSite> &sites,
               bool aggregate_sites,
               Stats &stats)
{
  std::map<size_t, const FunctionInterface *> iface_by_func;
  for ( const FunctionInterface &fi : interfaces )
    iface_by_func[fi.func] = &fi;

  // ---------------------------------------------------------------- argument/parameter/return edges
  for ( const CallSite &s : sites )
  {
    // Unresolved indirect call: nothing to bind against. This is the "controllable
    // non-conservativeness" the paper mentions - the caller keeps its own type instead of being
    // merged with every possible callee.
    if ( s.callee_ea == kNoAddress )
    {
      ++stats.unresolved;
      continue;
    }
    ++stats.sites;

    if ( !s.callee_func.has_value() )
      continue;
    std::map<size_t, const FunctionInterface *>::const_iterator it
      = iface_by_func.find(*s.callee_func);
    if ( it == iface_by_func.end() )
      continue;
    const FunctionInterface &fi = *it->second;

    const size_t n = std::min(s.args.size(), fi.params.size());
    for ( size_t i = 0; i < n; ++i )
    {
      // A plain value argument joins with the parameter; an argument passed by address makes the
      // parameter a pointer to the addressed variable instead (see `CallSite::arg_pointees`).
      if ( bind_values(types, s.caller, s.args[i], *s.callee_func, fi.params[i], stats) )
        ++stats.param_binds;
      else if ( i < s.arg_pointees.size()
             && bind_pointee(types, *s.callee_func, fi.params[i], s.caller, s.arg_pointees[i], stats) )
        ++stats.param_binds;
    }
    if ( bind_values(types, s.caller, s.result, *s.callee_func, fi.result, stats) )
      ++stats.result_binds;
  }

  // ---------------------------------------------------------------- cross-site aggregation
  // Every value handed to (or returned by) the same callee is one type: a `void*` seen as two
  // different struct pointers through the same function becomes the union of both behaviors. This
  // also covers callees whose body was never lifted (libc imports, external stubs).
  if ( !aggregate_sites )
    return;

  std::map<uint64_t, std::vector<const CallSite *>> by_callee;
  for ( const CallSite &s : sites )
  {
    if ( s.callee_ea != kNoAddress )
      by_callee[s.callee_ea].push_back(&s);
  }

  for ( const std::pair<const uint64_t, std::vector<const CallSite *>> &group : by_callee )
  {
    const std::vector<const CallSite *> &v = group.second;
    if ( v.size() < 2 )
      continue;
    const CallSite *first = v[0];
    for ( size_t j = 1; j < v.size(); ++j )
    {
      const CallSite *other = v[j];
      const size_t n = std::min(first->args.size(), other->args.size());
      for ( size_t i = 0; i < n; ++i )
      {
        if ( bind_values(types, first->caller, first->args[i], other->caller, other->args[i], stats) )
          ++stats.site_groups;
        else if ( i < first->arg_pointees.size() )
        {
          // Both sites pass an address: joining the two addressed variables directly is what turns
          // "a different object at each call site" into one precise union of behaviors.
          if ( bind_values(types, first->caller, first->arg_pointees[i], other->caller,
                           i < other->arg_pointees.size() ? other->arg_pointees[i]
                                                          : std::optional<trex::Variable>(),
                           stats) )
            ++stats.site_groups;
        }
      }
      if ( bind_values(types, first->caller, first->result, other->caller, other->result, stats) )
        ++stats.site_groups;
    }
  }
}

InterprocResult run_trex_pipeline_interproc(
    const std::shared_ptr<const trex::Program> &program,
    const std::optional<trex::ILVariableMap> &vars,
    const std::vector<FunctionInterface> &interfaces,
    const std::vector<CallSite> &sites,
    bool aggregate_sites,
    Stats &stats)
{
  InterprocResult out;

  // ---------------------------------------------------------------- structural inference
  StructuralTypes types = infer_structural_types(program);

  // Propagate on a clone: if a join trips one of the container's invariants, the run falls back to
  // the per-function types instead of half-merged ones. `deep_clone` keeps the shared `ssa` object,
  // so the SSA-variable lookups above stay valid.
  StructuralTypes merged = types.deep_clone();
  bool propagated = true;
  try
  {
    propagate(merged, interfaces, sites, aggregate_sites, stats);
  }
  catch ( ... )
  {
    propagated = false;
    stats = Stats{};
  }
  out.propagated = propagated;
  out.stats = stats;

  StructuralTypes &use = propagated ? merged : types;

  // ---------------------------------------------------------------- colocation + aggregates
  std::shared_ptr<StructuralTypes> structured;
  if ( config().enable_colocation_analysis )
  {
    std::shared_ptr<StructuralTypes> inferred = std::make_shared<StructuralTypes>(std::move(use));
    std::shared_ptr<CoLocated> colocated
      = std::make_shared<CoLocated>(CoLocated::analyze(inferred));
    AggregateTypes aggregate = AggregateTypes::analyze(colocated);
    structured = std::make_shared<StructuralTypes>(aggregate.to_structural_types());
    out.pipeline.colocation_analysis_ran = true;
  }
  else
  {
    structured = std::make_shared<StructuralTypes>(std::move(use));
  }
  out.pipeline.structured_types = structured;

  // ---------------------------------------------------------------- serialization
  SerializableStructuralTypes<ExternalVariable> serializable
    = serialize_structural_types(*structured, vars);

  if ( config().enable_type_rounding )
    round_up_to_c_types(serializable.types_mut());

  out.pipeline.structural_text = serializable.serialize();

  // The C-like text is printed from the same (possibly rounded) types.
  PrintableCTypes<ExternalVariable> printer(serializable);
  out.pipeline.c_like_text = printer.to_string();

  out.pipeline.types = std::move(serializable);
  return out;
}

} // namespace trex::interproc
