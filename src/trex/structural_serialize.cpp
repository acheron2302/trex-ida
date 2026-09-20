// Port of upstream `StructuralTypes::serialize` (structural.rs:1322-1580) and of the aggregate
// size restriction helper it uses (structural.rs:1810-1940).
//
// Lives in its own translation unit because it is the bridge between the structural engine and the
// serialization layer; `structural.cpp` owns the inference itself.

#include <algorithm>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <trex/error.hpp>
#include <trex/inference_config.hpp>
#include <trex/log.hpp>
#include <trex/serialize_structural.hpp>
#include <trex/ssa.hpp>
#include <trex/structural.hpp>

namespace trex {
namespace {

using ssa::Variable;

bool is_definite(const AggregateSize &a, size_t n)
{
  return a.kind == AggregateSize::Kind::Definite && a.value == n;
}

} // namespace

Index get_equivalent_index_with_restricted_aggregate_size(
    IndexMap<std::map<size_t, Index>> &restriction_map_cache,
    Container<StructuralType> &types,
    Index idx,
    size_t upper_bound_size,
    const Program &program)
{
  if ( const std::map<size_t, Index> *cached = restriction_map_cache.get(idx) )
  {
    std::map<size_t, Index>::const_iterator it = cached->find(upper_bound_size);
    if ( it != cached->end() )
      return it->second;
  }

  const StructuralType typ = types.get(idx);

  if ( !typ.observed_size().has_value() )
  {
    log::trace("Trying to restrict size of observed-size-unknown type",
               { { "idx", idx.to_string() }, { "requested_upper_bound", upper_bound_size } });
    StructuralType newtyp = typ;
    newtyp.upper_bound_size = upper_bound_size;
    return types.insert(newtyp);
  }

  const size_t observed = *typ.observed_size();
  std::optional<AggregateSize> aggsz_opt = typ.aggregate_size(types, std::nullopt);
  TREX_CHECK(aggsz_opt.has_value(), "aggregate_size of a sized type must be known");
  const AggregateSize aggsz = *aggsz_opt;


  Index tgt_idx;

  switch ( aggsz.kind )
  {
    case AggregateSize::Kind::Definite:
    case AggregateSize::Kind::IndefiniteOutOfFuel:
    {
      const bool out_of_fuel = aggsz.kind == AggregateSize::Kind::IndefiniteOutOfFuel;
      if ( out_of_fuel )
      {
        log::debug("Detected an overly-recursive type. Using only first element and ignoring rest",
                   { { "observed_size", observed }, { "requested_upper_bound", upper_bound_size } });
      }

      // Upstream matches on the tuple `(aggregate_size, observed_size)`:
      //     (Definite(sz) | IndefiniteOutOfFuel, sz) => ...
      // so for the `Definite` arm the comparison uses the AGGREGATE size (which for a struct
      // includes all colocated fields) and for `IndefiniteOutOfFuel` it uses the observed size.
      // Using the observed size unconditionally (as an earlier version of this port did) leaves an
      // over-sized aggregate un-chopped and changes which type a variable ends up with.
      const size_t sz = out_of_fuel ? observed : aggsz.value;

      if ( sz <= upper_bound_size && !out_of_fuel )
      {
        return idx;
      }

      if ( observed == upper_bound_size )
      {
        log::trace("Aggregate restriction: colocated chop",
                   { { "observed_size", observed }, { "requested_upper_bound", upper_bound_size } });
        StructuralType newtyp = typ;
        newtyp.colocated_struct_fields.clear();
        tgt_idx = types.insert(newtyp);
      }
      else if ( observed > upper_bound_size )
      {
        log::trace("Aggregate restriction: local chop",
                   { { "observed_size", observed }, { "requested_upper_bound", upper_bound_size } });
        StructuralType newtyp = typ;
        newtyp.upper_bound_size = upper_bound_size;

        std::set<size_t> copies;
        for ( size_t sz : newtyp.copy_sizes )
        {
          if ( sz <= upper_bound_size )
            copies.insert(sz);
        }
        newtyp.copy_sizes = copies;

        if ( upper_bound_size < program.pointer_size && newtyp.pointer_to.has_value() )
        {
          log::debug("Localchop: non-pointer due to size restrictions",
                     { { "requested_upper_bound", upper_bound_size },
                       { "pointer_sizes_in_binary", program.pointer_size } });
          newtyp.pointer_to.reset();
        }

        std::set<std::pair<IntegerOp, size_t>> int_ops;
        for ( const auto &op : newtyp.integer_ops )
        {
          if ( op.second <= upper_bound_size )
            int_ops.insert(op);
        }
        newtyp.integer_ops = int_ops;

        std::set<std::pair<BooleanOp, size_t>> bool_ops;
        for ( const auto &op : newtyp.boolean_ops )
        {
          if ( op.second <= upper_bound_size )
            bool_ops.insert(op);
        }
        newtyp.boolean_ops = bool_ops;

        std::set<std::pair<FloatOp, size_t>> float_ops;
        for ( const auto &op : newtyp.float_ops )
        {
          if ( op.second <= upper_bound_size )
            float_ops.insert(op);
        }
        newtyp.float_ops = float_ops;

        newtyp.colocated_struct_fields.clear();
        tgt_idx = types.insert(newtyp);
      }
      else if ( out_of_fuel )
      {
        log::trace("Aggregate restriction: smaller elem on overly-recursive type. Giving up.",
                   { { "observed_size", observed }, { "requested_upper_bound", upper_bound_size } });
        return idx;
      }
      else
      {
        log::debug("TODO: Definite but smaller upper bound size. Giving up and returning the full size.",
                   { { "observed_size", observed }, { "requested_upper_bound", upper_bound_size } });
        return idx;
      }
      break;
    }

    case AggregateSize::Kind::IndefiniteArrayWithElementSize:
    {
      const size_t element_size = aggsz.value;
      log::trace("Restricting type size for indefinite array",
                 { { "element_size", element_size }, { "requested_upper_bound", upper_bound_size } });
      TREX_CHECK(observed == element_size, "indefinite array's observed size must equal its element size");

      StructuralType newtyp = typ;
      newtyp.observed_array = false;
      const Index newidx = types.insert(newtyp);

      if ( element_size > upper_bound_size )
      {
        // The element itself must be broken apart.
        tgt_idx = get_equivalent_index_with_restricted_aggregate_size(restriction_map_cache,
                                                                     types,
                                                                     newidx,
                                                                     upper_bound_size,
                                                                     program);
      }
      else
      {
        StructuralType aggtyp = types.get(newidx);
        for ( size_t i = 1; i < upper_bound_size / element_size; ++i )
          aggtyp.colocated_struct_fields[i * element_size] = newidx;

        const size_t remainder_size = upper_bound_size % element_size;
        if ( remainder_size != 0 )
        {
          aggtyp.colocated_struct_fields[(upper_bound_size / element_size) * element_size]
            = get_equivalent_index_with_restricted_aggregate_size(restriction_map_cache,
                                                                  types,
                                                                  newidx,
                                                                  remainder_size,
                                                                  program);
        }
        tgt_idx = types.insert(aggtyp);
      }
      break;
    }

    case AggregateSize::Kind::IndefiniteStructLowerBoundedBy:
    {
      const size_t lower_bound = aggsz.value;
      log::trace("Restricting type size for indefinite struct",
                 { { "lower_bound", lower_bound }, { "requested_upper_bound", upper_bound_size } });

      if ( observed >= upper_bound_size )
      {
        StructuralType newtyp = typ;
        newtyp.colocated_struct_fields.clear();
        newtyp.observed_array = false;
        if ( observed > upper_bound_size )
        {
          newtyp.upper_bound_size = upper_bound_size;
          std::set<size_t> copies;
          for ( size_t sz : newtyp.copy_sizes )
          {
            if ( sz <= upper_bound_size )
              copies.insert(sz);
          }
          newtyp.copy_sizes = copies;

          std::set<std::pair<IntegerOp, size_t>> int_ops;
          for ( const auto &op : newtyp.integer_ops )
          {
            if ( op.second <= upper_bound_size )
              int_ops.insert(op);
          }
          newtyp.integer_ops = int_ops;
        }
        tgt_idx = types.insert(newtyp);
      }
      else
      {
        log::debug("Indefinite struct, first element chop insufficient. Giving up and returning full struct.",
                   { { "observed_size", observed }, { "requested_upper_bound", upper_bound_size } });
        return idx;
      }
      break;
    }
  }

  const std::optional<AggregateSize> final_size = types.get(tgt_idx).aggregate_size(types, std::nullopt);
  if ( !final_size.has_value() || !is_definite(*final_size, upper_bound_size) )
  {
    log::debug("Non-matching definite size for squished type.",
               { { "expected_definite_size", upper_bound_size } });
  }

  std::map<size_t, Index> *cache_entry = restriction_map_cache.get_mut(idx);
  if ( cache_entry == nullptr )
  {
    restriction_map_cache.insert(idx, std::map<size_t, Index>());
    cache_entry = restriction_map_cache.get_mut(idx);
  }
  TREX_CHECK(cache_entry != nullptr, "failed to allocate a restriction-map cache entry");
  (*cache_entry)[upper_bound_size] = tgt_idx;
  return tgt_idx;
}

SerializableStructuralTypes<ExternalVariable> serialize_structural_types(
    const StructuralTypes &self,
    const std::optional<ILVariableMap> &vars)
{
  using il_var = ::trex::Variable;

  // ------------------------------------------------------------------ stack pointer default
  std::pair<std::string, il_var> vars_stack_pointer;
  if ( vars.has_value() )
  {
    vars_stack_pointer = vars->stack_pointer;
  }
  else
  {
    const size_t ptr = self.ssa->program->pointer_size;
    TREX_CHECK(ptr == 4 || ptr == 8, "unsupported pointer size %zu", ptr);
    size_t register_space = 0;
    bool found = false;
    for ( size_t i = 0; i < self.ssa->program->address_spaces.size(); ++i )
    {
      if ( self.ssa->program->address_spaces[i].name == "register" )
      {
        register_space = i;
        found = true;
        break;
      }
    }
    TREX_CHECK(found, "no `register` address space in the program");
    vars_stack_pointer.first = ptr == 4 ? "ESP" : "RSP";
    vars_stack_pointer.second = il_var::varnode(register_space, ptr == 4 ? 0x10 : 0x20, ptr);
  }

  std::map<size_t, std::vector<ssa::Variable>> stack_pointer_var; // fnid -> the SP ssa variable(s)
  std::vector<std::tuple<ExternalVariable, size_t, Index>> var_type_list;
  std::vector<std::pair<ExternalVariable, size_t>> non_matching_sized_external_variables;

  if ( vars.has_value() )
  {
    for ( const auto &entry : vars->varmap )
    {
      const ExternalVariable &extvar = entry.first;
      const size_t fnid = entry.second.first;
      const std::vector<il_var> &ilvars = entry.second.second;

      // Functions that raise a processor exception immediately carry no useful variables.
      std::optional<std::pair<size_t, size_t>> il_range
        = self.ssa->program->get_il_addrs_for_machine_addr(self.ssa->program->functions[fnid].entry.first);
      if ( il_range.has_value()
        && self.ssa->program->instructions[il_range->first].op.kind == OpKind::ProcessorException )
      {
        continue;
      }

      std::optional<size_t> extvarsize;
      for ( const il_var &ilvar : ilvars )
      {
        size_t size = 0;
        if ( ilvar.kind == VarKind::Varnode )
          size = ilvar.size;
        else if ( ilvar.kind == VarKind::StackVariable )
          size = ilvar.var_size;
        else
          TREX_UNREACHABLE("unexpected external-variable IL kind");
        if ( extvarsize.has_value() )
          TREX_CHECK(*extvarsize == size, "inconsistent external variable sizes");
        else
          extvarsize = size;

        std::optional<std::vector<ssa::Variable>> matching
          = self.ssa->get_first_matching_variables_for(ilvar, fnid);
        if ( matching.has_value() )
        {
          log::trace("Matching variables", { { "extvar", extvar.name } });
          for ( const ssa::Variable &var : *matching )
          {
            std::optional<Index> idx = self.get_type_index(var);
            if ( !idx.has_value() )
            {
              // Upstream unwraps here, which holds for its Ghidra frontend because every variable
              // it reports was touched by the analysis. The IDA frontend reports *every* lvar IDA
              // allocated, including ones that never appear in a constrained instruction, so an
              // unconstrained variable is skipped rather than aborting the whole run.
              log::debug("Skipping a variable the analysis never constrained",
                         { { "extvar", extvar.name }, { "var", var.debug_string() } });
              continue;
            }
            var_type_list.emplace_back(extvar, *extvarsize, *idx);
          }
        }
        else if ( ilvar.kind == VarKind::StackVariable )
        {
          log::trace("Extvar is a stack variable", { { "extvar", extvar.name } });

          const std::vector<ssa::Variable> *sp_vars = nullptr;
          std::map<size_t, std::vector<ssa::Variable>>::const_iterator cached = stack_pointer_var.find(fnid);
          if ( cached != stack_pointer_var.end() )
          {
            sp_vars = &cached->second;
          }
          else
          {
            std::optional<std::vector<ssa::Variable>> spvs
              = self.ssa->get_first_matching_variables_for(vars_stack_pointer.second, fnid);
            if ( !spvs.has_value() )
            {
              log::debug("Could not find a stack pointer variable for stack-relative external var",
                         { { "extvar", extvar.name }, { "fnid", fnid } });
              non_matching_sized_external_variables.emplace_back(extvar, *extvarsize);
              continue;
            }
            TREX_CHECK(spvs->size() == 1, "expected exactly one stack pointer variable");
            std::vector<ssa::Variable> &stored = stack_pointer_var[fnid];
            stored = *spvs;
            sp_vars = &stored;
          }

          const int64_t offset = ilvar.stack_offset;
          std::vector<ssa::Variable> matching_vars
            = self.ssa->get_stack_involved_ssa_variables(fnid, (*sp_vars)[0], offset);
          if ( matching_vars.empty() )
          {
            log::debug("Could not get matching internal vars for stack-relative external var",
                       { { "extvar", extvar.name }, { "fnid", fnid } });
            non_matching_sized_external_variables.emplace_back(extvar, *extvarsize);
          }
          else
          {
            for ( const ssa::Variable &var : matching_vars )
            {
              std::optional<Index> idx = self.get_type_index(var);
              if ( !idx.has_value() )
              {
                log::debug("Skipping a stack variable the analysis never constrained",
                           { { "extvar", extvar.name }, { "var", var.debug_string() } });
                continue;
              }
              var_type_list.emplace_back(extvar, *extvarsize, *idx);
            }
          }
        }
        else
        {
          log::debug("Could not get matching internal vars for external var",
                     { { "extvar", extvar.name }, { "fnid", fnid } });
          non_matching_sized_external_variables.emplace_back(extvar, *extvarsize);
        }
      }
    }
  }

  // ------------------------------------------------------------------ no .vars file: use the IL
  if ( !vars.has_value() )
  {
    const Program &program = *self.ssa->program;
    for ( size_t pc = 0; pc < program.instructions.size(); ++pc )
    {
      const Instruction &ins = program.instructions[pc];
      if ( ins.op.kind != OpKind::FunctionStart )
        continue;

      size_t current_func_id = 0;
      bool found = false;
      for ( size_t f = 0; f < program.functions.size() && !found; ++f )
      {
        for ( size_t bb : program.functions[f].basic_blocks )
        {
          const std::vector<size_t> &block = program.basic_blocks[bb];
          if ( std::find(block.begin(), block.end(), pc) != block.end() )
          {
            current_func_id = f;
            found = true;
            break;
          }
        }
      }
      TREX_CHECK(found, "FunctionStart instruction does not belong to any function");
      const std::string &current_func = program.functions[current_func_id].name;

      std::vector<ssa::Variable> function_variables;
      if ( config().show_only_fn_input_types_if_no_vars_provided )
      {
        function_variables = self.ssa->get_function_inputs(pc);
      }
      else
      {
        std::set<ssa::Variable> unique_vars;
        for ( const auto &kv : self.ssa->get_all_normal_vars_of_function(current_func_id) )
        {
          if ( kv.second.kind == ssa::Variable::Kind::Variable )
            unique_vars.insert(kv.second);
        }
        function_variables.assign(unique_vars.begin(), unique_vars.end());
      }

      for ( const ssa::Variable &v : function_variables )
      {
        std::optional<Index> t = self.get_type_index(v);
        if ( t.has_value() )
        {
          const StructuralType &typ = self.types.get(*t);
          var_type_list.emplace_back(ExternalVariable(v.debug_string() + "@" + current_func),
                                     typ.observed_size().value_or(0),
                                     *t);
        }
        else
        {
          log::debug("Missing type for variable",
                     { { "current_func", current_func }, { "v", v.debug_string() } });
        }
      }
    }
  }

  // ------------------------------------------------------------------ build the result
  std::vector<Index *> roots;
  roots.reserve(var_type_list.size());
  for ( auto &entry : var_type_list )
    roots.push_back(&std::get<2>(entry));

  Container<StructuralType> types = self.types.deep_clone(roots);

  std::map<ExternalVariable, Index> varmap;
  IndexMap<std::map<size_t, Index>> restriction_map_cache;

  for ( auto &entry : var_type_list )
  {
    const ExternalVariable &extvar = std::get<0>(entry);
    const size_t extvarsize = std::get<1>(entry);
    Index typidx = std::get<2>(entry);
    if ( config().allow_size_restriction_based_on_given_variable_size_info )
    {
      typidx = get_equivalent_index_with_restricted_aggregate_size(restriction_map_cache,
                                                                  types,
                                                                  typidx,
                                                                  extvarsize,
                                                                  *self.ssa->program);
    }
    std::map<ExternalVariable, Index>::iterator prev = varmap.find(extvar);
    if ( prev != varmap.end() )
      types.join(prev->second, typidx);
    else
      varmap.insert(std::make_pair(extvar, typidx));
  }

  if ( config().allow_outputting_size_only_types_based_on_input )
  {
    for ( const auto &entry : non_matching_sized_external_variables )
    {
      const ExternalVariable &extvar = entry.first;
      const size_t extvarsize = entry.second;
      std::map<ExternalVariable, Index>::iterator prev = varmap.find(extvar);
      if ( prev != varmap.end() )
      {
        if ( !types.get_mut(prev->second).set_upper_bound_size(extvarsize) )
        {
          log::debug("Conflicting upper bound sizes", { { "extvar", extvar.name } });
        }
      }
      else
      {
        StructuralType typ;
        TREX_CHECK(typ.set_upper_bound_size(extvarsize), "default type must accept an upper bound");
        varmap.insert(std::make_pair(extvar, types.insert(typ)));
      }
    }
  }

  IndexMap<std::string> type_names;
  return new_serializable_structural_types(varmap, type_names, std::move(types));
}

} // namespace trex
