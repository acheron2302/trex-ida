// The end-to-end TRex pipeline - see include/trex/pipeline.hpp.
//
// Faithful port of the driver in upstream `trex/src/main.rs`.

#include <trex/pipeline.hpp>

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <trex/aggregate_types.hpp>
#include <trex/c_type_printer.hpp>
#include <trex/error.hpp>
#include <trex/serialize_structural.hpp>
#include <trex/starts_at_analysis.hpp>
#include <trex/type_rounding.hpp>

namespace trex {

TrexPipelineResult run_trex_pipeline(const std::shared_ptr<const Program> &program,
                                     const std::optional<ILVariableMap> &vars)
{
  TrexPipelineResult result;

  // ---------------------------------------------------------------- structural inference
  StructuralTypes types = infer_structural_types(program);

  // ---------------------------------------------------------------- colocation + aggregates
  std::shared_ptr<StructuralTypes> structured;
  if ( config().enable_colocation_analysis )
  {
    std::shared_ptr<StructuralTypes> inferred = std::make_shared<StructuralTypes>(std::move(types));
    std::shared_ptr<CoLocated> colocated
      = std::make_shared<CoLocated>(CoLocated::analyze(inferred));
    AggregateTypes aggregate = AggregateTypes::analyze(colocated);
    structured = std::make_shared<StructuralTypes>(aggregate.to_structural_types());
    result.colocation_analysis_ran = true;
  }
  else
  {
    structured = std::make_shared<StructuralTypes>(std::move(types));
  }
  result.structured_types = structured;

  // ---------------------------------------------------------------- serialization
  SerializableStructuralTypes<ExternalVariable> serializable
    = serialize_structural_types(*structured, vars);

  if ( config().enable_type_rounding )
    round_up_to_c_types(serializable.types_mut());

  result.structural_text = serializable.serialize();

  // The C-like text is printed from the same (possibly rounded) types.
  PrintableCTypes<ExternalVariable> printer(serializable);
  result.c_like_text = printer.to_string();

  result.types = std::move(serializable);
  return result;
}

} // namespace trex
