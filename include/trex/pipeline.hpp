#pragma once

// The end-to-end TRex pipeline, shared by the test CLI and the IDA plugin.
//
// Mirrors upstream `trex/src/main.rs`:
//   infer structural types -> (colocation +) aggregate analysis -> serialize
//   -> (optionally) round to C primitives -> structural text + C-like text.

#include <memory>
#include <optional>
#include <string>

#include <trex/il.hpp>
#include <trex/inference_config.hpp>
#include <trex/serialize_structural.hpp>
#include <trex/structural.hpp>

namespace trex {

namespace starts_at_analysis {
class CoLocated;
}
namespace aggregate_types {
class AggregateTypes;
}

/// Inference over a lifted program: the port of `Program::infer_structural_types`.
StructuralTypes infer_structural_types(const std::shared_ptr<const Program> &program);

/// Everything a completed run produces.
struct TrexPipelineResult
{
  /// `SerializableStructuralTypes::serialize()` output (the `.structural` format).
  std::string structural_text;
  /// `PrintableCTypes` output (the C-like types).
  std::string c_like_text;
  /// The serialized types, post-rounding when rounding is enabled. Kept so callers can map
  /// variables to inferred type names (the plugin's report and its write-back action).
  std::optional<SerializableStructuralTypes<ExternalVariable>> types;
  /// The structural types the serialization came from (used for the GraphViz dump).
  std::shared_ptr<const StructuralTypes> structured_types;
  /// Whether colocation/aggregate analysis ran (mirrors CONFIG.enable_colocation_analysis).
  bool colocation_analysis_ran = false;
};

/// Run inference + serialization for a lifted program.
/// \param vars  the external-variable map; nullopt reproduces upstream's "no .vars file" behaviour.
TrexPipelineResult run_trex_pipeline(const std::shared_ptr<const Program> &program,
                                     const std::optional<ILVariableMap> &vars);

} // namespace trex
