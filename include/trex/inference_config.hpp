#pragma once

// A global store of flags that impact inference - port of upstream `trex/src/inference_config.rs`.
//
// Upstream lazily initialises a process-global from the command line and asserts it is only
// initialised once. The port keeps the same global and the same defaults, but allows
// re-initialisation because the IDA plugin runs inference repeatedly in one process.

#include <string>
#include <vector>

namespace trex {

struct InferenceConfig
{
  bool allow_size_restriction_based_on_given_variable_size_info = true;
  bool unify_types_on_comparison_ops = true;
  bool unify_types_on_carry_or_borrow_ops = true;
  bool direct_join_pointees_rather_than_clone_and_join = true;
  bool direct_join_struct_fields_rather_than_clone_and_join = true;
  bool enable_colocation_analysis = true;
  bool allow_aggregate_analysis_to_set_upper_bound_size = false;
  bool enable_type_rounding = true;
  bool prefer_signed_integers_when_rounding = true;
  bool signed_integers_support_all_integer_ops = false;
  bool allow_type_rounding_based_on_upper_bound_size = true;
  bool round_up_undefined_n_to_integer = true;
  bool collapse_union_of_signed_and_unsigned_ints = true;
  bool allow_outputting_size_only_types_based_on_input = true;
  bool additionally_include_next_size_nonlinear_ops_for_integers = false;
  bool dump_inference_log_dot_files = false;
  bool fix_ghidra_branch_to_next_insn_as_call_with_fallthrough = true;
  bool stack_pointer_patch_after_call_fallthrough = true;
  bool calling_convention_match_caller_if_unknown_for_callee = true;
  bool debug_print_il_insns_for_ssa = false;
  bool debug_print_asm_insns_for_ssa = false;
  bool show_only_fn_input_types_if_no_vars_provided = true;

  /// Configuration for the IDA frontend only (no upstream counterpart): directory for
  /// `inference-log-*.dot` files when `dump_inference_log_dot_files` is set. Empty = current dir.
  std::string dot_output_dir;
};

/// Advanced configuration options to tweak inference behaviour (upstream `-Z` flags).
/// Declaration order matches upstream `CommandLineInferenceConfig`.
enum class ConfigFlag
{
  DisableTypeRounding = 0,
  DisableSizeRestrictingCloneChop,
  DisableComparisonOpBasedUnification,
  DisableCarryBorrowBasedUnification,
  DisableAggregateTypeAnalysis,
  EnableAggregateAnalysisImpactingUpperBoundSize,
  DisableSignedIntegerPreference,
  EnableSignedIntegersSupportAllIntegerOperations,
  DisableTypeRoundingBasedOnUpperBoundSize,
  DisableRoundingUpUndefinedNToInteger,
  DisableCollapseUnionOfSignedAndUnsignedInts,
  DisableOutputForSizeKnownOnlyTypes,
  EnableAdditionallyIncludeNextSizeNonLinearOpsForIntegers,
  CloneAndJoinRatherThanDirectJoinOfPointeesDuringDelayedJoins,
  CloneAndJoinRatherThanDirectJoinOfStructFieldsDuringDelayedJoins,
  DumpInferenceLogDotFiles,
  DisableFixGhidraBranchToNextInsnAsCallWithFallthrough,
  DisableStackPointerPatchAfterCallFallthrough,
  DisableCallingConventionMatchCallerIfUnknownForCallee,
  EnableDebugPrintILInsnsForSSA,
  EnableDebugPrintASMInsnsForSSA,
  EnableShowAllSSAVariablesIfNoVarsFileProvided,
};

/// The global configuration store (upstream `static ref CONFIG`).
InferenceConfig &config();

/// Initialise the global configuration from the given advanced flags.
void initialize_config(const std::vector<ConfigFlag> &flags = {});

/// Apply one advanced flag to a config object (upstream `From<Vec<CommandLineInferenceConfig>>`).
void apply_config_flag(InferenceConfig &cfg, ConfigFlag flag);

/// Build a config from defaults plus the given flags.
InferenceConfig config_from_flags(const std::vector<ConfigFlag> &flags);

/// `-Z` argument parsing: upstream's clap enum names (`enable-...`, `disable-...`, kebab-case).
/// Returns nullopt for an unknown name.
bool config_flag_from_cli_name(const std::string &name, ConfigFlag &out);
/// The clap spelling of a flag (used by the test CLI's help text).
std::string config_flag_cli_name(ConfigFlag flag);

} // namespace trex
