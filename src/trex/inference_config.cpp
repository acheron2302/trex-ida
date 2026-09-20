#include <trex/inference_config.hpp>

#include <array>

namespace trex {
namespace {

InferenceConfig g_config;

void warn_unused(const InferenceConfig &) {}

} // namespace

InferenceConfig &config()
{
  return g_config;
}

void apply_config_flag(InferenceConfig &cfg, ConfigFlag flag)
{
  switch ( flag )
  {
    case ConfigFlag::DisableTypeRounding:
      cfg.enable_type_rounding = false;
      break;
    case ConfigFlag::DisableSizeRestrictingCloneChop:
      cfg.allow_size_restriction_based_on_given_variable_size_info = false;
      break;
    case ConfigFlag::DisableComparisonOpBasedUnification:
      cfg.unify_types_on_comparison_ops = false;
      break;
    case ConfigFlag::DisableCarryBorrowBasedUnification:
      cfg.unify_types_on_carry_or_borrow_ops = false;
      break;
    case ConfigFlag::DisableAggregateTypeAnalysis:
      cfg.enable_colocation_analysis = false;
      break;
    case ConfigFlag::EnableAggregateAnalysisImpactingUpperBoundSize:
      cfg.allow_aggregate_analysis_to_set_upper_bound_size = true;
      break;
    case ConfigFlag::DisableSignedIntegerPreference:
      cfg.prefer_signed_integers_when_rounding = false;
      break;
    case ConfigFlag::EnableSignedIntegersSupportAllIntegerOperations:
      cfg.signed_integers_support_all_integer_ops = true;
      break;
    case ConfigFlag::DisableTypeRoundingBasedOnUpperBoundSize:
      cfg.allow_type_rounding_based_on_upper_bound_size = false;
      break;
    case ConfigFlag::DisableRoundingUpUndefinedNToInteger:
      cfg.round_up_undefined_n_to_integer = false;
      break;
    case ConfigFlag::DisableCollapseUnionOfSignedAndUnsignedInts:
      cfg.collapse_union_of_signed_and_unsigned_ints = false;
      break;
    case ConfigFlag::DisableOutputForSizeKnownOnlyTypes:
      cfg.allow_outputting_size_only_types_based_on_input = false;
      break;
    case ConfigFlag::EnableAdditionallyIncludeNextSizeNonLinearOpsForIntegers:
      cfg.additionally_include_next_size_nonlinear_ops_for_integers = true;
      break;
    case ConfigFlag::CloneAndJoinRatherThanDirectJoinOfPointeesDuringDelayedJoins:
      cfg.direct_join_pointees_rather_than_clone_and_join = false;
      break;
    case ConfigFlag::CloneAndJoinRatherThanDirectJoinOfStructFieldsDuringDelayedJoins:
      cfg.direct_join_struct_fields_rather_than_clone_and_join = false;
      break;
    case ConfigFlag::DumpInferenceLogDotFiles:
      cfg.dump_inference_log_dot_files = true;
      break;
    case ConfigFlag::DisableFixGhidraBranchToNextInsnAsCallWithFallthrough:
      cfg.fix_ghidra_branch_to_next_insn_as_call_with_fallthrough = false;
      break;
    case ConfigFlag::DisableStackPointerPatchAfterCallFallthrough:
      cfg.stack_pointer_patch_after_call_fallthrough = false;
      break;
    case ConfigFlag::DisableCallingConventionMatchCallerIfUnknownForCallee:
      cfg.calling_convention_match_caller_if_unknown_for_callee = false;
      break;
    case ConfigFlag::EnableDebugPrintILInsnsForSSA:
      cfg.debug_print_il_insns_for_ssa = true;
      break;
    case ConfigFlag::EnableDebugPrintASMInsnsForSSA:
      cfg.debug_print_asm_insns_for_ssa = true;
      break;
    case ConfigFlag::EnableShowAllSSAVariablesIfNoVarsFileProvided:
      cfg.show_only_fn_input_types_if_no_vars_provided = false;
      break;
  }
}

InferenceConfig config_from_flags(const std::vector<ConfigFlag> &flags)
{
  InferenceConfig cfg;
  for ( ConfigFlag f : flags )
    apply_config_flag(cfg, f);
  warn_unused(cfg);
  return cfg;
}

void initialize_config(const std::vector<ConfigFlag> &flags)
{
  g_config = config_from_flags(flags);
}

namespace {

struct FlagName
{
  ConfigFlag flag;
  const char *cli_name;
};

const std::array<FlagName, 22> &flag_names()
{
  static const std::array<FlagName, 22> names = { {
    { ConfigFlag::DisableTypeRounding, "disable-type-rounding" },
    { ConfigFlag::DisableSizeRestrictingCloneChop, "disable-size-restricting-clone-chop" },
    { ConfigFlag::DisableComparisonOpBasedUnification, "disable-comparison-op-based-unification" },
    { ConfigFlag::DisableCarryBorrowBasedUnification, "disable-carry-borrow-based-unification" },
    { ConfigFlag::DisableAggregateTypeAnalysis, "disable-aggregate-type-analysis" },
    { ConfigFlag::EnableAggregateAnalysisImpactingUpperBoundSize,
      "enable-aggregate-analysis-impacting-upper-bound-size" },
    { ConfigFlag::DisableSignedIntegerPreference, "disable-signed-integer-preference" },
    { ConfigFlag::EnableSignedIntegersSupportAllIntegerOperations,
      "enable-signed-integers-support-all-integer-operations" },
    { ConfigFlag::DisableTypeRoundingBasedOnUpperBoundSize,
      "disable-type-rounding-based-on-upper-bound-size" },
    { ConfigFlag::DisableRoundingUpUndefinedNToInteger, "disable-rounding-up-undefined-n-to-integer" },
    { ConfigFlag::DisableCollapseUnionOfSignedAndUnsignedInts,
      "disable-collapse-union-of-signed-and-unsigned-ints" },
    { ConfigFlag::DisableOutputForSizeKnownOnlyTypes, "disable-output-for-size-known-only-types" },
    { ConfigFlag::EnableAdditionallyIncludeNextSizeNonLinearOpsForIntegers,
      "enable-additionally-include-next-size-non-linear-ops-for-integers" },
    { ConfigFlag::CloneAndJoinRatherThanDirectJoinOfPointeesDuringDelayedJoins,
      "clone-and-join-rather-than-direct-join-of-pointees-during-delayed-joins" },
    { ConfigFlag::CloneAndJoinRatherThanDirectJoinOfStructFieldsDuringDelayedJoins,
      "clone-and-join-rather-than-direct-join-of-struct-fields-during-delayed-joins" },
    { ConfigFlag::DumpInferenceLogDotFiles, "dump-inference-log-dot-files" },
    { ConfigFlag::DisableFixGhidraBranchToNextInsnAsCallWithFallthrough,
      "disable-fix-ghidra-branch-to-next-insn-as-call-with-fallthrough" },
    { ConfigFlag::DisableStackPointerPatchAfterCallFallthrough,
      "disable-stack-pointer-patch-after-call-fallthrough" },
    { ConfigFlag::DisableCallingConventionMatchCallerIfUnknownForCallee,
      "disable-calling-convention-match-caller-if-unknown-for-callee" },
    { ConfigFlag::EnableDebugPrintILInsnsForSSA, "enable-debug-print-il-insns-for-ssa" },
    { ConfigFlag::EnableDebugPrintASMInsnsForSSA, "enable-debug-print-asm-insns-for-ssa" },
    { ConfigFlag::EnableShowAllSSAVariablesIfNoVarsFileProvided,
      "enable-show-all-ssa-variables-if-no-vars-file-provided" },
  } };
  return names;
}

} // namespace

bool config_flag_from_cli_name(const std::string &name, ConfigFlag &out)
{
  for ( const FlagName &n : flag_names() )
  {
    if ( name == n.cli_name )
    {
      out = n.flag;
      return true;
    }
  }
  return false;
}

std::string config_flag_cli_name(ConfigFlag flag)
{
  for ( const FlagName &n : flag_names() )
    if ( n.flag == flag )
      return n.cli_name;
  return "<unknown>";
}

} // namespace trex
