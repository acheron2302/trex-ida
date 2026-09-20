#pragma once

// Reference (Ghidra-text) frontend.
//
// Port of upstream `trex/src/ghidra_lifter.rs::lift_from` and
// `trex/src/ghidra_variable_lifter.rs::lift_from`. The two lifters consume the
// textual p-code listing and DWARF-derived variable table that the upstream
// `PCodeExporter.java` / `VariableExporter.java` scripts emit, and build a
// `trex::Program` / `trex::ILVariableMap` identical to the Rust version.
//
// This frontend is test-only: it is what proves the core pipeline matches the
// Rust oracle. The plugin uses the IDA microcode frontend instead.

#include <memory>
#include <string>

#include <trex/il.hpp>

namespace trex {

/// Port of `ghidra_lifter::lift_from`. Parses the textual `.lifted` p-code
/// listing and returns a `Program` ready for type inference.
std::shared_ptr<Program> lift_program_from_lifted_text(const std::string &text);

/// Port of `ghidra_variable_lifter::lift_from`. Parses the textual `.vars`
/// file (DWARF-derived variable table) and returns an `ILVariableMap` keyed
/// by `name@function@<8-hex-digits>` ExternalVariables, with stack-relative
/// entries lifted to `Variable::stack_variable` and the program's stack
/// pointer copied from the `stack_pointer` line.
ILVariableMap lift_variable_map_from_vars_text(const std::string &text,
                                               const std::shared_ptr<const Program> &prog);

} // namespace trex