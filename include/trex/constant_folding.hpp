// On-demand constant folding analysis.
//
// 1:1 port of `third_party/trex/trex/src/constant_folding.rs` (144 lines) into C++20.
//
// `ConstFolded` memoises constant values per (IL PC, input slot) for the lifetime of
// the analysis. The four value flavours (`Unknown`, `SentinelForRecursion`, `Dynamic`,
// `Constant(u64)`) guard against recursive definitions: a recursive query returns
// `None` (the value is "dynamic", not a compile-time constant).
//
// `output_at(il_pc)` is the constant value of the instruction's output (if any);
// `input_at(il_pc, i)` is the constant value of the input at slot `i` (if any). Both
// return `std::nullopt` when the value is not a compile-time constant.

#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include <trex/ssa.hpp>

namespace trex {

// Forward declaration so `ConstFolded::from_ssa` can take `&Rc<SSA>`-style shared ptr.
class SSA;

class ConstFolded
{
public:
  /// Construct a new query-able analysis over `ssa`. Mirrors `ConstFolded::from_ssa`.
  static std::shared_ptr<ConstFolded> from_ssa(std::shared_ptr<const ssa::SSA> ssa);

  /// The constant output of the instruction at `il_pc`, if it is a constant.
  std::optional<uint64_t> output_at(size_t il_pc) const;

  /// The constant input at `il_pc` at position `i`, if it is a constant.
  std::optional<uint64_t> input_at(size_t il_pc, size_t i);

private:
  /// Internal memo slot. Mirrors `enum Value` from upstream.
  enum class Value
  {
    Unknown = 0,
    SentinelForRecursion,
    Dynamic,
    Constant,
  };

  // Per (il_pc, slot) memo entry. `constant` holds the constant value when `state ==
  // Constant`. When `state` is `Dynamic` or `SentinelForRecursion`, `constant` is
  // empty.
  struct Memo
  {
    Value state = Value::Unknown;
    std::optional<uint64_t> constant;
  };

  std::vector<std::array<Memo, 2>> known_constants_;
  std::shared_ptr<const ssa::SSA> ssa_;
};

} // namespace trex