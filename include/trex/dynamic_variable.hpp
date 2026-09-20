// Dynamically-scoped boolean variables (port of `third_party/trex/trex/src/dynamic_variable.rs`).
//
// Upstream is a Rust macro `dynamic_variable!` that emits three items per invocation:
//   - a thread-local `Cell<bool>` (the flag itself),
//   - a `with_<NAME>_set` helper that flips the flag true for the duration of a closure,
//   - an `if_<NAME>_is_set` helper that selects one of two closures by current value.
//
// The TRex IDA port is single-threaded, so the `thread_local!` becomes a single global
// `bool` per flag. The flag type is a small RAII class (`DynamicVariable`) that owns the
// global bool, plus the two free-function helpers `with_var_set` (RAII guard restored on
// scope exit) and `if_var_set` (lambda dispatch on the current value), each templated on
// the specific `DynamicVariable` instance they target.
//
// Usage mirrors upstream:
//
//     trex::dynamic_variable::DynamicVariable DONT_DISPLAY_POINTER_TO{false};
//     trex::dynamic_variable::with_var_set(DONT_DISPLAY_POINTER_TO, [&]{
//         ...code that runs with the flag set...
//     });
//
//     auto v = trex::dynamic_variable::if_var_set(DONT_DISPLAY_POINTER_TO,
//         [&]{ return 1; },
//         [&]{ return 2; });
//
// The helpers' names match the assignment spec verbatim (`with_var_set`, `if_var_set`);
// the call site names `DONT_DISPLAY_POINTER_TO` (etc.) are exactly the variables
// `structural.rs` defines in upstream, so the future port keeps the same identifiers.

#pragma once

#include <utility>

namespace trex::dynamic_variable {

/// One dynamically-scoped flag. Owns one global `bool` cell (single-threaded port).
class DynamicVariable
{
public:
  /// Initialise the flag to `initial`.
  explicit DynamicVariable(bool initial) noexcept : value_(initial) {}

  DynamicVariable(const DynamicVariable &) = delete;
  DynamicVariable &operator=(const DynamicVariable &) = delete;

  /// RAII guard that flips the flag to `new_value` on construction and restores its
  /// previous value on destruction. Used by `with_var_set`.
  class Setter
  {
  public:
    Setter(DynamicVariable &var, bool new_value) noexcept
        : var_(var), prev_(var.value_)
    {
      var_.value_ = new_value;
    }
    ~Setter() noexcept { var_.value_ = prev_; }

    Setter(const Setter &) = delete;
    Setter &operator=(const Setter &) = delete;

  private:
    DynamicVariable &var_;
    bool prev_;
  };

  /// Read the current value.
  bool get() const noexcept { return value_; }

  /// Set the value (manual; `with_var_set` is the typical entry point).
  void set(bool v) noexcept { value_ = v; }

private:
  bool value_;
};

/// Set `var` to `true` for the duration of `f` and restore it on scope exit.
/// (Mirrors upstream's `with_<NAME>_set`.)
template <typename F>
auto with_var_set(DynamicVariable &var, F &&f)
    -> decltype(std::forward<F>(f)())
{
  typename DynamicVariable::Setter guard(var, true);
  (void)guard;
  return std::forward<F>(f)();
}

/// Run `then_f` if `var` is currently `true`, else `else_f`.
/// (Mirrors upstream's `if_<NAME>_is_set`.)
template <typename ThenF, typename ElseF>
auto if_var_set(const DynamicVariable &var, ThenF &&then_f, ElseF &&else_f)
    -> decltype(std::forward<ThenF>(then_f)())
{
  if ( var.get() )
    return std::forward<ThenF>(then_f)();
  return std::forward<ElseF>(else_f)();
}

} // namespace trex::dynamic_variable