// Program-wide dataflow summary and the worklist-based forward analyzer.
//
// 1:1 port of `third_party/trex/trex/src/dataflow.rs` (314 lines) into C++20.
//
// `ASLocation` lives in `<trex/aslocation.hpp>` (already ported by an earlier step),
// because `il.rs` references it for `Variable::try_to_aslocation`; the dataflow summary
// also depends on it, so the same header is included here.
//
// `ProgPoint` and `ProgramSummary` are shared between the dataflow framework and the SSA
// pass (`<trex/ssa.hpp>`); they live here because that is where upstream defines them.
//
// `DataFlowElement` is the trait whose four methods (`init`, `join_from`,
// `init_func_start`, `transfer_function`) define a particular dataflow analysis;
// reaching definitions is one implementation, but the framework is generic.
// `DataFlow<T>` is the result of running a forward analysis over a single function.
//
// Upstream's `Rc<Program>` / `Rc<ProgramSummary>` become `std::shared_ptr<const ...>`
// in this single-threaded port. The `<T>` parameterisation of `DataFlow` in upstream
// exists only to give the storage a concrete element type; the worklist itself only
// calls virtual methods on `&DataFlowElement`, so the C++ port stores elements as
// `std::unique_ptr<DataFlowElement>` and uses a `clone()` virtual to deep-copy.

#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <trex/aslocation.hpp>
#include <trex/containers.hpp>
#include <trex/error.hpp>
#include <trex/il.hpp>
#include <trex/log.hpp>

namespace trex {

// ---------------------------------------------------------------------------
// ProgPoint
//
// A program point: in TRex's IL, the only kind of point is an IL PC. Upstream models
// this as a single-variant enum; we keep the single-variant shape with an explicit kind
// so future additions (eg. block-level points) port verbatim.
//
// Ordering matches Rust's derived `Ord` on the single `usize` payload: lower IL PCs
// compare less.
class ProgPoint
{
public:
  enum class Kind : uint8_t
  {
    Insn = 0,
  };

  Kind kind = Kind::Insn;
  size_t il_pc = 0;

  ProgPoint() = default;
  ProgPoint(Kind k, size_t pc) : kind(k), il_pc(pc) {}
  static ProgPoint insn(size_t il_pc) { return ProgPoint{ Kind::Insn, il_pc }; }

  std::string debug_string() const;

  friend bool operator==(const ProgPoint &a, const ProgPoint &b)
  {
    return a.kind == b.kind && a.il_pc == b.il_pc;
  }
  friend bool operator!=(const ProgPoint &a, const ProgPoint &b) { return !(a == b); }
  friend bool operator<(const ProgPoint &a, const ProgPoint &b)
  {
    if ( a.kind != b.kind )
      return (uint8_t)a.kind < (uint8_t)b.kind;
    return a.il_pc < b.il_pc;
  }
};

// ---------------------------------------------------------------------------
// ProgramSummary
//
// A read-only summary of the program's CFG and per-instruction input/output locations.
// All public fields use ordered containers so iteration order is deterministic —
// `DataFlow::analyze` walks `predecessors`/`successors` in their set order to reach a
// stable worklist ordering.
struct ProgramSummary
{
  std::vector<unordered::UnorderedSet<ProgPoint>> predecessors;
  std::vector<unordered::UnorderedSet<ProgPoint>> successors;
  std::vector<size_t> fn_of_ilpc;
  std::vector<size_t> start_of_fn;
  std::vector<size_t> end_of_fn;
  std::vector<std::vector<std::optional<ASLocation>>> outputs;
  std::vector<std::vector<std::optional<ASLocation>>> inputs;
  std::vector<unordered::UnorderedSet<ASLocation>> all_variables_of_fn;
  /// Read-only program reference (mirrors upstream's `Rc<Program>`).
  std::shared_ptr<const Program> program;

  /// Compute a summary of `program`. Mirrors `ProgramSummary::compute_from`.
  static std::shared_ptr<const ProgramSummary> compute_from(std::shared_ptr<const Program> program);
};

// ---------------------------------------------------------------------------
// DataFlowElement
//
// Abstract base for a per-instruction dataflow element. Subclasses override the four
// virtuals to define a particular analysis. The framework talks to them only through
// these virtuals, so `DataFlow` can hold them as `std::unique_ptr<DataFlowElement>`
// without re-introducing templates.
//
// `clone()` returns a fresh heap-allocated copy whose dynamic type is exactly the
// subclass; this is the equivalent of upstream's `#[derive(Clone)]` plus the implicit
// deep copies that happen inside `outs`/`ins`.
class DataFlowElement
{
public:
  virtual ~DataFlowElement() = default;

  /// Construct a fresh, default element value (the "bottom" of the lattice).
  virtual std::unique_ptr<DataFlowElement> make_init() const = 0;

  /// The join operator: pull information from `other` into `*this`. Satisfies the
  /// property `a.join_from(a.make_init())` leaves `a` unmodified.
  virtual void join_from(const DataFlowElement &other) = 0;

  /// The initial value at the start of the function whose entry IL PC is `fn_start`.
  virtual std::unique_ptr<DataFlowElement> make_init_func_start(const ProgramSummary &summary,
                                                                size_t fn_start) const = 0;

  /// The transfer function for IL instruction `il_pc`.
  virtual std::unique_ptr<DataFlowElement> make_transfer_function(size_t il_pc,
                                                                  const ProgramSummary &summary) const = 0;

  /// Deep-copy hook.
  virtual std::unique_ptr<DataFlowElement> clone() const = 0;

  /// Equality hook used by the worklist to decide whether OUT changed.
  virtual bool equals(const DataFlowElement &other) const = 0;

protected:
  DataFlowElement() = default;
  DataFlowElement(const DataFlowElement &) = default;
  DataFlowElement(DataFlowElement &&) = default;
  DataFlowElement &operator=(const DataFlowElement &) = default;
  DataFlowElement &operator=(DataFlowElement &&) = default;
};

// ---------------------------------------------------------------------------
// DataFlow
//
// The result of running a forward worklist-based dataflow analysis over a single
// function. Upstream's `UnorderedMap<usize, T>` is realised here as
// `unordered::UnorderedMap<size_t, std::unique_ptr<DataFlowElement>>`.
//
// `DataFlow::analyze<T>` is the public entry point: callers pass the concrete subclass
// `T` (which must override `DataFlowElement`'s virtuals) and the framework
// instantiates one element per IL instruction in the function, runs the worklist, and
// returns the populated `DataFlow`.
class DataFlow
{
public:
  unordered::UnorderedMap<size_t, std::unique_ptr<DataFlowElement>> outs;
  unordered::UnorderedMap<size_t, std::unique_ptr<DataFlowElement>> ins;
  std::shared_ptr<const ProgramSummary> summary;
  std::shared_ptr<const Program> program;

  /// Run a forward worklist analysis over function `func_id`. Mirrors
  /// `DataFlow::<T>::forward_analyze` from upstream.
  template <typename T>
  static DataFlow analyze(const std::shared_ptr<const ProgramSummary> &program_summary,
                          size_t func_id)
  {
    static_assert(std::is_base_of_v<DataFlowElement, T>,
                  "DataFlow::analyze: T must derive from DataFlowElement");
    static_assert(std::is_default_constructible_v<T>,
                  "DataFlow::analyze: T must be default-constructible");

    const Program &program = *program_summary->program;

    // Seed: every IL PC in the function, in BB-order. Upstream uses
    //   `bbidxs.iter().flat_map(|&bb| program.basic_blocks[bb].iter()).cloned()`
    std::vector<size_t> func_il_addrs;
    func_il_addrs.reserve(program.functions[func_id].basic_blocks.size());
    for ( size_t bb : program.functions[func_id].basic_blocks )
    {
      for ( size_t ins : program.basic_blocks[bb] )
        func_il_addrs.push_back(ins);
    }

    DataFlow r;
    r.summary = program_summary;
    r.program = program_summary->program;

    // outs / ins are initially `make_init()` for every instruction in the function.
    for ( size_t il_addr : func_il_addrs )
    {
      r.outs.insert(il_addr, T{}.make_init());
      r.ins.insert(il_addr, T{}.make_init());
    }

    // Upstream uses `UnorderedSet<usize>` for the worklist seed, then collects it into
    // a `VecDeque`. We do the same: ordered set to dedupe, then FIFO worklist.
    std::set<size_t> seen;
    std::deque<size_t> changed;
    for ( size_t il_addr : func_il_addrs )
    {
      if ( seen.insert(il_addr).second )
        changed.push_back(il_addr);
    }

    while ( !changed.empty() )
    {
      const size_t n = changed.front();
      changed.pop_front();

      // Reset r.ins[n] back to a fresh make_init(); we will rejoin over predecessors.
      r.ins.insert(n, T{}.make_init());

      if ( r.summary->predecessors[n].is_empty() )
      {
        const Instruction &ins = r.summary->program->instructions[n];

        const bool is_branch_to_self_right_after_a_ud2 = [&]() -> bool {
          if ( ins.op.kind != OpKind::Branch )
            return false;
          const Variable &target = ins.inputs[0];
          if ( target.kind != VarKind::MachineAddress )
            return false;
          if ( target.addr != ins.address )
            return false;
          auto range = r.summary->program->get_il_addrs_for_machine_addr(ins.address);
          if ( !range.has_value() )
            return false;
          return r.summary->program->instructions[range->first].op.kind
                 == OpKind::ProcessorException;
        }();

        if ( ins.op.kind != OpKind::FunctionStart )
        {
          if ( !is_branch_to_self_right_after_a_ud2 )
          {
            log::debug("Non-FunctionStart instruction found to not have predecessor",
                       { { "ilpc", (size_t)n }, { "ins", ins.debug_string() } });
          }
        }

        if ( !is_branch_to_self_right_after_a_ud2 )
        {
          std::unique_ptr<DataFlowElement> init_val = T{}.make_init_func_start(*r.summary, n);
          r.ins.insert(n, std::move(init_val));
        }
      }
      else
      {
        // Upstream panic-checks that every predecessor is also inside the function.
        for ( const ProgPoint &pp : r.summary->predecessors[n].iter() )
        {
          if ( pp.kind != ProgPoint::Kind::Insn )
            continue;
          const DataFlowElement *out = r.outs.get(pp.il_pc)->get();
          if ( out == nullptr )
          {
            TREX_UNREACHABLE("Found predecessors outside the function");
          }
          r.ins.get_mut(n)->get()->join_from(*out);
        }
      }

      // OUT[n] = transfer_function applied to IN[n]. The transfer function is a *method* of the
      // current IN element (it reads that element'''s state, e.g. the reaching definitions), so it
      // must be invoked on the element itself, never on a freshly default-constructed one.
      std::unique_ptr<DataFlowElement> new_out =
          r.ins.get_mut(n)->get()->make_transfer_function(n, *r.summary);
      // Clone the old OUT for equality check (the map's `insert` overwrites the slot).
      std::unique_ptr<DataFlowElement> old_out;
      if ( auto *cur = r.outs.get_mut(n) )
      {
        old_out = std::move(*cur);
      }
      const bool changed_out = !old_out || !old_out->equals(*new_out);
      r.outs.insert(n, std::move(new_out));

      if ( changed_out )
      {
        for ( const ProgPoint &s : r.summary->successors[n].iter() )
        {
          TREX_CHECK(s.kind == ProgPoint::Kind::Insn,
                     "DataFlow::analyze: unexpected ProgPoint kind in successors");
          changed.push_back(s.il_pc);
        }
      }
    }

    return r;
  }

  /// Convenience overload matching upstream's `&Rc<...>` ergonomics.
  template <typename T>
  static DataFlow analyze(const std::shared_ptr<ProgramSummary> &program_summary,
                          size_t func_id)
  {
    return analyze<T>(std::const_pointer_cast<const ProgramSummary>(program_summary), func_id);
  }
};

} // namespace trex