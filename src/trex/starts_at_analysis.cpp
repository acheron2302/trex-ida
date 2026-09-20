// Implementation of `starts_at_analysis` (port of upstream
// `trex/src/starts_at_analysis.rs`).
//
// The algorithm:
//   1. Initial worklist: every Load's `output_impacted_variable` and every
//      Store's `input[1]`, paired with the Load/Store's address input.
//   2. Pop a worklist element; if its (val, il_pcs ∪ reasons) has already
//      been processed, skip; otherwise add the obvious `OffsetDeref(0)`
//      for the current Load/Store and look at every instruction that
//      immediately affects the current `ptr` value.
//   3. If that affecting instruction is `IntAdd`/`IntSub`, check whether
//      either side is a compile-time constant (via `ssa.is_effectively_constant`
//      AND `ConstFolded::input_at`); depending on which side is constant and
//      which side is the pointer, emit either `OffsetDeref` or
//      `NonConstantOffsetDeref` and schedule the new base pointer for
//      further walking.
//
// `ssa::Variable` is a value type with copy semantics — we copy it by
// passing it by value or by reference; no `clone()` exists.

#include <trex/starts_at_analysis.hpp>

#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <trex/constant_folding.hpp>
#include <trex/containers.hpp>
#include <trex/dataflow.hpp>
#include <trex/il.hpp>
#include <trex/log.hpp>
#include <trex/ssa.hpp>
#include <trex/structural.hpp>

namespace trex {

namespace {

// A worklist element. Mirrors the Rust `WorklistElement` struct exactly.
struct WorklistElement
{
  size_t il_pc = 0;
  ssa::Variable ptr;
  ssa::Variable val;
  std::vector<size_t> reason;
};

} // namespace

std::string Constraint::debug_string() const
{
  if (kind == Kind::OffsetDeref) {
    return "OffsetDeref { t: " + t.debug_string() + ", offset: " + std::to_string(offset)
           + ", base_ptr: " + base_ptr.debug_string() + " }";
  }
  return "NonConstantOffsetDeref { t: " + t.debug_string() + ", offset: " + offset_var.debug_string()
         + ", base_ptr: " + base_ptr.debug_string() + " }";
}

std::string CoLocated::debug_string() const
{
  std::string out = "CoLocated { constraints: {";
  bool first = true;
  for (const auto &[c, _] : constraints.iter()) {
    if (!first) out += ", ";
    first = false;
    out += c.debug_string();
  }
  out += "} }";
  return out;
}

// ---------------------------------------------------------------------------
// Initial worklist population
//
// Mirrors `initial_worklist_elements_at`: a Store emits one element whose
// pointee is `input[1]`; a Load emits one element per SSA output variable
// produced by the Load.
// ---------------------------------------------------------------------------
static std::vector<WorklistElement>
initial_worklist_elements_at(const CoLocated &self, size_t il_pc)
{
  const auto &ssa = *self.structural_types->ssa;
  const Instruction &ins = ssa.program->instructions[il_pc];

  std::vector<WorklistElement> out;
  if (ins.op.kind == OpKind::Store) {
    out.push_back(WorklistElement{
        /*il_pc=*/il_pc,
        /*ptr=*/ssa.get_input_variable(il_pc, 0),
        /*val=*/ssa.get_input_variable(il_pc, 1),
        /*reason=*/{},
    });
  } else if (ins.op.kind == OpKind::Load) {
    auto out_var = ssa.get_output_impacted_variable(il_pc);
    if (out_var.has_value()) {
      out.push_back(WorklistElement{
          /*il_pc=*/il_pc,
          /*ptr=*/ssa.get_input_variable(il_pc, 0),
          /*val=*/*out_var,
          /*reason=*/{},
      });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// analyze_instruction_at
//
// Walks the current Load/Store's address back through any IntAdd/IntSub that
// immediately affects it. Records the obvious `OffsetDeref(0)` for the
// current Load/Store; then, if the affecting instruction is an integer
// add/sub with exactly one constant operand, records the resulting
// `OffsetDeref` (constant offset) or `NonConstantOffsetDeref` (dynamic
// offset from a non-pointer constant base) and recurses on the new base
// pointer.
// ---------------------------------------------------------------------------
static void analyze_instruction_at(CoLocated &self, WorklistElement wle,
                                   std::deque<WorklistElement> &worklist)
{
  const auto &ssa = *self.structural_types->ssa;

  // Add the immediately obvious constraint, visible from the deref.
  if (ssa.program->instructions[wle.il_pc].op.kind == OpKind::Load
      || ssa.program->instructions[wle.il_pc].op.kind == OpKind::Store) {
    Constraint c = Constraint::offset_deref(wle.val, 0, wle.ptr);
    auto entry = self.constraints.entry(std::move(c));
    auto &set = entry.or_default();
    for (size_t r : wle.reason) {
      set.insert(r);
    }
    set.insert(wle.il_pc);
  }

  // Add constraints due to second-order effects.
  const std::vector<size_t> affecting
      = ssa.get_all_immediately_affecting_instructions(wle.ptr);

  for (size_t affecting_il_pc : affecting) {
    const Instruction &ins = ssa.program->instructions[affecting_il_pc];
    if (ins.op.kind != OpKind::IntAdd && ins.op.kind != OpKind::IntSub) {
      continue; // do nothing
    }

    const int64_t m = (ins.op.kind == OpKind::IntAdd) ? 1 : -1;
    ssa::Variable a = ssa.get_input_variable(affecting_il_pc, 0);
    ssa::Variable b = ssa.get_input_variable(affecting_il_pc, 1);

    bool is_a_const = ssa.is_effectively_constant(a);
    bool is_b_const = ssa.is_effectively_constant(b);

    struct Result
    {
      Constraint constraint;
      bool have_new_ptr = false;
      ssa::Variable new_ptr;
    };
    std::optional<Result> rres;

    if ((!is_a_const && is_b_const) || (is_a_const && !is_b_const)) {
      // Only one side is a constant — likely a struct-like dereference.
      const size_t c_posn = is_a_const ? 0 : 1;
      std::optional<uint64_t> c_opt = self.constant_folding->input_at(affecting_il_pc, c_posn);
      if (!c_opt.has_value()) {
        log::debug("Effectively-constant and constant-folding disagree. Ignoring.",
                   {{"affecting_il_pc", affecting_il_pc},
                    {"c_posn", c_posn},
                    {"ins_op_kind", (int)ins.op.kind}});
        continue;
      }
      const int64_t c = static_cast<int64_t>(*c_opt);
      ssa::Variable basev = is_a_const ? b : a;

      const StructuralType *baset = self.structural_types->get_type_of(basev);
      TREX_CHECK(baset != nullptr, "starts_at_analysis: missing structural type for base variable");
      if (baset->pointer_to.has_value()) {
        // `basev` is a pointer
        Result res;
        res.constraint = Constraint::offset_deref(wle.val, c * m, basev);
        res.have_new_ptr = true;
        res.new_ptr = basev;
        rres = std::move(res);
      } else {
        // The constant is the pointer, and we have a non-constant
        // dereference from it (likely an array at that constant).
        Result res;
        ssa::Variable offset_v = basev;
        ssa::Variable base_ptr_v = ssa::Variable::constant_value(
            ProgPoint::insn(affecting_il_pc), c_posn, static_cast<uint64_t>(c));
        res.constraint = Constraint::non_constant_offset_deref(wle.val, std::move(offset_v),
                                                               std::move(base_ptr_v));
        res.have_new_ptr = false;
        rres = std::move(res);
      }
    } else if (is_a_const && is_b_const) {
      std::optional<uint64_t> ca = self.constant_folding->input_at(affecting_il_pc, 0);
      std::optional<uint64_t> cb = self.constant_folding->input_at(affecting_il_pc, 1);
      log::info("TODO: Both sides effectively constant, should be calculating constant here?",
                {{"ilpc", affecting_il_pc},
                 {"op_kind", (int)ins.op.kind},
                 {"const_a", ca.has_value() ? (int64_t)*ca : (int64_t)-1},
                 {"const_b", cb.has_value() ? (int64_t)*cb : (int64_t)-1}});
      continue;
    } else {
      // Both non-constant — array-like dereference.
      const StructuralType *a_t = self.structural_types->get_type_of(a);
      const StructuralType *b_t = self.structural_types->get_type_of(b);
      TREX_CHECK(a_t != nullptr && b_t != nullptr,
                 "starts_at_analysis: missing structural types for non-constant addends");

      std::optional<ssa::Variable> base_ptr;
      ssa::Variable offset_v;
      if (a_t->pointer_to.has_value() && !b_t->pointer_to.has_value()) {
        base_ptr = a;
        offset_v = b;
      } else if (!a_t->pointer_to.has_value() && b_t->pointer_to.has_value()) {
        base_ptr = b;
        offset_v = a;
      } else if (a_t->pointer_to.has_value() && b_t->pointer_to.has_value()) {
        log::debug("Both pointer variables",
                   {{"ilpc", affecting_il_pc}, {"op_kind", (int)ins.op.kind}});
        continue;
      } else {
        log::debug("Both non-pointer variables",
                   {{"ilpc", affecting_il_pc}, {"op_kind", (int)ins.op.kind}});
        continue;
      }
      Result res;
      ssa::Variable bp = *base_ptr;
      res.constraint = Constraint::non_constant_offset_deref(wle.val, std::move(offset_v), bp);
      res.have_new_ptr = true;
      res.new_ptr = bp;
      rres = std::move(res);
    }

    if (!rres.has_value())
      continue;

    Result &r = *rres;
    {
      auto entry = self.constraints.entry(std::move(r.constraint));
      auto &set = entry.or_default();
      for (size_t x : wle.reason) {
        set.insert(x);
      }
      set.insert(wle.il_pc);
      set.insert(affecting_il_pc);
    }
    if (r.have_new_ptr) {
      std::vector<size_t> new_reason = std::move(wle.reason);
      new_reason.push_back(wle.il_pc);
      worklist.push_back(WorklistElement{
          /*il_pc=*/affecting_il_pc,
          /*ptr=*/std::move(r.new_ptr),
          /*val=*/std::move(wle.val),
          /*reason=*/std::move(new_reason),
      });
    }
  }
}

// ---------------------------------------------------------------------------
// CoLocated::analyze
//
// Two-pass: collect every initial worklist element by walking the program
// in instruction order (upstream uses `flat_map(|(i, _ins)| …)` so the
// iteration order is `instructions.iter().enumerate()` — we replicate that
// exactly). Then drain the worklist with the seen-set dedup.
// ---------------------------------------------------------------------------
CoLocated CoLocated::analyze(const std::shared_ptr<StructuralTypes> &structural_types)
{
  CoLocated r;
  r.structural_types = structural_types;
  r.constant_folding = ConstFolded::from_ssa(structural_types->ssa);

  std::deque<WorklistElement> worklist;
  const auto &program = structural_types->ssa->program;
  for (size_t i = 0; i < program->instructions.size(); ++i) {
    auto elems = initial_worklist_elements_at(r, i);
    for (auto &e : elems) {
      worklist.push_back(std::move(e));
    }
  }

  // XXX: Is this sane? Will we miss anything by doing this?
  // (preserved from upstream verbatim)
  std::map<ssa::Variable,
           std::pair<unordered::UnorderedSet<size_t>, unordered::UnorderedSet<size_t>>>
      seen;

  while (!worklist.empty()) {
    WorklistElement args = std::move(worklist.front());
    worklist.pop_front();

    bool seen_before = true;
    auto seen_it = seen.find(args.val);
    if (seen_it == seen.end()) {
      seen_before = false;
      seen.emplace(args.val, std::make_pair(unordered::UnorderedSet<size_t>{},
                                            unordered::UnorderedSet<size_t>{}));
      seen_it = seen.find(args.val);
    }
    auto &pc_set = seen_it->second.first;
    auto &re_set = seen_it->second.second;
    if (pc_set.insert(args.il_pc)) {
      seen_before = false;
    }
    for (size_t rr : args.reason) {
      if (re_set.insert(rr)) {
        seen_before = false;
      }
    }
    if (seen_before) {
      continue;
    }

    analyze_instruction_at(r, std::move(args), worklist);
  }

  return r;
}

std::vector<ssa::Variable> CoLocated::get_aggregate_base_variables() const
{
  std::set<ssa::Variable> seen;
  for (const auto &[c, _] : constraints.iter()) {
    if (c.kind == Constraint::Kind::OffsetDeref) {
      if (c.offset != 0) {
        seen.insert(c.base_ptr);
      }
    } else {
      seen.insert(c.base_ptr);
    }
  }
  std::vector<ssa::Variable> out;
  out.reserve(seen.size());
  for (const auto &v : seen) {
    out.push_back(v);
  }
  return out;
}

} // namespace trex