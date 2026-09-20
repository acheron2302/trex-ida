// Transcribed unit tests for `Program::infer_structural_types`.
//
// Five tests are always-on (they require no c_types / serialize_structural
// support): tiny_program_inference, basic_type_inference,
// basic_pointer_type_inference, linked_list_inference,
// across_two_loads_inference. They mirror upstream
// `third_party/trex/trex/src/tests.rs` exactly (same hand-written IL
// programs, same expected results).
//
// The two C-type / printer tests (`c_types_for_linked_list_slot_1` and
// `c_types_for_linked_list_slot_2`) are gated on the Output-agent
// dependency. Define `TREX_HAVE_OUTPUT_TYPES=1` when the c_types /
// serialize_structural / c_type_printer modules are in place to enable
#include "harness.hpp"
#include <trex/structural.hpp>
#include <trex/pipeline.hpp>

#include <trex/aggregate_types.hpp>
#include <trex/c_type_printer.hpp>
#include <trex/il.hpp>
#include <trex/lifted_frontend.hpp>
#include <trex/serialize_structural.hpp>
#include <trex/starts_at_analysis.hpp>
#include <trex/structural.hpp>
#include <trex/type_rounding.hpp>

#include <cstddef>
#include <fstream>
#include <memory>
#include <sstream>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace {

// Helper: build a tiny Program.
std::shared_ptr<trex::Program> make_tiny_program()
{
  using namespace trex;
  std::vector<AddressSpace> as = {
    AddressSpace{ "ram", Endian::Little, 1 },
    AddressSpace{ "as1", Endian::Little, 1 },
  };
  Program prog = Program::create(std::move(as));

  prog.begin_function("tiny_program", {}, 0);

  prog.add_one_machine_instruction({
    Instruction{
      /*address=*/ 0,
      Op(OpKind::Copy),
      Variable::varnode(/*as_idx=*/ 0, /*offset=*/ 0, /*size=*/ 1),
      {
        Variable::varnode(/*as_idx=*/ 1, /*offset=*/ 1, /*size=*/ 1),
        Variable::unused(),
      },
      /*indirect_targets=*/ {}
    }
  });

  prog.add_one_machine_instruction({
    Instruction{
      /*address=*/ 1,
      Op(OpKind::IntSub),
      Variable::varnode(/*as_idx=*/ 1, /*offset=*/ 3, /*size=*/ 1),
      {
        Variable::varnode(/*as_idx=*/ 1, /*offset=*/ 2, /*size=*/ 1),
        Variable::constant(/*value=*/ 4, /*size=*/ 1),
      },
      /*indirect_targets=*/ {}
    }
  });

  prog.end_function();
  return std::make_shared<Program>(std::move(prog));
}

std::shared_ptr<trex::Program> make_basic_program()
{
  using namespace trex;
  std::vector<AddressSpace> as = {
    AddressSpace{ "RAM", Endian::Little, 8 },
  };
  Program prog = Program::create(std::move(as));
  prog.begin_function("basic_program", {}, 0);

  for ( int i = 0; i < 2; ++i )
  {
    Variable out = Variable::varnode(0, i == 0 ? 0 : 123, 22);
    prog.add_one_machine_instruction({
      Instruction{
        /*address=*/ (uint64_t)i,
        Op(OpKind::Copy),
        out,
        {
          Variable::varnode(0, 456, 22),
          Variable::unused(),
        },
        {}
      }
    });
  }

  prog.end_function();
  return std::make_shared<Program>(std::move(prog));
}

std::shared_ptr<trex::Program> make_basic_pointer_program()
{
  using namespace trex;
  std::vector<AddressSpace> as = {
    AddressSpace{ "RAM", Endian::Little, 8 },
  };
  Program prog = Program::create(std::move(as));
  prog.begin_function("basic_pointer_program", {}, 0);

  for ( int i = 0; i < 2; ++i )
  {
    prog.add_one_machine_instruction({
      Instruction{
        /*address=*/ (uint64_t)i,
        Op(OpKind::Load),
        Variable::varnode(0, i == 0 ? 0 : 123, 22),
        {
          Variable::deref_varnode(
              /*derefval_as=*/ 0, /*derefval_sz=*/ 22,
              /*addr_as=*/ 0, /*addr_off=*/ 456),
          Variable::unused(),
        },
        {}
      }
    });
  }

  prog.end_function();
  return std::make_shared<Program>(std::move(prog));
}

std::shared_ptr<trex::Program> make_linked_list_slot1_program()
{
  using namespace trex;
  std::vector<AddressSpace> as = {
    AddressSpace{ "ram", Endian::Little, 8 },
    AddressSpace{ "temp", Endian::Little, 8 },
  };
  Program prog = Program::create(std::move(as));

  Variable var_temp        = Variable::varnode(1, 0, 8);
  Variable deref_var_temp4 = Variable::deref_varnode(0, 4, 1, 0);
  Variable var_p           = Variable::varnode(0, 0, 8);
  Variable deref_var_p_next= Variable::deref_varnode(0, 8, 0, 0);
  Variable var_x           = Variable::varnode(0, 100, 4);

  prog.begin_function("linked_list_slot1", {}, 0);
  prog.add_one_machine_instruction({
    Instruction{ 0, Op(OpKind::Load), var_temp,        { deref_var_p_next, Variable::unused() }, {} },
    Instruction{ 0, Op(OpKind::Cbranch), Variable::unused(),
                 { Variable::machine_address(1), var_temp }, {} },
    Instruction{ 0, Op(OpKind::Branch),   Variable::unused(),
                 { Variable::machine_address(100), Variable::unused() }, {} },
  });
  prog.add_one_machine_instruction({
    Instruction{ 1, Op(OpKind::Copy), var_p, { var_temp, Variable::unused() }, {} },
  });
  prog.add_one_machine_instruction({
    Instruction{ 2, Op(OpKind::Branch), Variable::unused(),
                 { Variable::machine_address(0), Variable::unused() }, {} },
  });
  prog.add_one_machine_instruction({
    Instruction{ 100, Op(OpKind::IntAdd), var_temp,
                 { var_p, Variable::constant(8, 8) }, {} },
    Instruction{ 100, Op(OpKind::Load),  var_x,
                 { deref_var_temp4, Variable::unused() }, {} },
  });
  prog.end_function();
  return std::make_shared<Program>(std::move(prog));
}

// Upstream's `across_two_loads()` lifts the inline textual listing below through
// `ghidra_lifter::lift_from`; this port runs the same text through the reference frontend so the
// test exercises exactly the same path.
std::shared_ptr<trex::Program> make_across_two_loads_program()
{
  static const char *kLifted = "\
PROGRAM\n\
name across_two_loads\n\
big_endian false\n\
\n\
ADDRESS_SPACES\n\
        0 ram 8\n\
\n\
PCODE_LISTING\n\
        00100000 loadtwiceFromSameReg\n\
                Unaffected:\n\
                00100000 (register, 0xaa, 8) LOAD (const, 0x0, 4) , (register, 0x80, 8)\n\
                00100000 (register, 0xbb, 8) LOAD (const, 0x0, 4) , (register, 0x80, 8)\n\
\n\
        00200000 loadtwiceFromCopiedSameAddr\n\
                Unaffected:\n\
                00200000 (register, 0x90, 8) COPY (register, 0x80, 8)\n\
                00200000 (register, 0xaa, 8) LOAD (const, 0x0, 4) , (register, 0x80, 8)\n\
                00200000 (register, 0xbb, 8) LOAD (const, 0x0, 4) , (register, 0x90, 8)\n\
\n\
        00300000 loadtwiceFromSameCalculatedAddr\n\
                Unaffected:\n\
                00300000 (register, 0x20, 8) INT_ADD (register, 0x80, 8) , (const, 0x5, 8)\n\
                00300000 (register, 0x30, 8) INT_ADD (register, 0x80, 8) , (const, 0x5, 8)\n\
                00300000 (register, 0xaa, 8) LOAD (const, 0x0, 4) , (register, 0x20, 8)\n\
                00300000 (register, 0xbb, 8) LOAD (const, 0x0, 4) , (register, 0x30, 8)\n";

  return trex::lift_program_from_lifted_text(kLifted);
}

}  // namespace

// ---------------------------------------------------------------------------
// Test bodies.
// ---------------------------------------------------------------------------

TEST(tiny_program_inference)
{
  auto prog = make_tiny_program();
  auto types = trex::infer_structural_types(prog);

  // SSA layout: [FunctionStart=0, copy=1, sub=2, FunctionEnd=3]
  auto o0 = types.ssa->get_output_impacted_variable(1).value();
  auto o1 = types.ssa->get_input_variable(1, 0);
  auto o2 = types.ssa->get_input_variable(2, 0);
  auto o3 = types.ssa->get_output_impacted_variable(2).value();

  CHECK(o0 != o1);
  CHECK(o0 != o2);
  CHECK(o0 != o3);
  CHECK(o1 != o2);
  CHECK(o1 != o3);
  CHECK(o2 != o3);

  auto i0 = types.get_type_index(o0).value();
  auto i1 = types.get_type_index(o1).value();
  auto i2 = types.get_type_index(o2).value();
  auto i3 = types.get_type_index(o3).value();

  const auto *t0 = types.get_type_from_index(i0);
  const auto *t1 = types.get_type_from_index(i1);
  const auto *t2 = types.get_type_from_index(i2);
  const auto *t3 = types.get_type_from_index(i3);

  CHECK_EQ(t0->observed_size(), std::optional<std::size_t>(1));
  CHECK_EQ(t1->observed_size(), std::optional<std::size_t>(1));
  CHECK_EQ(t2->observed_size(), std::optional<std::size_t>(1));
  CHECK_EQ(t3->observed_size(), std::optional<std::size_t>(1));

  CHECK(types.are_equal_at_indexes(i0, i1));

  CHECK(t2->integer_ops.count({ trex::IntegerOp::Sub, 1 }) != 0);
  CHECK(t3->integer_ops.count({ trex::IntegerOp::Sub, 1 }) != 0);
}

TEST(basic_type_inference)
{
  auto prog = make_basic_program();
  auto types = trex::infer_structural_types(prog);

  auto v_at_456 = types.ssa->get_input_variable(1, 0);
  CHECK(v_at_456 == types.ssa->get_input_variable(2, 0));

  auto v_at_0   = types.ssa->get_output_impacted_variable(1).value();
  auto v_at_123 = types.ssa->get_output_impacted_variable(2).value();

  auto idx0   = types.get_type_index(v_at_0).value();
  auto idx456 = types.get_type_index(v_at_456).value();
  auto idx123 = types.get_type_index(v_at_123).value();

  CHECK(types.are_equal_at_indexes(idx0, idx456));
  CHECK(types.are_equal_at_indexes(idx0, idx123));

  auto loc0 = types.get_type_index(v_at_0).value();
  CHECK_EQ(types.get_type_from_index(loc0)->observed_size(),
           std::optional<std::size_t>(22));
}

TEST(basic_pointer_type_inference)
{
  auto prog = make_basic_pointer_program();
  auto types = trex::infer_structural_types(prog);

  auto v_at_456 = types.ssa->get_input_variable(1, 0);
  CHECK(v_at_456 == types.ssa->get_input_variable(2, 0));

  auto v_at_0   = types.ssa->get_output_impacted_variable(1).value();
  auto v_at_123 = types.ssa->get_output_impacted_variable(2).value();

  auto idx0   = types.get_type_index(v_at_0).value();
  auto idx123 = types.get_type_index(v_at_123).value();

  CHECK(types.are_equal_at_indexes(idx0, idx123));

  auto loc0 = types.get_type_index(v_at_0).value();
  CHECK_EQ(types.get_type_from_index(loc0)->observed_size(),
           std::optional<std::size_t>(22));

  auto loc456 = types.get_type_index(v_at_456).value();
  CHECK(types.get_type_from_index(loc456)->pointer_to.has_value());
  CHECK(types.are_equal_at_indexes(
      loc0, types.get_type_from_index(loc456)->pointer_to.value()));
}

TEST(linked_list_inference)
{
  auto prog = make_linked_list_slot1_program();
  auto types = trex::infer_structural_types(prog);

  auto var_p      = types.ssa->get_input_variable(1, 0);
  auto var_temp1  = types.ssa->get_input_variable(2, 1);
  CHECK(types.ssa->get_input_variable(4, 0) == var_temp1);
  CHECK(types.ssa->get_input_variable(6, 0) == var_p);
  auto var_temp2  = types.ssa->get_input_variable(7, 0);
  CHECK(var_temp1 != var_temp2);
  CHECK(types.ssa->get_output_impacted_variable(6) == var_temp2);
  auto var_x      = types.ssa->get_output_impacted_variable(7).value();

  auto i_p     = types.get_type_index(var_p).value();
  auto i_temp1 = types.get_type_index(var_temp1).value();
  auto i_temp2 = types.get_type_index(var_temp2).value();
  auto i_x     = types.get_type_index(var_x).value();

  const auto *t_p     = types.get_type_from_index(i_p);
  const auto *t_temp2 = types.get_type_from_index(i_temp2);
  const auto *t_x     = types.get_type_from_index(i_x);

  auto i_p_deref = t_p->pointer_to.value();

  CHECK(types.are_equal_at_indexes(i_p_deref, i_temp1));
  CHECK(types.are_equal_at_indexes(i_p_deref, i_p));
  CHECK(types.are_equal_at_indexes(i_p, i_temp1));

  CHECK_EQ(t_p->observed_size(),     std::optional<std::size_t>(8));
  CHECK_EQ(t_temp2->observed_size(), std::optional<std::size_t>(8));
  CHECK_EQ(t_x->observed_size(),     std::optional<std::size_t>(4));

  CHECK(t_p->integer_ops.count({ trex::IntegerOp::Add, 8 }) != 0);
  CHECK(t_p->zero_comparable);
  CHECK(t_p->integer_ops.count({ trex::IntegerOp::Eq, 8 }) != 0);
  CHECK(t_temp2->integer_ops.count({ trex::IntegerOp::Add, 8 }) != 0);
}

TEST(across_two_loads_inference)
{
  auto prog = make_across_two_loads_program();
  auto types = trex::infer_structural_types(prog);

  auto output_at = [&](size_t pc)
  {
    return types.ssa->get_output_impacted_variable(pc).value();
  };
  auto same_at = [&](size_t a, size_t b)
  {
    return types.are_equal_at_indexes(
        types.get_type_index(output_at(a)).value(),
        types.get_type_index(output_at(b)).value());
  };

  CHECK(same_at(1, 2));
  CHECK(same_at(6, 7));
  CHECK(same_at(12, 13));
}

// ---------------------------------------------------------------------------
// End-to-end C-type tests (upstream `c_types_for_linked_list_slot_{1,2}`).
//
// These run the shipped Ghidra fixtures through the *reference* frontend, the full inference
// pipeline (structural -> co-location -> aggregates -> type rounding) and the C printer, and
// compare the whitespace-normalised output with the expected text.
// ---------------------------------------------------------------------------

namespace {

std::string read_text_file(const std::string &path)
{
  std::ifstream f(path, std::ios::binary);
  if ( !f )
    throw std::runtime_error("could not read " + path);
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

std::string fixture_path(const char *name)
{
  return std::string(TREX_FIXTURE_DIR) + "/" + name;
}

/// Whitespace-insensitive comparison, exactly as upstream does with `split_whitespace`.
std::vector<std::string> whitespace_tokens(const std::string &s)
{
  std::vector<std::string> tokens;
  std::istringstream is(s);
  std::string tok;
  while ( is >> tok )
    tokens.push_back(tok);
  return tokens;
}

std::string c_types_for_fixture(const char *stem)
{
  std::shared_ptr<trex::Program> prog
    = trex::lift_program_from_lifted_text(read_text_file(fixture_path((std::string(stem) + ".lifted").c_str())));
  trex::ILVariableMap vars
    = trex::lift_variable_map_from_vars_text(read_text_file(fixture_path((std::string(stem) + ".vars").c_str())), prog);

  trex::StructuralTypes types = trex::infer_structural_types(prog);
  std::shared_ptr<trex::StructuralTypes> inferred
    = std::make_shared<trex::StructuralTypes>(std::move(types));
  std::shared_ptr<trex::CoLocated> colocated
    = std::make_shared<trex::CoLocated>(trex::CoLocated::analyze(inferred));
  trex::AggregateTypes aggregate = trex::AggregateTypes::analyze(colocated);
  trex::StructuralTypes structured = aggregate.to_structural_types();

  trex::SerializableStructuralTypes<trex::ExternalVariable> serializable
    = trex::serialize_structural_types(structured, std::optional<trex::ILVariableMap>(vars));
  trex::round_up_to_c_types(serializable.types_mut());

  trex::PrintableCTypes<trex::ExternalVariable> printer(serializable);
  return printer.to_string();
}

void check_c_types_for_fixture(const char *stem, const char *expected)
{
  const std::string got = c_types_for_fixture(stem);
  const std::vector<std::string> a = whitespace_tokens(got);
  const std::vector<std::string> b = whitespace_tokens(expected);
  if ( a != b )
  {
    std::string diff = "C-like output mismatch for ";
    diff += stem;
    diff += "\n--- expected ---\n";
    diff += expected;
    diff += "\n--- got ---\n";
    diff += got;
    throw std::runtime_error(diff);
  }
}

} // namespace

TEST(c_types_for_linked_list_slot_1)
{
  check_c_types_for_fixture("test-linked-list-slot1",
                            "// n@getlast@00100000 : t1*\n"
                            "// nxt@getlast@00100000 : t1*\n"
                            "\n"
                            "struct t1 {\n"
                            "  t1* field_0;\n"
                            "  int32_t field_8;\n"
                            "};\n");
}

TEST(c_types_for_linked_list_slot_2)
{
  check_c_types_for_fixture("test-linked-list-slot2",
                            "// n@getlast@00100000 : t1*\n"
                            "// nxt@getlast@00100000 : t1*\n"
                            "\n"
                            "struct t1 {\n"
                            "  int32_t field_0;\n"
                            "  t1* field_8;\n"
                            "};\n");
}

// ---------------------------------------------------------------------------
// Single-TU test runner.
// ---------------------------------------------------------------------------

int main()
{
  return trex_test::run_all();
}
