// Unit tests for the native-type planner (src/plugin/type_plan.cpp).
//
// Every case here builds a small structural type by hand, runs it through the real printer
// (which is what rounds the types to C primitives and issues the `tN` names) and then through
// `plan::build_plan`, so the assertions are about the pipeline the plugin actually runs.
//
// The shapes below are chosen to pin the behaviour the old text round trip got wrong: offsets
// are the bytes the printer wrote (decimal), unrepresentable members become gaps with an exact
// extent instead of being dropped, floats and the other widened scalars stay real members, and
// unions/flexible arrays keep their shape.

#include "harness.hpp"

#include <cstddef>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include <trex/aggregate_types.hpp>
#include <trex/c_type_printer.hpp>
#include <trex/il.hpp>
#include <trex/lifted_frontend.hpp>
#include <trex/pipeline.hpp>
#include <trex/serialize_structural.hpp>
#include <trex/starts_at_analysis.hpp>
#include <trex/structural.hpp>
#include <trex/type_rounding.hpp>

#include "plugin/trex_window.hpp"
#include "plugin/type_plan.hpp"

namespace
{

using trex::Container;
using trex::ExternalVariable;
using trex::FloatOp;
using trex::Index;
using trex::IndexMap;
using trex::IntegerOp;
using trex::PrintableCTypes;
using trex::SerializableStructuralTypes;
using trex::StructuralType;

using trexida::plan::PlannedAggregate;
using trexida::plan::PlannedMember;
using trexida::plan::TypePlan;

/// A type that only ever had `size` bytes copied.
StructuralType sized(std::size_t size)
{
  StructuralType t;
  t.upper_bound_size = size;
  t.copy_sizes.insert(size);
  return t;
}

/// A type seen doing `size`-byte integer arithmetic.
StructuralType int_of(std::size_t size)
{
  StructuralType t = sized(size);
  t.integer_ops.insert({ IntegerOp::Add, size });
  return t;
}

/// A type seen doing `size`-byte floating arithmetic.
StructuralType float_of(std::size_t size)
{
  StructuralType t = sized(size);
  t.float_ops.insert({ FloatOp::Add, size });
  return t;
}

/// Everything a case built, ready to be planned.
struct Fixture
{
  SerializableStructuralTypes<ExternalVariable> stypes;
  PrintableCTypes<ExternalVariable> printer;
  explicit Fixture(std::map<ExternalVariable, Index> varmap, Container<StructuralType> types)
    : stypes(std::move(varmap), IndexMap<std::string>(), std::move(types))
    , printer(stypes)
  {
  }

  TypePlan plan() const { return trexida::plan::build_plan(stypes, printer, 8); }
};

const PlannedAggregate *find_aggregate(const TypePlan &plan, const std::string &name)
{
  for ( const PlannedAggregate &a : plan.aggregates )
    if ( a.name == name )
      return &a;
  return nullptr;
}

const PlannedMember *find_member(const PlannedAggregate &agg, const std::string &name)
{
  for ( const PlannedMember &m : agg.members )
    if ( m.name == name )
      return &m;
  return nullptr;
}

/// Read a fixture file into memory (mirrors the helper the printer tests use).
std::string read_text_file(const std::string &path)
{
  std::ifstream f(path, std::ios::binary);
  if ( !f )
    throw std::runtime_error("could not read " + path);
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

/// The plan of the .lifted fixture the plugin's own e2e and the differential oracle use.
SerializableStructuralTypes<ExternalVariable> linked_list_fixture()
{
  std::shared_ptr<trex::Program> prog = trex::lift_program_from_lifted_text(
    read_text_file(std::string(TREX_FIXTURE_DIR) + "/test-linked-list-slot1.lifted"));
  trex::ILVariableMap vars = trex::lift_variable_map_from_vars_text(
    read_text_file(std::string(TREX_FIXTURE_DIR) + "/test-linked-list-slot1.vars"), prog);

  trex::StructuralTypes types = trex::infer_structural_types(prog);
  std::shared_ptr<trex::StructuralTypes> inferred =
    std::make_shared<trex::StructuralTypes>(std::move(types));
  std::shared_ptr<trex::CoLocated> colocated =
    std::make_shared<trex::CoLocated>(trex::CoLocated::analyze(inferred));
  trex::AggregateTypes aggregate = trex::AggregateTypes::analyze(colocated);
  trex::StructuralTypes structured = aggregate.to_structural_types();

  SerializableStructuralTypes<ExternalVariable> serializable
    = trex::serialize_structural_types(structured, std::optional<trex::ILVariableMap>(vars));
  trex::round_up_to_c_types(serializable.types_mut());
  return serializable;
}

} // namespace

// ---------------------------------------------------------------------------
// Offsets
// ---------------------------------------------------------------------------

TEST(plan_member_offsets_are_decimal)
{
  // A struct with members at 0, 8 and 16. The old text path decoded the `field_16` suffix with
  // strtoull(..., 16) and placed that member at 22 bytes; the planner reads the byte offsets the
  // printer actually stored.
  Container<StructuralType> types;
  Index f4 = types.insert(float_of(4));
  Index i16 = types.insert(int_of(16));
  StructuralType agg = sized(24);
  agg.colocated_struct_fields[8] = f4;
  agg.colocated_struct_fields[16] = i16;
  Index a = types.insert(agg);

  Fixture fx({ { ExternalVariable("v@f@00001000"), a } }, std::move(types));
  const TypePlan plan = fx.plan();

  const PlannedAggregate *t1 = find_aggregate(plan, "t1");
  CHECK(t1 != nullptr);
  CHECK_EQ(find_member(*t1, "field_8")->offset, (std::size_t)8);
  CHECK_EQ(find_member(*t1, "field_16")->offset, (std::size_t)16);

  // Offsets are strictly ascending and no member is placed by a hex-decoded name.
  for ( std::size_t i = 1; i < t1->members.size(); ++i )
    CHECK(t1->members[i - 1].offset < t1->members[i].offset);
}

TEST(plan_preserves_later_offsets)
{
  // 0 (real), 8 (gap: `void`), 16 (real). The gap must not shift the third member.
  Container<StructuralType> types;
  Index blank = types.insert(StructuralType());
  Index i4 = types.insert(int_of(4));
  StructuralType agg = sized(8);
  agg.integer_ops.insert({ IntegerOp::Add, 8 });
  agg.colocated_struct_fields[8] = blank;
  agg.colocated_struct_fields[16] = i4;
  Index a = types.insert(agg);

  Fixture fx({ { ExternalVariable("v@f@00001000"), a } }, std::move(types));
  const TypePlan plan = fx.plan();

  const PlannedAggregate *t1 = find_aggregate(plan, "t1");
  CHECK(t1 != nullptr);
  CHECK_EQ(t1->members.size(), (std::size_t)3);
  CHECK_EQ(t1->members[0].offset, (std::size_t)0);
  CHECK_EQ(t1->members[0].is_gap, false);
  CHECK_EQ(t1->members[1].offset, (std::size_t)8);
  CHECK_EQ(t1->members[1].is_gap, true);
  CHECK_EQ(t1->members[2].offset, (std::size_t)16);
  CHECK_EQ(t1->members[2].is_gap, false);
}

TEST(plan_fixture_offsets_are_decimal)
{
  // The same property on the fixture the plugin ships: `struct t1 { t1* field_0; int32_t
  // field_8; }` must plan at byte offsets 0 and 8.
  const SerializableStructuralTypes<ExternalVariable> st = linked_list_fixture();
  PrintableCTypes<ExternalVariable> printer(st);
  const TypePlan plan = trexida::plan::build_plan(st, printer, 8);

  const PlannedAggregate *t1 = find_aggregate(plan, "t1");
  CHECK(t1 != nullptr);
  CHECK_EQ(t1->members.size(), (std::size_t)2);
  CHECK_EQ(t1->members[0].offset, (std::size_t)0);
  CHECK_EQ(t1->members[0].type_spelling, std::string("t1*"));
  CHECK_EQ(t1->members[1].offset, (std::size_t)8);
  CHECK_EQ(t1->members[1].type_spelling, std::string("int32_t"));
  CHECK_EQ(t1->size_known, true);
  CHECK_EQ(t1->size, (std::size_t)12); // 8-byte pointer at 0 + 4-byte int at 8
}

// ---------------------------------------------------------------------------
// Representability
// ---------------------------------------------------------------------------

TEST(plan_float_member_is_representable)
{
  // The old scalar-size tables had no entry for float/double/bool, so such a member was dropped
  // or turned into padding.
  Container<StructuralType> types;
  Index d8 = types.insert(float_of(8));
  Index f4 = types.insert(float_of(4));
  StructuralType agg = sized(24);
  agg.colocated_struct_fields[8] = d8;
  agg.colocated_struct_fields[16] = f4;
  Index a = types.insert(agg);

  Fixture fx({ { ExternalVariable("v@f@00001000"), a } }, std::move(types));
  const TypePlan plan = fx.plan();

  const PlannedAggregate *t1 = find_aggregate(plan, "t1");
  CHECK(t1 != nullptr);
  const PlannedMember *at8 = find_member(*t1, "field_8");
  const PlannedMember *at16 = find_member(*t1, "field_16");
  CHECK(at8 != nullptr);
  CHECK(at16 != nullptr);
  CHECK_EQ(at8->type_spelling, std::string("double"));
  CHECK_EQ(at8->is_gap, false);
  CHECK_EQ(at8->extent, (std::size_t)8);
  CHECK_EQ(at16->type_spelling, std::string("float"));
  CHECK_EQ(at16->is_gap, false);
  CHECK_EQ(at16->extent, (std::size_t)4);
}

TEST(plan_unknown_member_becomes_gap)
{
  // `void` (and `undefinedN`, and `padding[N]`) carry no type information; the member keeps its
  // bytes as a gap of exactly the slot extent.
  Container<StructuralType> types;
  Index blank = types.insert(StructuralType());
  Index i4 = types.insert(int_of(4));
  StructuralType agg = sized(8);
  agg.integer_ops.insert({ IntegerOp::Add, 8 });
  agg.colocated_struct_fields[8] = blank;
  agg.colocated_struct_fields[16] = i4;
  Index a = types.insert(agg);

  Fixture fx({ { ExternalVariable("v@f@00001000"), a } }, std::move(types));
  const TypePlan plan = fx.plan();

  const PlannedAggregate *t1 = find_aggregate(plan, "t1");
  CHECK(t1 != nullptr);
  const PlannedMember *gap = find_member(*t1, "gap_field_8");
  CHECK(gap != nullptr);
  CHECK_EQ(gap->offset, (std::size_t)8);
  CHECK_EQ(gap->extent, (std::size_t)8); // 16 - 8: the slot, not the aggregate total
  CHECK_EQ(plan.gap_members, (std::size_t)1);
}

TEST(plan_padding_member_uses_its_own_width)
{
  // `padding[N]`: N is authoritative and is not re-derived from the neighbouring offsets - here
  // the slot is 4 bytes wide but the gap covers all 20 the analysis saw.
  Container<StructuralType> types;
  Index i4 = types.insert(int_of(4));
  StructuralType agg;
  agg.colocated_struct_fields[4] = i4;
  agg.copy_sizes.insert(20);
  Index a = types.insert(agg);

  Fixture fx({ { ExternalVariable("v:f@00001000"), a } }, std::move(types));
  const TypePlan plan = fx.plan();

  const PlannedAggregate *t1 = find_aggregate(plan, "t1");
  CHECK(t1 != nullptr);
  const PlannedMember *head = &t1->members[0];
  CHECK_EQ(head->is_gap, true);
  CHECK_EQ(head->type_spelling, std::string("padding[20]"));
  CHECK_EQ(head->extent, (std::size_t)20);
  CHECK_EQ(head->offset, (std::size_t)0);
  // The real member after it is untouched.
  const PlannedMember *at4 = find_member(*t1, "field_4");
  CHECK(at4 != nullptr);
  CHECK_EQ(at4->offset, (std::size_t)4);
  CHECK_EQ(at4->is_gap, false);
}

TEST(plan_drops_unknown_extent)
{
  // Nothing about the aggregate or its last field has an observed size, so the trailing
  // `void` member has no extent to be a gap of and is dropped instead of shifting the layout.
  Container<StructuralType> types;
  Index blank = types.insert(StructuralType());
  Index i4 = types.insert(int_of(4));
  StructuralType agg;
  agg.colocated_struct_fields[4] = i4;
  agg.colocated_struct_fields[8] = blank;
  Index a = types.insert(agg);

  Fixture fx({ { ExternalVariable("v@f@00001000"), a } }, std::move(types));
  const TypePlan plan = fx.plan();

  const PlannedAggregate *t1 = find_aggregate(plan, "t1");
  CHECK(t1 != nullptr);
  CHECK_EQ(t1->size_known, false);
  CHECK(find_member(*t1, "field_8") == nullptr);
  CHECK(find_member(*t1, "gap_field_8") == nullptr);
  CHECK_EQ(plan.dropped_members, (std::size_t)1);
  // The members before it are untouched.
  CHECK_EQ(find_member(*t1, "field_4")->offset, (std::size_t)4);
}

// ---------------------------------------------------------------------------
// Aggregates
// ---------------------------------------------------------------------------

TEST(plan_union_alternatives_at_zero)
{
  // A type with both 4-byte integer and 4-byte floating capabilities rounds to two primitives,
  // which the printer emits as a union.
  Container<StructuralType> types;
  StructuralType both = sized(4);
  both.integer_ops.insert({ IntegerOp::Add, 4 });
  both.float_ops.insert({ FloatOp::Add, 4 });
  Index u = types.insert(both);
  StructuralType holder = sized(16);
  holder.colocated_struct_fields[8] = u;
  Index h = types.insert(holder);

  Fixture fx({ { ExternalVariable("v@f@00001000"), h } }, std::move(types));
  const TypePlan plan = fx.plan();

  const PlannedAggregate *t3 = find_aggregate(plan, "t3");
  CHECK(t3 != nullptr);
  CHECK_EQ(t3->is_union, true);
  CHECK_EQ(t3->members.size(), (std::size_t)2);
  CHECK_EQ(t3->members[0].name, std::string("alt_0"));
  CHECK_EQ(t3->members[1].name, std::string("alt_1"));
  for ( const PlannedMember &m : t3->members )
    CHECK_EQ(m.offset, (std::size_t)0);

  // A struct holding that union by value must be created after it.
  const PlannedAggregate *t1 = find_aggregate(plan, "t1");
  CHECK(t1 != nullptr);
  std::size_t pos_union = 0, pos_holder = 0;
  for ( std::size_t i = 0; i < plan.aggregates.size(); ++i )
  {
    if ( plan.aggregates[i].name == "t3" ) pos_union = i;
    if ( plan.aggregates[i].name == "t1" ) pos_holder = i;
  }
  CHECK(pos_union < pos_holder);
}

TEST(plan_union_gap_alternative_at_zero)
{
  // A field only ever seen being copied in 12-byte chunks has no primitive to describe it, so
  // the printer offers `long double` *or* `padding[12]` - a union with one gap alternative. The
  // gap covers the union's own bytes and, like every alternative, starts at 0.
  Container<StructuralType> types;
  Index wide = types.insert(sized(12));
  Index i4 = types.insert(int_of(4));
  StructuralType agg = sized(8);
  agg.integer_ops.insert({ IntegerOp::Add, 8 });
  agg.colocated_struct_fields[8] = wide;
  agg.colocated_struct_fields[16] = i4;
  Index a = types.insert(agg);

  Fixture fx({ { ExternalVariable("v@f@00001000"), a } }, std::move(types));
  const TypePlan plan = fx.plan();

  const PlannedAggregate *t3 = find_aggregate(plan, "t3");
  CHECK(t3 != nullptr);
  CHECK_EQ(t3->is_union, true);
  CHECK_EQ(t3->members.size(), (std::size_t)2);

  const PlannedMember *real = find_member(*t3, "alt_0");
  CHECK(real != nullptr);
  CHECK_EQ(real->is_gap, false);
  CHECK_EQ(real->offset, (std::size_t)0);

  const PlannedMember *gap = find_member(*t3, "gap_alt_1");
  CHECK(gap != nullptr);
  CHECK_EQ(gap->is_gap, true);
  CHECK_EQ(gap->offset, (std::size_t)0);
  CHECK_EQ(gap->extent, (std::size_t)12); // padding[12]: N is authoritative
  CHECK_EQ(plan.gap_members, (std::size_t)1);
}

TEST(plan_flexible_array_last)
{
  // A struct whose last colocated field is the struct itself prints as `T[]`, and that member
  // becomes a flexible array member (nelems == 0, extent 0).
  Container<StructuralType> types;
  StructuralType flex;
  flex.observed_array = true;
  Index f = types.insert(flex);
  types.get_mut(f).colocated_struct_fields[4] = f;
  StructuralType holder = sized(24);
  holder.colocated_struct_fields[8] = f;
  Index h = types.insert(holder);

  Fixture fx({ { ExternalVariable("v@f@00001000"), h } }, std::move(types));
  const TypePlan plan = fx.plan();

  const PlannedAggregate *t1 = find_aggregate(plan, "t1");
  CHECK(t1 != nullptr);
  const PlannedMember *last = &t1->members.back();
  CHECK_EQ(last->offset, (std::size_t)8);
  CHECK_EQ(last->is_flexible_array, true);
  CHECK_EQ(last->extent, (std::size_t)0);
  CHECK_EQ(last->is_gap, false);
  // Nothing but the flexible array member may follow it.
  for ( const PlannedMember &m : t1->members )
    if ( m.is_flexible_array )
      CHECK(&m == last);
}

// ---------------------------------------------------------------------------
// Types window
// ---------------------------------------------------------------------------

TEST(plan_window_renders_the_printed_declaration)
{
  // The window renders the plan it is given; for a struct with no gaps that text must be exactly
  // what the C printer emits, so what the user copies is what the printer produced.
  const SerializableStructuralTypes<ExternalVariable> st = linked_list_fixture();
  PrintableCTypes<ExternalVariable> printer(st);
  const TypePlan plan = trexida::plan::build_plan(st, printer, 8);
  const PlannedAggregate *t1 = find_aggregate(plan, "t1");
  CHECK(t1 != nullptr);

  trex::ui::StructInfo si;
  si.kind = "struct";
  si.name = t1->name;
  si.size = t1->size;
  for ( const PlannedMember &pm : t1->members )
  {
    trex::ui::MemberRow row;
    row.type = pm.type_spelling;
    row.name = pm.name;
    row.offset = pm.offset;
    row.extent = pm.extent;
    row.is_gap = pm.is_gap;
    si.members.push_back(std::move(row));
  }
  si.member_count = si.members.size();

  const std::string rendered = trex::ui::render_declaration(si);
  CHECK_EQ(rendered,
           std::string("struct t1 {\n"
                       "  t1* field_0;\n"
                       "  int32_t field_8;\n"
                       "};\n"));
  CHECK(printer.to_string().find(rendered) != std::string::npos);
}

TEST(plan_window_renders_gap_members_as_byte_blobs)
{
  // A gap member has no type the user could paste, but it does have an exact width: it renders as
  // the byte blob of that width so the clipboard output stays valid C.
  trex::ui::StructInfo si;
  si.kind = "union";
  si.name = "t7";
  trex::ui::MemberRow gap;
  gap.type = "padding[12]";
  gap.name = "gap_alt_1";
  gap.extent = 12;
  gap.is_gap = true;
  si.members.push_back(gap);
  trex::ui::MemberRow real;
  real.type = "int32_t";
  real.name = "alt_0";
  real.extent = 4;
  si.members.push_back(real);

  CHECK_EQ(trex::ui::render_declaration(si),
           std::string("union t7 {\n"
                       "  unsigned char gap_alt_1[12];\n"
                       "  int32_t alt_0;\n"
                       "};\n"));
}

// ---------------------------------------------------------------------------
// Variables
// ---------------------------------------------------------------------------

TEST(plan_no_type_info_variables)
{
  // The rule run_apply() has always applied: `void` / `undefined*` / `padding*` (and an empty
  // spelling) are not applied at all - the variable keeps IDA's own type.
  CHECK_EQ(trexida::plan::has_type_information(""), false);
  CHECK_EQ(trexida::plan::has_type_information("void"), false);
  CHECK_EQ(trexida::plan::has_type_information("undefined"), false);
  CHECK_EQ(trexida::plan::has_type_information("undefined4"), false);
  CHECK_EQ(trexida::plan::has_type_information("padding"), false);
  CHECK_EQ(trexida::plan::has_type_information("padding[4]"), false);

  CHECK_EQ(trexida::plan::has_type_information("t1*"), true);
  CHECK_EQ(trexida::plan::has_type_information("int32_t"), true);
  CHECK_EQ(trexida::plan::has_type_information("t3"), true);
  CHECK_EQ(trexida::plan::has_type_information("void*"), true);

  // The fixture's two variables are real pointers and must be planned as applicable.
  const SerializableStructuralTypes<ExternalVariable> st = linked_list_fixture();
  PrintableCTypes<ExternalVariable> printer(st);
  const TypePlan plan = trexida::plan::build_plan(st, printer, 8);

  CHECK_EQ(plan.variable_types.size(), (std::size_t)2);
  for ( const trexida::plan::PlannedVariable &v : plan.variable_types )
  {
    CHECK_EQ(v.has_type_info, true);
    CHECK_EQ(v.spelling, std::string("t1*"));
  }
}