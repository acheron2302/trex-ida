#include <trex/il.hpp>

#include <trex/inference_config.hpp>

#include <algorithm>
#include <cstdarg>
#include <cstdio>

namespace trex {
namespace {

const char *const kOpNames[] = {
  "BoolAnd", "BoolNegate", "BoolOr", "BoolXor", "Branch", "BranchIndOffset",
  "CallWithFallthrough", "CallWithNoFallthrough", "CallWithFallthroughIndirect",
  "CallWithNoFallthroughIndirect", "Cbranch", "Copy", "Float2Float", "Float2IntTrunc",
  "FloatAbs", "FloatAdd", "FloatDiv", "FloatEqual", "FloatNotEqual", "FloatLess",
  "FloatLessEqual", "FloatIsNan", "FloatMult", "FloatNeg", "FloatRound", "FloatSqrt",
  "FloatSub", "Int2Float", "IntAdd", "IntAnd", "IntCarry", "IntEqual", "IntNotEqual",
  "IntLess", "IntMult", "IntOr", "IntSBorrow", "IntSCarry", "IntUDiv", "IntSDiv",
  "IntURem", "IntSRem", "IntSext", "IntSLess", "IntLeftShift", "IntURightShift",
  "IntSRightShift", "IntSub", "IntOnesComp", "IntTwosComp", "IntXor", "IntZext", "Load",
  "Popcount", "Return", "Store", "Piece", "SubPiece", "FunctionStart", "FunctionEnd",
  "Nop", "ProcessorException", "ScalarLowerOp", "ScalarUpperOp", "PackedVectorOp",
  "UnderspecifiedOutputModification", "UnderspecifiedNoOutput",
};

const char *const kVsopNames[] = {
  "FloatAdd", "FloatSub", "FloatMul", "FloatDiv", "LogicalShiftLeft",
};

std::string fmt(const char *format, ...)
{
  char buf[512];
  va_list va;
  va_start(va, format);
  vsnprintf(buf, sizeof(buf), format, va);
  va_end(va);
  return std::string(buf);
}

//--------------------------------------------------------------------------
// Validation helpers (port of the `try_confirm_valid` macros in il.rs)
//--------------------------------------------------------------------------

struct Validator
{
  const Instruction *ins;
  std::optional<std::string> err;

  explicit Validator(const Instruction *i) : ins(i) {}

  bool failed() const { return err.has_value(); }

  void set_error(const std::string &message)
  {
    if ( !err.has_value() )
      err = message;
  }

  /// exp!(__fail $e => [$failpats])
  void expect_one(const Variable &v, const char *const *names, size_t count, const char *what)
  {
    if ( failed() )
      return;
    for ( size_t i = 0; i < count; ++i )
    {
      if ( matches(v, names[i]) )
        return;
    }
    std::string expected;
    for ( size_t i = 0; i < count; ++i )
    {
      if ( i != 0 )
        expected += " | ";
      expected += names[i];
    }
    set_error(fmt("Got %s %s for operation %s. Expected one of [%s]. Address: 0x%llx.",
                  what,
                  v.debug_string().c_str(),
                  ins->op.name().c_str(),
                  expected.c_str(),
                  (unsigned long long)ins->address));
  }

  static bool matches(const Variable &v, const char *name)
  {
    if ( strcmp(name, "0") == 0 )
      return v.kind == VarKind::Unused;
    if ( strcmp(name, "vn") == 0 )
      return v.kind == VarKind::Varnode;
    if ( strcmp(name, "vnc") == 0 )
      return v.kind == VarKind::Varnode || v.kind == VarKind::Constant;
    if ( strcmp(name, "vnc0") == 0 )
      return v.kind == VarKind::Varnode || v.kind == VarKind::Constant || v.kind == VarKind::Unused;
    if ( strcmp(name, "c") == 0 )
      return v.kind == VarKind::Constant;
    if ( strcmp(name, "dr") == 0 )
      return v.kind == VarKind::DerefVarnode;
    if ( strcmp(name, "pc") == 0 )
      return v.kind == VarKind::MachineAddress || v.kind == VarKind::ILAddress
          || v.kind == VarKind::ILOffset;
    return false;
  }

  void pattern(const Variable &i0, const char *n0, const Variable &i1, const char *n1, const Variable &o, const char *no)
  {
    expect_one(i0, &n0, 1, "inputs[0]");
    expect_one(i1, &n1, 1, "inputs[1]");
    expect_one(o, &no, 1, "output");
  }

  void pattern3(const Variable &i0,
                const char *const *n0,
                size_t c0,
                const Variable &i1,
                const char *const *n1,
                size_t c1,
                const Variable &o,
                const char *const *no,
                size_t co)
  {
    expect_one(i0, n0, c0, "inputs[0]");
    expect_one(i1, n1, c1, "inputs[1]");
    expect_one(o, no, co, "output");
  }

  void same_size(const Variable &a, const char *na, const Variable &b, const char *nb)
  {
    if ( failed() )
      return;
    std::optional<size_t> sa = a.try_size();
    std::optional<size_t> sb = b.try_size();
    if ( sa.has_value() && sb.has_value() && *sa != *sb )
      set_error(fmt("Got unequal sizes %zu and %zu for %s and %s operation %s",
                    *sa,
                    *sb,
                    na,
                    nb,
                    ins->op.name().c_str()));
  }

  void size_lt(const Variable &a, const char *na, const Variable &b, const char *nb)
  {
    if ( failed() )
      return;
    std::optional<size_t> sa = a.try_size();
    std::optional<size_t> sb = b.try_size();
    if ( sa.has_value() && sb.has_value() && !(*sa < *sb) )
      set_error(fmt("Got invalid sizes %zu and %zu for %s and %s operation %s",
                    *sa,
                    *sb,
                    na,
                    nb,
                    ins->op.name().c_str()));
  }

  void size_sum(const Variable &a, const char *na, const Variable &b, const char *nb, const Variable &c, const char *nc)
  {
    if ( failed() )
      return;
    std::optional<size_t> sa = a.try_size();
    std::optional<size_t> sb = b.try_size();
    std::optional<size_t> sc = c.try_size();
    if ( sa.has_value() && sb.has_value() && sc.has_value() && *sa + *sb != *sc )
      set_error(fmt("Expected %s+%s==%s. Got %zu+%zu and %zu for operation %s",
                    na,
                    nb,
                    nc,
                    *sa,
                    *sb,
                    *sc,
                    ins->op.name().c_str()));
  }

  void size_is(const Variable &a, const char *na, size_t expected)
  {
    if ( failed() )
      return;
    if ( a.try_size() != std::optional<size_t>(expected) )
      set_error(fmt("Got size %s for %s in operation %s. Expected %zu",
                    a.try_size().has_value() ? std::to_string(*a.try_size()).c_str() : "none",
                    na,
                    ins->op.name().c_str(),
                    expected));
  }
};

std::string describe_op(const Op &op)
{
  if ( op.is_vector() )
    return op.name() + "(" + std::to_string(op.scalar_bits) + ", " + kVsopNames[(int)op.vsop] + ")";
  return op.name();
}

} // namespace

//--------------------------------------------------------------------------
// ASLocation
//--------------------------------------------------------------------------

std::string ASLocation::debug_string() const
{
  return fmt("ASLocation{as=%zu, off=0x%llx}", address_space_idx, (unsigned long long)offset);
}

//--------------------------------------------------------------------------
// Op
//--------------------------------------------------------------------------

std::string Op::name() const
{
  size_t idx = (size_t)kind;
  if ( idx < sizeof(kOpNames) / sizeof(kOpNames[0]) )
    return kOpNames[idx];
  return "Op<" + std::to_string((int)kind) + ">";
}

std::string Op::debug_string() const
{
  return describe_op(*this);
}

//--------------------------------------------------------------------------
// Variable
//--------------------------------------------------------------------------

std::optional<size_t> Variable::try_size() const
{
  switch ( kind )
  {
    case VarKind::Unused:
    case VarKind::ILAddress:
    case VarKind::ILOffset:
    case VarKind::MachineAddress:
      return std::nullopt;
    case VarKind::Constant:
      return size;
    case VarKind::Varnode:
      return size;
    case VarKind::DerefVarnode:
      // Should not use `size` on DerefVarnode; get the address or derefval size directly instead.
      return std::nullopt;
    case VarKind::StackVariable:
      // Should not use `size`; get it directly instead.
      return std::nullopt;
  }
  return std::nullopt;
}

std::optional<ASLocation> Variable::try_to_aslocation() const
{
  switch ( kind )
  {
    case VarKind::Varnode:
      return ASLocation(address_space_idx, (uint64_t)offset);
    case VarKind::DerefVarnode:
      // Points to the address's location. Dereferenced value is ignored.
      return ASLocation(addr_address_space_idx, (uint64_t)addr_offset);
    default:
      return std::nullopt;
  }
}

ASLocation Variable::to_aslocation() const
{
  std::optional<ASLocation> loc = try_to_aslocation();
  TREX_CHECK(loc.has_value(), "variable has no address-space location: %s", debug_string().c_str());
  return *loc;
}

Variable Variable::machine_addr_to_il_if_possible(const Program &program) const
{
  if ( kind == VarKind::MachineAddress )
  {
    std::map<uint64_t, std::pair<size_t, size_t>>::const_iterator it = program.address_mapping.find(addr);
    if ( it != program.address_mapping.end() )
      return Variable::iladdress(it->second.first);
  }
  return *this;
}

std::string Variable::debug_string() const
{
  switch ( kind )
  {
    case VarKind::Unused:
      return "Unused";
    case VarKind::Varnode:
      return fmt("Varnode{as=%zu, off=%zu, sz=%zu}", address_space_idx, offset, size);
    case VarKind::DerefVarnode:
      return fmt("Deref@%zu,sz=%zu{as=%zu, off=%zu}",
                 derefval_address_space_idx,
                 derefval_size,
                 addr_address_space_idx,
                 addr_offset);
    case VarKind::Constant:
      return fmt("$%lluu%zu", (unsigned long long)value, size);
    case VarKind::MachineAddress:
      return fmt("MCA(0x%llx)", (unsigned long long)addr);
    case VarKind::ILAddress:
      return fmt("ILA(%zu)", offset);
    case VarKind::ILOffset:
      return fmt("ILO(%+lld)", (long long)il_offset);
    case VarKind::StackVariable:
      return fmt("STACKVAR{off=0x%llx,sz=%zu}", (unsigned long long)stack_offset, var_size);
  }
  return "Variable<?>";
}

bool operator==(const Variable &a, const Variable &b)
{
  if ( a.kind != b.kind )
    return false;
  switch ( a.kind )
  {
    case VarKind::Unused:
      return true;
    case VarKind::Varnode:
      return a.address_space_idx == b.address_space_idx && a.offset == b.offset && a.size == b.size;
    case VarKind::DerefVarnode:
      return a.derefval_address_space_idx == b.derefval_address_space_idx
          && a.derefval_size == b.derefval_size
          && a.addr_address_space_idx == b.addr_address_space_idx
          && a.addr_offset == b.addr_offset;
    case VarKind::Constant:
      return a.value == b.value && a.size == b.size;
    case VarKind::MachineAddress:
      return a.addr == b.addr;
    case VarKind::ILAddress:
      return a.offset == b.offset;
    case VarKind::ILOffset:
      return a.il_offset == b.il_offset;
    case VarKind::StackVariable:
      return a.stack_offset == b.stack_offset && a.var_size == b.var_size;
  }
  return false;
}

bool operator<(const Variable &a, const Variable &b)
{
  if ( a.kind != b.kind )
    return (uint8_t)a.kind < (uint8_t)b.kind;
  switch ( a.kind )
  {
    case VarKind::Unused:
      return false;
    case VarKind::Varnode:
      if ( a.address_space_idx != b.address_space_idx )
        return a.address_space_idx < b.address_space_idx;
      if ( a.offset != b.offset )
        return a.offset < b.offset;
      return a.size < b.size;
    case VarKind::DerefVarnode:
      if ( a.derefval_address_space_idx != b.derefval_address_space_idx )
        return a.derefval_address_space_idx < b.derefval_address_space_idx;
      if ( a.derefval_size != b.derefval_size )
        return a.derefval_size < b.derefval_size;
      if ( a.addr_address_space_idx != b.addr_address_space_idx )
        return a.addr_address_space_idx < b.addr_address_space_idx;
      return a.addr_offset < b.addr_offset;
    case VarKind::Constant:
      if ( a.value != b.value )
        return a.value < b.value;
      return a.size < b.size;
    case VarKind::MachineAddress:
      return a.addr < b.addr;
    case VarKind::ILAddress:
      return a.offset < b.offset;
    case VarKind::ILOffset:
      return a.il_offset < b.il_offset;
    case VarKind::StackVariable:
      if ( a.stack_offset != b.stack_offset )
        return a.stack_offset < b.stack_offset;
      return a.var_size < b.var_size;
  }
  return false;
}

//--------------------------------------------------------------------------
// Instruction
//--------------------------------------------------------------------------

std::optional<std::string> Instruction::try_confirm_valid() const
{
  Validator v(this);

  switch ( op.kind )
  {
    case OpKind::CallWithFallthroughIndirect:
    case OpKind::CallWithNoFallthroughIndirect:
    case OpKind::BranchIndOffset:
      break;
    default:
      if ( !indirect_targets.empty() )
        return fmt("Got indirect targets [%s] for operation %s",
                   [&] {
                     std::string s;
                     for ( size_t i = 0; i < indirect_targets.size(); ++i )
                     {
                       if ( i != 0 )
                         s += ", ";
                       s += indirect_targets[i].debug_string();
                     }
                     return s;
                   }().c_str(),
                   op.name().c_str());
      break;
  }

  switch ( op.kind )
  {
    case OpKind::Branch:
    case OpKind::CallWithFallthrough:
    case OpKind::CallWithNoFallthrough:
      v.pattern(inputs[0], "pc", inputs[1], "0", output, "0");
      break;
    case OpKind::BranchIndOffset:
    case OpKind::Return:
    case OpKind::CallWithFallthroughIndirect:
    case OpKind::CallWithNoFallthroughIndirect:
      v.pattern(inputs[0], "vn", inputs[1], "0", output, "0");
      break;
    case OpKind::Cbranch:
      v.pattern(inputs[0], "pc", inputs[1], "vnc", output, "0");
      break;
    case OpKind::Copy:
      v.pattern(inputs[0], "vnc", inputs[1], "0", output, "vn");
      v.same_size(inputs[0], "inputs[0]", output, "output");
      break;
    case OpKind::BoolNegate:
      v.pattern(inputs[0], "vnc", inputs[1], "0", output, "vn");
      v.same_size(inputs[0], "inputs[0]", output, "output");
      v.size_is(output, "output", 1);
      break;
    case OpKind::FloatAdd:
    case OpKind::FloatSub:
    case OpKind::FloatMult:
    case OpKind::FloatDiv:
      v.pattern(inputs[0], "vnc", inputs[1], "vnc", output, "vn");
      v.same_size(inputs[0], "inputs[0]", inputs[1], "inputs[1]");
      v.same_size(inputs[0], "inputs[0]", output, "output");
      break;
    case OpKind::Int2Float:
    case OpKind::Float2IntTrunc:
    case OpKind::Float2Float:
      v.pattern(inputs[0], "vnc", inputs[1], "0", output, "vn");
      break;
    case OpKind::FloatRound:
    case OpKind::FloatNeg:
    case OpKind::FloatAbs:
    case OpKind::FloatSqrt:
      v.pattern(inputs[0], "vnc", inputs[1], "0", output, "vn");
      v.same_size(output, "output", inputs[0], "inputs[0]");
      break;
    case OpKind::IntAdd:
    case OpKind::IntSub:
    case OpKind::IntMult:
    case OpKind::IntAnd:
    case OpKind::IntOr:
    case OpKind::IntXor:
    case OpKind::IntUDiv:
    case OpKind::IntURem:
    case OpKind::IntSDiv:
    case OpKind::IntSRem:
      v.pattern(inputs[0], "vnc", inputs[1], "vnc", output, "vn");
      v.same_size(inputs[0], "inputs[0]", inputs[1], "inputs[1]");
      v.same_size(inputs[0], "inputs[0]", output, "output");
      break;
    case OpKind::BoolAnd:
    case OpKind::BoolOr:
    case OpKind::BoolXor:
      v.pattern(inputs[0], "vnc", inputs[1], "vnc", output, "vn");
      v.same_size(inputs[0], "inputs[0]", inputs[1], "inputs[1]");
      v.same_size(inputs[0], "inputs[0]", output, "output");
      v.size_is(output, "output", 1);
      break;
    case OpKind::IntEqual:
    case OpKind::IntNotEqual:
    case OpKind::IntCarry:
    case OpKind::IntSCarry:
    case OpKind::IntSBorrow:
    case OpKind::IntSLess:
    case OpKind::IntLess:
    case OpKind::FloatEqual:
    case OpKind::FloatNotEqual:
    case OpKind::FloatLess:
    case OpKind::FloatLessEqual:
      v.pattern(inputs[0], "vnc", inputs[1], "vnc", output, "vn");
      v.same_size(inputs[0], "inputs[0]", inputs[1], "inputs[1]");
      v.size_is(output, "output", 1);
      break;
    case OpKind::FloatIsNan:
      v.pattern(inputs[0], "vnc", inputs[1], "0", output, "vn");
      v.size_is(output, "output", 1);
      break;
    case OpKind::IntLeftShift:
    case OpKind::IntURightShift:
    case OpKind::IntSRightShift:
      v.pattern(inputs[0], "vnc", inputs[1], "vnc", output, "vn");
      v.same_size(inputs[0], "inputs[0]", output, "output");
      break;
    case OpKind::IntOnesComp:
    case OpKind::IntTwosComp:
      v.pattern(inputs[0], "vnc", inputs[1], "0", output, "vn");
      v.same_size(inputs[0], "inputs[0]", output, "output");
      break;
    case OpKind::Popcount:
      v.pattern(inputs[0], "vnc", inputs[1], "0", output, "vn");
      break;
    case OpKind::IntZext:
    case OpKind::IntSext:
      v.pattern(inputs[0], "vnc", inputs[1], "0", output, "vn");
      v.size_lt(inputs[0], "inputs[0]", output, "output");
      break;
    case OpKind::Piece:
      v.pattern(inputs[0], "vnc", inputs[1], "vnc", output, "vn");
      v.size_sum(inputs[0], "inputs[0]", inputs[1], "inputs[1]", output, "output");
      break;
    case OpKind::SubPiece:
      v.pattern(inputs[0], "vnc", inputs[1], "vnc", output, "vn");
      v.size_lt(output, "output", inputs[0], "inputs[0]");
      break;
    case OpKind::Load:
      v.pattern(inputs[0], "dr", inputs[1], "0", output, "vn");
      break;
    case OpKind::Store:
      v.pattern(inputs[0], "dr", inputs[1], "vnc", output, "0");
      break;
    case OpKind::FunctionStart:
      v.pattern(inputs[0], "pc", inputs[1], "0", output, "0");
      break;
    case OpKind::FunctionEnd:
    case OpKind::Nop:
    case OpKind::ProcessorException:
      v.pattern(inputs[0], "0", inputs[1], "0", output, "0");
      break;
    case OpKind::ScalarLowerOp:
    case OpKind::ScalarUpperOp:
    case OpKind::PackedVectorOp:
      if ( op.vsop == VectorScalarOp::LogicalShiftLeft )
      {
        v.pattern(inputs[0], "vnc", inputs[1], "vnc", output, "vn");
        v.same_size(output, "output", inputs[0], "inputs[0]");
      }
      else
      {
        v.pattern(inputs[0], "vnc", inputs[1], "vnc", output, "vn");
        v.same_size(output, "output", inputs[0], "inputs[0]");
        v.same_size(output, "output", inputs[1], "inputs[1]");
      }
      if ( !v.failed() )
      {
        size_t out_size = output.try_size().value_or(0);
        if ( out_size <= op.scalar_bits )
          v.set_error(fmt("Vector operation uses size %zu operands, but has scalar op of size %d",
                          out_size,
                          (int)op.scalar_bits));
        else if ( out_size % op.scalar_bits != 0 )
          v.set_error(fmt("Vector operation uses size %zu operands, which is not a multiple of "
                          "scalar op of size %d",
                          out_size,
                          (int)op.scalar_bits));
      }
      break;
    case OpKind::UnderspecifiedOutputModification:
      v.pattern(inputs[0], "vnc0", inputs[1], "vnc0", output, "vn");
      break;
    case OpKind::UnderspecifiedNoOutput:
      v.pattern(inputs[0], "vnc0", inputs[1], "vnc0", output, "0");
      break;
  }

  return v.err;
}

void Instruction::confirm_valid() const
{
  std::optional<std::string> e = try_confirm_valid();
  TREX_CHECK(!e.has_value(), "%s", e.has_value() ? e->c_str() : "");
}

std::string Instruction::debug_string() const
{
  std::string indtgts;
  for ( size_t i = 0; i < indirect_targets.size(); ++i )
  {
    if ( i != 0 )
      indtgts += ", ";
    indtgts += indirect_targets[i].debug_string();
  }
  return fmt("Instruction { addr: 0x%llx, op: %s, output: %s, inputs: [%s, %s], indtgts: [%s] }",
             (unsigned long long)address,
             describe_op(op).c_str(),
             output.debug_string().c_str(),
             inputs[0].debug_string().c_str(),
             inputs[1].debug_string().c_str(),
             indtgts.c_str());
}

bool operator==(const Instruction &a, const Instruction &b)
{
  return a.address == b.address && a.op == b.op && a.output == b.output && a.inputs[0] == b.inputs[0]
      && a.inputs[1] == b.inputs[1] && a.indirect_targets == b.indirect_targets;
}

//--------------------------------------------------------------------------
// Program
//--------------------------------------------------------------------------

Program Program::create(std::vector<AddressSpace> address_spaces)
{
  TREX_CHECK(!address_spaces.empty(), "expected at least one address space");
  size_t pointer_size = 0;
  if ( address_spaces.size() == 1 )
  {
    pointer_size = address_spaces[0].wordsize;
  }
  else
  {
    std::vector<size_t> ps;
    for ( const AddressSpace &a : address_spaces )
    {
      if ( a.name == "ram" || a.name == "RAM" )
        ps.push_back(a.wordsize);
    }
    TREX_CHECK(ps.size() == 1, "expected exactly one address space named ram");
    pointer_size = ps[0];
  }

  Program p;
  p.address_spaces = std::move(address_spaces);
  p.pointer_size = pointer_size;
  return p;
}

void Program::begin_function(std::string name, std::vector<Variable> unaffected, uint64_t entry_point)
{
  if ( !functions.empty() )
  {
    const FunctionInfo &prev = functions.back();
    bool end_seen_in_prev_function = false;
    for ( size_t bb : prev.basic_blocks )
    {
      for ( size_t ins : basic_blocks[bb] )
      {
        if ( instructions[ins].op.kind == OpKind::FunctionEnd )
        {
          end_seen_in_prev_function = true;
          break;
        }
      }
      if ( end_seen_in_prev_function )
        break;
    }
    TREX_CHECK(end_seen_in_prev_function,
               "Should have called end_function before calling begin_function again");
  }

  Instruction ins;
  ins.address = UINT64_MAX;
  ins.op = Op(OpKind::FunctionStart);
  ins.output = Variable::unused();
  ins.inputs[0] = Variable::iloffset(1);
  ins.inputs[1] = Variable::unused();
  ins.confirm_valid();

  size_t fn_start = instructions.size();
  instructions.push_back(ins);
  size_t fn_start_bb = basic_blocks.size();
  basic_blocks.push_back({ fn_start });

  FunctionInfo info;
  info.name = std::move(name);
  info.unaffected.insert(unaffected.begin(), unaffected.end());
  info.basic_blocks.insert(fn_start_bb);
  info.entry = { entry_point, fn_start };
  functions.push_back(std::move(info));
}

void Program::end_function()
{
  TREX_CHECK(!functions.empty(), "end_function called without begin_function");

  Instruction ins;
  ins.address = UINT64_MAX;
  ins.op = Op(OpKind::FunctionEnd);
  ins.output = Variable::unused();
  ins.inputs[0] = Variable::unused();
  ins.inputs[1] = Variable::unused();
  ins.confirm_valid();

  if ( functions.back().basic_blocks.size() > 1 )
  {
    std::vector<Variable> fn_start_locs;
    for ( size_t bbi : functions.back().basic_blocks )
    {
      for ( size_t i : basic_blocks[bbi] )
      {
        if ( instructions[i].op.kind == OpKind::FunctionStart )
          fn_start_locs.push_back(instructions[i].inputs[0]);
      }
    }
    TREX_CHECK(fn_start_locs.size() == 1, "expected exactly one FunctionStart");
    TREX_CHECK(fn_start_locs[0].kind == VarKind::ILAddress,
               "Weird, function entry for %s is not within bounds. Got %s",
               functions.back().name.c_str(),
               fn_start_locs[0].debug_string().c_str());
  }

  size_t fn_end = instructions.size();
  instructions.push_back(ins);
  size_t fn_end_bb = basic_blocks.size();
  basic_blocks.push_back({ fn_end });
  functions.back().basic_blocks.insert(fn_end_bb);
}

void Program::assert_no_il_addresses_in(const std::vector<Instruction> &insns) const
{
  for ( const Instruction &ins : insns )
  {
    for ( int i = 0; i < 2; ++i )
    {
      TREX_CHECK(ins.inputs[i].kind != VarKind::ILAddress,
                 "Unexpected use of `ILAddress` in IL instruction %s",
                 ins.debug_string().c_str());
    }
    TREX_CHECK(ins.output.kind != VarKind::ILAddress,
               "Unexpected use of `ILAddress` in IL instruction %s",
               ins.debug_string().c_str());
  }
}

void Program::add_one_machine_instruction(std::vector<Instruction> new_instructions)
{
  TREX_CHECK(!functions.empty(), "expected a function to have been started");
  TREX_CHECK(!new_instructions.empty(), "Expected some IL instructions.");

  uint64_t addr = new_instructions[0].address;
  for ( const Instruction &i : new_instructions )
  {
    TREX_CHECK(i.address == addr,
               "Not all provided IL instructions correspond to a single machine instruction. "
               "Got: %s",
               i.debug_string().c_str());
  }

  size_t il_addr = instructions.size();
  std::map<uint64_t, std::pair<size_t, size_t>>::const_iterator existing = address_mapping.find(addr);
  TREX_CHECK(existing == address_mapping.end(),
             "Instruction at address 0x%llx was already added earlier. Old IL instructions at %zu. "
             "Trying to insert, at %zu.",
             (unsigned long long)addr,
             existing == address_mapping.end() ? 0 : existing->second.first,
             il_addr);
  address_mapping[addr] = { il_addr, new_instructions.size() };

  for ( const Instruction &i : new_instructions )
    i.confirm_valid();
  assert_no_il_addresses_in(new_instructions);

  // If we are at the function entry point, then set the function start to jump to here.
  if ( addr == functions.back().entry.first )
  {
    std::vector<size_t> fn_starts;
    for ( size_t bbi : functions.back().basic_blocks )
    {
      for ( size_t i : basic_blocks[bbi] )
      {
        if ( instructions[i].op.kind == OpKind::FunctionStart )
          fn_starts.push_back(i);
      }
    }
    TREX_CHECK(fn_starts.size() == 1, "expected exactly one FunctionStart");
    size_t cur_il_addr = instructions.size();
    instructions[fn_starts[0]].inputs[0] = Variable::iladdress(cur_il_addr);
  }

  // Set up basic blocks: one trivial block per IL instruction (as upstream does).
  size_t ins_start = instructions.size();
  size_t bb_start = basic_blocks.size();
  for ( size_t i = 0; i < new_instructions.size(); ++i )
    basic_blocks.push_back({ ins_start + i });
  for ( size_t i = bb_start; i < basic_blocks.size(); ++i )
    functions.back().basic_blocks.insert(i);

  for ( Instruction &i : new_instructions )
    instructions.push_back(std::move(i));
}

std::optional<std::pair<size_t, size_t>> Program::get_il_addrs_for_machine_addr(uint64_t machine_addr) const
{
  std::map<uint64_t, std::pair<size_t, size_t>>::const_iterator it = address_mapping.find(machine_addr);
  if ( it == address_mapping.end() )
    return std::nullopt;
  return it->second;
}

std::vector<size_t> Program::get_successor_instruction_addresses_for(size_t il_addr) const
{
  const Instruction &ins = instructions[il_addr];

  auto input_to_addr = [&](const Variable &input) -> std::optional<size_t> {
    switch ( input.kind )
    {
      case VarKind::MachineAddress:
      {
        std::map<uint64_t, std::pair<size_t, size_t>>::const_iterator it = address_mapping.find(input.addr);
        if ( it == address_mapping.end() )
          return std::nullopt;
        return it->second.first;
      }
      case VarKind::ILAddress:
        return input.offset;
      case VarKind::ILOffset:
      {
        int64_t v = (int64_t)il_addr + input.il_offset;
        TREX_CHECK(v >= 0 && (size_t)v < instructions.size(),
                   "IL offset %lld leads to out of bounds v=%lld len=%zu",
                   (long long)input.il_offset,
                   (long long)v,
                   instructions.size());
        return (size_t)v;
      }
      default:
        TREX_UNREACHABLE("unexpected control-flow target operand: %s", input.debug_string().c_str());
    }
  };

  std::vector<size_t> fallthrough;
  if ( il_addr + 1 < instructions.size() )
    fallthrough.push_back(il_addr + 1);

  switch ( ins.op.kind )
  {
    case OpKind::Branch:
    {
      std::optional<size_t> a = input_to_addr(ins.inputs[0]);
      return a.has_value() ? std::vector<size_t>{ *a } : std::vector<size_t>{};
    }
    case OpKind::CallWithFallthrough:
    case OpKind::CallWithFallthroughIndirect:
      // We do not include the callee, to allow for convenient intra-function analysis.
      return fallthrough;
    case OpKind::CallWithNoFallthrough:
    case OpKind::CallWithNoFallthroughIndirect:
      return {};
    case OpKind::Return:
      return {};
    case OpKind::BranchIndOffset:
    {
      std::vector<size_t> v;
      for ( const Variable &tgt : ins.indirect_targets )
      {
        std::optional<size_t> a = input_to_addr(tgt);
        if ( a.has_value() )
        {
          v.push_back(*a);
        }
        else
        {
          log::debug("Branch to unknown machine address. Ignoring for successor.",
                     { { "ilpc", (size_t)il_addr }, { "ins", ins.debug_string() } });
        }
      }
      return v;
    }
    case OpKind::Cbranch:
    {
      std::vector<size_t> v = fallthrough;
      std::optional<size_t> a = input_to_addr(ins.inputs[0]);
      if ( a.has_value() )
        v.push_back(*a);
      return v;
    }
    case OpKind::FunctionStart:
    {
      std::optional<size_t> a = input_to_addr(ins.inputs[0]);
      TREX_CHECK(a.has_value(), "FunctionStart points at an unknown machine address");
      return { *a };
    }
    case OpKind::ProcessorException:
    case OpKind::FunctionEnd:
      return {};
    default:
      return fallthrough;
  }
}

void Program::add_aux_data_for_stack_pointer_fixups(Variable sp, uint64_t machine_addr_target)
{
  TREX_CHECK(config().stack_pointer_patch_after_call_fallthrough,
             "stack pointer fixups require stack_pointer_patch_after_call_fallthrough");
  if ( aux_data_for_stack_pointer_fixups.has_value() )
  {
    TREX_CHECK(aux_data_for_stack_pointer_fixups->first == sp,
               "stack pointer changed between fixups");
    aux_data_for_stack_pointer_fixups->second.insert(machine_addr_target);
  }
  else
  {
    aux_data_for_stack_pointer_fixups = std::make_pair(sp, std::set<uint64_t>{ machine_addr_target });
  }
}

void Program::add_comment_to_machine_address(uint64_t machine_addr, const std::string &comment)
{
  std::map<uint64_t, std::string>::iterator it = machine_insn_comments.find(machine_addr);
  if ( it == machine_insn_comments.end() )
    machine_insn_comments[machine_addr] = comment;
  else
    it->second += "; " + comment;
}

size_t Program::function_index_for_il_ip(size_t il_pc) const
{
  for ( size_t i = 0; i < functions.size(); ++i )
  {
    for ( size_t bb : functions[i].basic_blocks )
    {
      const std::vector<size_t> &block = basic_blocks[bb];
      if ( std::find(block.begin(), block.end(), il_pc) != block.end() )
        return i;
    }
  }
  TREX_UNREACHABLE("should only be called on PCs that exist in some function (got %zu)", il_pc);
}

size_t Program::function_start_il_ip_for_il_ip(size_t il_pc) const
{
  size_t fn_idx = function_index_for_il_ip(il_pc);
  size_t func_start_il_pc = functions[fn_idx].entry.second;
  TREX_CHECK(instructions[func_start_il_pc].op.kind == OpKind::FunctionStart,
             "function entry is not a FunctionStart");
  return func_start_il_pc;
}

std::set<Variable> Program::get_unaffected_variables_for_call_to(const Variable &target,
                                                                 size_t caller_il_pc) const
{
  TREX_CHECK(target.kind == VarKind::MachineAddress,
             "Call to non-machine address found: %s",
             target.debug_string().c_str());

  std::set<Variable> result;
  bool found_function = false;

  for ( const FunctionInfo &fi : functions )
  {
    if ( fi.entry.first == target.addr )
    {
      result.insert(fi.unaffected.begin(), fi.unaffected.end());
      found_function = true;
      break;
    }
  }

  if ( aux_data_for_stack_pointer_fixups.has_value() )
  {
    const Variable &sp = aux_data_for_stack_pointer_fixups->first;
    const std::set<uint64_t> &sp_fixups = aux_data_for_stack_pointer_fixups->second;
    if ( sp_fixups.find(target.addr) != sp_fixups.end() )
      result.insert(sp);
  }

  if ( config().calling_convention_match_caller_if_unknown_for_callee && !found_function )
  {
    size_t caller_idx = function_index_for_il_ip(caller_il_pc);
    const FunctionInfo &caller = functions[caller_idx];
    result.insert(caller.unaffected.begin(), caller.unaffected.end());
    log::trace("Matching unknown calling convention to caller's",
               { { "target", target.debug_string() },
                 { "caller_il_pc", (size_t)caller_il_pc },
                 { "func", caller.name } });
  }

  if ( !found_function && result.empty() )
  {
    log::debug("Call to unknown function address, clobbering everything",
               { { "addr", std::to_string(target.addr) } });
  }

  return result;
}

} // namespace trex
