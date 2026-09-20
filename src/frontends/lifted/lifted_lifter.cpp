// Reference (Ghidra-text) frontend for TRex - port of upstream
// `trex/src/ghidra_lifter.rs::lift_from`.
//
// Recursive-descent parser for the textual p-code listing that the upstream
// `PCodeExporter.java` script emits. The output is a `trex::Program`
// byte-identical (modulo the C++ -> Rust memory layout) to what the Rust
// lifter would produce.

#include <cstdint>
#include <cstdio>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include <trex/error.hpp>
#include <trex/il.hpp>
#include <trex/inference_config.hpp>
#include <trex/lifted_frontend.hpp>
#include <trex/log.hpp>

namespace trex {
namespace {

// ---------------------------------------------------------------------------
// Address-space map key.
// ---------------------------------------------------------------------------
//
// Upstream uses `UnorderedMap<Result<usize, &'static str>, (usize, AddressSpace)>`
// where `Ok(n)` keys the *Ghidra-emitted* numeric index of an address space
// and `Err("unique")` / `Err("register")` key the two synthetic spaces that
// Ghidra's exporter does not tell us about. Iteration order matches
// insertion order, so we model this with a `std::map` over an ordered
// `Key` whose variant order matches upstream's `Result` discriminant
// (`Ok` < `Err` after `enumerate` renumbers entries, but since we are
// walking an already-built vector with stable indices, this collapses
// to "stable iteration by index").

enum class KeyKind : uint8_t
{
  Ok = 0,
  Unique,
  Register,
};

struct Key
{
  KeyKind kind = KeyKind::Ok;
  size_t idx = 0; // valid for Ok; ignored otherwise

  friend bool operator<(const Key &a, const Key &b)
  {
    if ( a.kind != b.kind )
      return (uint8_t)a.kind < (uint8_t)b.kind;
    if ( a.kind == KeyKind::Ok )
      return a.idx < b.idx;
    return false;
  }
};

using AddressSpaceMap = std::map<Key, std::pair<size_t, AddressSpace>>;

// ---------------------------------------------------------------------------
// Auxiliary data captured while parsing the p-code listing.
// ---------------------------------------------------------------------------
struct AuxDataWhenParsingPCodeListing
{
  std::vector<std::pair<Variable, uint64_t>> sp_fixups;
  std::map<uint64_t, std::string> machine_addr_comments;

  AuxDataWhenParsingPCodeListing() = default;
};

// ---------------------------------------------------------------------------
// Line parsing helpers.
// ---------------------------------------------------------------------------

bool starts_with(std::string_view s, std::string_view p)
{
  return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}

bool contains(std::string_view s, std::string_view p)
{
  return s.find(p) != std::string_view::npos;
}

// Parse a leading hex literal (with or without "0x" prefix).
uint64_t parse_hex(std::string_view s)
{
  if ( starts_with(s, "0x") || starts_with(s, "0X") )
    s.remove_prefix(2);
  if ( s.empty() )
    TREX_UNREACHABLE("empty hex literal");
  try
  {
    return std::stoull(std::string(s), nullptr, 16);
  }
  catch ( const std::exception & )
  {
    TREX_UNREACHABLE("not a hexadecimal literal: `{}`", std::string(s));
  }
}

uint64_t parse_dec(std::string_view s)
{
  TREX_CHECK(!s.empty(), "empty decimal literal");
  try
  {
    return std::stoull(std::string(s), nullptr, 10);
  }
  catch ( const std::exception & )
  {
    TREX_UNREACHABLE("not a decimal literal: `{}`", std::string(s));
  }
}

// Strip one ASCII prefix; panics on mismatch.
std::string_view strip_prefix_or_panic(std::string_view s, std::string_view p, const char *what)
{
  TREX_CHECK(starts_with(s, p), "expected `{}` prefix in `{}`", what, std::string(s));
  return s.substr(p.size());
}

std::string_view strip_suffix_or_panic(std::string_view s, std::string_view p, const char *what)
{
  TREX_CHECK(s.size() >= p.size() && s.compare(s.size() - p.size(), p.size(), p) == 0,
             "expected `{}` suffix in `{}`", what, std::string(s));
  return s.substr(0, s.size() - p.size());
}

// ---------------------------------------------------------------------------
// parse_variable
//
// Parses a single `(space, 0xOFFSET, size)` tuple, or the `---` placeholder
// for `Variable::Unused`. Returns `(var, size_bytes, rest_of_line)`. The
// returned `size_bytes` is the same numeric the caller would have to ask
// for via `var.try_size()`; the Rust code threads it through explicitly.
// ---------------------------------------------------------------------------
struct ParseVariableResult
{
  Variable var;
  uint64_t size;
  std::string_view rest;
};

ParseVariableResult parse_variable(std::string_view inp, const AddressSpaceMap &address_space_map)
{
  std::string_view s = inp;
  // Trim leading whitespace.
  while ( !s.empty() && (s.front() == ' ' || s.front() == '\t') )
    s.remove_prefix(1);

  if ( starts_with(s, "---") )
  {
    std::string_view rest = s.substr(3);
    while ( !rest.empty() && (rest.front() == ' ' || rest.front() == '\t') )
      rest.remove_prefix(1);
    return { Variable::unused(), 0, rest };
  }

  // Three whitespace-separated tokens: "(space,", "0xOFFSET,", "size)".
  // We split on whitespace, then strip the delimiters individually.
  auto next_token = [&](std::string_view &cur) -> std::string_view {
    size_t i = 0;
    while ( i < cur.size() && cur[i] != ' ' && cur[i] != '\t' )
      ++i;
    std::string_view tok = cur.substr(0, i);
    while ( i < cur.size() && (cur[i] == ' ' || cur[i] == '\t') )
      ++i;
    cur = cur.substr(i);
    return tok;
  };

  std::string_view cur = s;
  std::string_view a_tok = next_token(cur);
  std::string_view b_tok = next_token(cur);
  std::string_view c_tok = next_token(cur);

  std::string_view a = strip_prefix_or_panic(a_tok, "(", "leading `(` of variable");
  a = strip_suffix_or_panic(a, ",", "trailing `,` of address space name");
  std::string_view b = strip_prefix_or_panic(b_tok, "0x", "leading `0x` of offset");
  b = strip_suffix_or_panic(b, ",", "trailing `,` of offset");
  std::string_view c = strip_suffix_or_panic(c_tok, ")", "trailing `)` of size");

  uint64_t offset = parse_hex(b);
  uint64_t size = parse_dec(c);

  Variable var;
  if ( a == "const" )
  {
    TREX_CHECK(size <= std::numeric_limits<size_t>::max(),
               "constant size {} overflows size_t", size);
    var = Variable::constant(offset, static_cast<size_t>(size));
  }
  else
  {
    // Look up the address space by name. Address spaces are stored with
    // both their numeric Ghidra key (`Ok(idx)`) and the synthetic
    // (`Unique`, `Register`) keys, so a linear search by name is the
    // simplest faithful translation.
    const AddressSpace *match = nullptr;
    size_t match_idx = 0;
    for ( const auto &kv : address_space_map )
    {
      if ( kv.second.second.name == std::string(a) )
      {
        match = &kv.second.second;
        match_idx = kv.second.first;
        break;
      }
    }
    TREX_CHECK(match != nullptr, "Could not find address space `{}`", std::string(a));
    TREX_CHECK(offset <= std::numeric_limits<size_t>::max(),
               "offset {} overflows size_t", offset);
    TREX_CHECK(size <= std::numeric_limits<size_t>::max(),
               "size {} overflows size_t", size);
    var = Variable::varnode(match_idx,
                            static_cast<size_t>(offset),
                            static_cast<size_t>(size));
  }

  // The Rust code returns `inp[rest_start..].trim_start_matches(&[' ', ','])`
  // - i.e. it removes the consumed 3 tokens plus any following `,` or space.
  // We already advanced `cur` past three tokens; trim additional leading
  // spaces and commas to match exactly.
  std::string_view rest = cur;
  while ( !rest.empty() && (rest.front() == ' ' || rest.front() == '\t' || rest.front() == ',') )
    rest.remove_prefix(1);
  return { var, size, rest };
}

// ---------------------------------------------------------------------------
// varnode_to_pc
//
// Convert a Variable to either a MachineAddress (Varnode -> ram) or an
// ILOffset (Constant -> signed displacement). Used by BRANCH/CBRANCH and
// the direct CALL ops.
// ---------------------------------------------------------------------------
Variable varnode_to_pc(const Variable &v,
                       const AddressSpaceMap &address_space_map,
                       bool const_allowed)
{
  if ( v.kind == VarKind::Varnode )
  {
    const AddressSpace *as = nullptr;
    for ( const auto &kv : address_space_map )
    {
      if ( kv.second.first == v.address_space_idx )
      {
        as = &kv.second.second;
        break;
      }
    }
    TREX_CHECK(as != nullptr,
               "varnode_to_pc could not resolve address space idx {}", v.address_space_idx);
    TREX_CHECK(as->name == "ram",
               "varnode_to_pc requires the ram space, got `{}`", as->name);
    TREX_CHECK(v.offset <= std::numeric_limits<uint64_t>::max(),
               "varnode_to_pc offset overflow");
    return Variable::machine_address(static_cast<uint64_t>(v.offset));
  }
  if ( v.kind == VarKind::Constant && const_allowed )
  {
    // Upstream: `offset: u32::try_from(value).unwrap() as i32 as isize`.
    // Equivalent in C++:
    uint64_t raw = v.value & 0xFFFFFFFFULL;
    int32_t s = static_cast<int32_t>(static_cast<uint32_t>(raw));
    return Variable::iloffset(static_cast<int64_t>(s));
  }
  TREX_UNREACHABLE("varnode_to_pc: unexpected variable kind");
}

// ---------------------------------------------------------------------------
// parse_op
//
// Big switch on the textual opcode. Returns
//   (output, op, inputs[2], indirect_targets, rest_of_line)
// ---------------------------------------------------------------------------
struct ParseOpResult
{
  Variable output;
  Op op;
  Variable inputs[2];
  std::vector<Variable> indirect_targets;
  std::string_view rest;
};

ParseOpResult parse_op(std::string_view inp, const AddressSpaceMap &address_space_map)
{
  std::string_view cur = inp;
  // Trim leading whitespace - upstream uses `trim_start()`.
  while ( !cur.empty() && (cur.front() == ' ' || cur.front() == '\t') )
    cur.remove_prefix(1);

  // The first token is the destination variable, then a single space, then
  // the opcode, then a single space, then the operand list.
  ParseVariableResult pov = parse_variable(cur, address_space_map);
  Variable output = pov.var;
  cur = pov.rest;
  size_t sp = cur.find(' ');
  TREX_CHECK(sp != std::string_view::npos, "expected space after output variable");
  std::string_view op_name = cur.substr(0, sp);
  std::string_view rest = cur.substr(sp + 1);

  ParseOpResult result;
  result.output = output;
  result.inputs[0] = Variable::unused();
  result.inputs[1] = Variable::unused();

  if ( op_name == "STORE" )
  {
    ParseVariableResult v0 = parse_variable(rest, address_space_map);
    ParseVariableResult v1 = parse_variable(v0.rest, address_space_map);
    ParseVariableResult v2 = parse_variable(v1.rest, address_space_map);

    // v0 is the address-space index of the dereferenced address space.
    TREX_CHECK(v0.var.kind == VarKind::Constant,
               "STORE: first operand must be a constant address space index");
    auto it = address_space_map.find(Key{ KeyKind::Ok, v0.var.value });
    TREX_CHECK(it != address_space_map.end(),
               "STORE: could not find address space with Ghidra idx {}", v0.var.value);
    size_t derefval_as = it->second.first;
    const AddressSpace &as = it->second.second;

    // v1 is the address variable.
    TREX_CHECK(v1.var.kind == VarKind::Varnode,
               "STORE: second operand must be a Varnode");
    TREX_CHECK(v1.var.size == as.wordsize,
               "STORE: address size {} != address-space wordsize {}",
               v1.var.size, as.wordsize);
    TREX_CHECK(v2.size <= std::numeric_limits<size_t>::max(),
               "STORE: derefval size overflow");
    Variable dst = Variable::deref_varnode(derefval_as,
                                           static_cast<size_t>(v2.size),
                                           v1.var.address_space_idx,
                                           v1.var.offset);

    result.op = Op(OpKind::Store);
    result.inputs[0] = dst;
    result.inputs[1] = v2.var;
    result.rest = v2.rest;
    return result;
  }

  if ( op_name == "LOAD" )
  {
    ParseVariableResult v0 = parse_variable(rest, address_space_map);
    ParseVariableResult v1 = parse_variable(v0.rest, address_space_map);

    TREX_CHECK(v0.var.kind == VarKind::Constant,
               "LOAD: first operand must be a constant address space index");
    auto it = address_space_map.find(Key{ KeyKind::Ok, v0.var.value });
    TREX_CHECK(it != address_space_map.end(),
               "LOAD: could not find address space with Ghidra idx {}", v0.var.value);
    size_t derefval_as = it->second.first;
    const AddressSpace &as = it->second.second;

    TREX_CHECK(v1.var.kind == VarKind::Varnode,
               "LOAD: second operand must be a Varnode");
    TREX_CHECK(v1.var.size == as.wordsize,
               "LOAD: address size {} != address-space wordsize {}",
               v1.var.size, as.wordsize);
    auto out_size = output.try_size();
    TREX_CHECK(out_size.has_value(),
               "LOAD: output variable has no size ({})", output.debug_string());
    Variable src = Variable::deref_varnode(derefval_as,
                                           *out_size,
                                           v1.var.address_space_idx,
                                           v1.var.offset);

    result.op = Op(OpKind::Load);
    result.inputs[0] = src;
    result.inputs[1] = Variable::unused();
    result.rest = v1.rest;
    return result;
  }

  if ( op_name == "CALLWITHFALLTHROUGH" || op_name == "CALLWITHNOFALLTHROUGH" )
  {
    ParseVariableResult v0 = parse_variable(rest, address_space_map);
    Variable target = varnode_to_pc(v0.var, address_space_map, false);
    OpKind k = (op_name == "CALLWITHFALLTHROUGH") ? OpKind::CallWithFallthrough
                                                  : OpKind::CallWithNoFallthrough;
    result.op = Op(k);
    result.inputs[0] = target;
    result.rest = v0.rest;
    return result;
  }

  if ( op_name == "COPY" || op_name == "BOOL_NEGATE" || op_name == "POPCOUNT"
      || op_name == "INT_2COMP" || op_name == "INT_NEGATE" || op_name == "INT_ZEXT"
      || op_name == "INT_SEXT" || op_name == "RETURN" )
  {
    ParseVariableResult v0 = parse_variable(rest, address_space_map);
    OpKind k = OpKind::Nop;
    if ( op_name == "COPY" ) k = OpKind::Copy;
    else if ( op_name == "BOOL_NEGATE" ) k = OpKind::BoolNegate;
    else if ( op_name == "POPCOUNT" ) k = OpKind::Popcount;
    else if ( op_name == "INT_2COMP" ) k = OpKind::IntTwosComp;
    else if ( op_name == "INT_NEGATE" ) k = OpKind::IntOnesComp;
    else if ( op_name == "INT_ZEXT" ) k = OpKind::IntZext;
    else if ( op_name == "INT_SEXT" ) k = OpKind::IntSext;
    else if ( op_name == "RETURN" ) k = OpKind::Return;
    result.op = Op(k);
    result.inputs[0] = v0.var;
    result.rest = v0.rest;
    return result;
  }

  if ( op_name == "BRANCHIND" || op_name == "CALLWITHFALLTHROUGHIND"
      || op_name == "CALLWITHNOFALLTHROUGHIND" )
  {
    ParseVariableResult v0 = parse_variable(rest, address_space_map);
    OpKind k = OpKind::Nop;
    if ( op_name == "BRANCHIND" ) k = OpKind::BranchIndOffset;
    else if ( op_name == "CALLWITHFALLTHROUGHIND" ) k = OpKind::CallWithFallthroughIndirect;
    else if ( op_name == "CALLWITHNOFALLTHROUGHIND" ) k = OpKind::CallWithNoFallthroughIndirect;

    // The rest of the line is `INDIRECT_TARGETS: <hex> <hex> ...`.
    std::string_view r = v0.rest;
    while ( !r.empty() && (r.front() == ' ' || r.front() == '\t') )
      r.remove_prefix(1);
    r = strip_prefix_or_panic(r, "INDIRECT_TARGETS:", "indirect-targets marker");
    while ( !r.empty() && (r.front() == ' ' || r.front() == '\t') )
      r.remove_prefix(1);

    std::vector<Variable> indirect_targets;
    size_t i = 0;
    while ( i < r.size() )
    {
      while ( i < r.size() && (r[i] == ' ' || r[i] == '\t') )
        ++i;
      size_t j = i;
      while ( j < r.size() && r[j] != ' ' && r[j] != '\t' )
        ++j;
      if ( j == i )
        break;
      std::string_view tok = r.substr(i, j - i);
      indirect_targets.push_back(Variable::machine_address(parse_hex(tok)));
      i = j;
    }

    result.op = Op(k);
    result.inputs[0] = v0.var;
    result.indirect_targets = std::move(indirect_targets);
    result.rest = std::string_view();
    return result;
  }

  if ( op_name == "INT_ADD" || op_name == "INT_EQUAL" || op_name == "INT_NOTEQUAL"
      || op_name == "INT_SUB" || op_name == "INT_CARRY" || op_name == "INT_SCARRY"
      || op_name == "INT_SBORROW" || op_name == "INT_SLESS" || op_name == "INT_LESS"
      || op_name == "INT_AND" || op_name == "INT_OR" || op_name == "INT_XOR"
      || op_name == "INT_MULT" || op_name == "INT_DIV" || op_name == "INT_REM"
      || op_name == "INT_SDIV" || op_name == "INT_SREM" || op_name == "INT_LEFT"
      || op_name == "INT_RIGHT" || op_name == "INT_SRIGHT" || op_name == "BOOL_OR"
      || op_name == "BOOL_AND" || op_name == "BOOL_XOR" || op_name == "PIECE"
      || op_name == "SUBPIECE" )
  {
    ParseVariableResult v0 = parse_variable(rest, address_space_map);
    ParseVariableResult v1 = parse_variable(v0.rest, address_space_map);

    OpKind k = OpKind::Nop;
    if ( op_name == "INT_ADD" ) k = OpKind::IntAdd;
    else if ( op_name == "INT_EQUAL" ) k = OpKind::IntEqual;
    else if ( op_name == "INT_NOTEQUAL" ) k = OpKind::IntNotEqual;
    else if ( op_name == "INT_SUB" ) k = OpKind::IntSub;
    else if ( op_name == "INT_CARRY" ) k = OpKind::IntCarry;
    else if ( op_name == "INT_SCARRY" ) k = OpKind::IntSCarry;
    else if ( op_name == "INT_SBORROW" ) k = OpKind::IntSBorrow;
    else if ( op_name == "INT_LESS" ) k = OpKind::IntLess;
    else if ( op_name == "INT_SLESS" ) k = OpKind::IntSLess;
    else if ( op_name == "INT_AND" ) k = OpKind::IntAnd;
    else if ( op_name == "INT_OR" ) k = OpKind::IntOr;
    else if ( op_name == "INT_XOR" ) k = OpKind::IntXor;
    else if ( op_name == "INT_MULT" ) k = OpKind::IntMult;
    else if ( op_name == "INT_DIV" ) k = OpKind::IntUDiv;
    else if ( op_name == "INT_REM" ) k = OpKind::IntURem;
    else if ( op_name == "INT_SDIV" ) k = OpKind::IntSDiv;
    else if ( op_name == "INT_SREM" ) k = OpKind::IntSRem;
    else if ( op_name == "INT_LEFT" ) k = OpKind::IntLeftShift;
    else if ( op_name == "INT_RIGHT" ) k = OpKind::IntURightShift;
    else if ( op_name == "INT_SRIGHT" ) k = OpKind::IntSRightShift;
    else if ( op_name == "BOOL_OR" ) k = OpKind::BoolOr;
    else if ( op_name == "BOOL_AND" ) k = OpKind::BoolAnd;
    else if ( op_name == "BOOL_XOR" ) k = OpKind::BoolXor;
    else if ( op_name == "PIECE" ) k = OpKind::Piece;
    else if ( op_name == "SUBPIECE" ) k = OpKind::SubPiece;

    result.op = Op(k);
    result.inputs[0] = v0.var;
    result.inputs[1] = v1.var;
    result.rest = v1.rest;
    return result;
  }

  if ( op_name == "INT2FLOAT" || op_name == "TRUNC" || op_name == "ROUND"
      || op_name == "FLOAT2FLOAT" || op_name == "FLOAT_NEG" || op_name == "FLOAT_ABS"
      || op_name == "FLOAT_SQRT" )
  {
    ParseVariableResult v0 = parse_variable(rest, address_space_map);
    OpKind k = OpKind::Nop;
    if ( op_name == "INT2FLOAT" ) k = OpKind::Int2Float;
    else if ( op_name == "TRUNC" ) k = OpKind::Float2IntTrunc;
    else if ( op_name == "ROUND" ) k = OpKind::FloatRound;
    else if ( op_name == "FLOAT2FLOAT" ) k = OpKind::Float2Float;
    else if ( op_name == "FLOAT_NEG" ) k = OpKind::FloatNeg;
    else if ( op_name == "FLOAT_ABS" ) k = OpKind::FloatAbs;
    else if ( op_name == "FLOAT_SQRT" ) k = OpKind::FloatSqrt;
    result.op = Op(k);
    result.inputs[0] = v0.var;
    result.rest = v0.rest;
    return result;
  }

  if ( op_name == "FLOAT_NAN" )
  {
    ParseVariableResult v0 = parse_variable(rest, address_space_map);
    result.op = Op(OpKind::FloatIsNan);
    result.inputs[0] = v0.var;
    result.rest = v0.rest;
    return result;
  }

  if ( op_name == "FLOAT_ADD" || op_name == "FLOAT_SUB" || op_name == "FLOAT_MULT"
      || op_name == "FLOAT_DIV" || op_name == "FLOAT_EQUAL" || op_name == "FLOAT_NOTEQUAL"
      || op_name == "FLOAT_LESS" || op_name == "FLOAT_LESSEQUAL" )
  {
    ParseVariableResult v0 = parse_variable(rest, address_space_map);
    ParseVariableResult v1 = parse_variable(v0.rest, address_space_map);
    OpKind k = OpKind::Nop;
    if ( op_name == "FLOAT_ADD" ) k = OpKind::FloatAdd;
    else if ( op_name == "FLOAT_SUB" ) k = OpKind::FloatSub;
    else if ( op_name == "FLOAT_MULT" ) k = OpKind::FloatMult;
    else if ( op_name == "FLOAT_DIV" ) k = OpKind::FloatDiv;
    else if ( op_name == "FLOAT_EQUAL" ) k = OpKind::FloatEqual;
    else if ( op_name == "FLOAT_NOTEQUAL" ) k = OpKind::FloatNotEqual;
    else if ( op_name == "FLOAT_LESS" ) k = OpKind::FloatLess;
    else if ( op_name == "FLOAT_LESSEQUAL" ) k = OpKind::FloatLessEqual;
    result.op = Op(k);
    result.inputs[0] = v0.var;
    result.inputs[1] = v1.var;
    result.rest = v1.rest;
    return result;
  }

  if ( op_name == "BRANCH" )
  {
    ParseVariableResult v0 = parse_variable(rest, address_space_map);
    Variable target = varnode_to_pc(v0.var, address_space_map, true);
    result.op = Op(OpKind::Branch);
    result.inputs[0] = target;
    result.rest = v0.rest;
    return result;
  }

  if ( op_name == "CBRANCH" )
  {
    ParseVariableResult v0 = parse_variable(rest, address_space_map);
    ParseVariableResult v1 = parse_variable(v0.rest, address_space_map);
    Variable target = varnode_to_pc(v0.var, address_space_map, true);
    result.op = Op(OpKind::Cbranch);
    result.inputs[0] = target;
    result.inputs[1] = v1.var;
    result.rest = v1.rest;
    return result;
  }

  if ( op_name == "NOP" )
  {
    std::string_view r = rest;
    while ( !r.empty() && (r.front() == ' ' || r.front() == '\t') )
      r.remove_prefix(1);
    TREX_CHECK(r == "---", "NOP: expected `---` operand, got `{}`", std::string(r));
    result.op = Op(OpKind::Nop);
    result.rest = std::string_view();
    return result;
  }

  if ( op_name == "CALLOTHER" )
  {
    ParseVariableResult v0 = parse_variable(rest, address_space_map);

    // The CALLOTHER opcode name is the last whitespace-separated token of
    // the rest of the line; the `munch` helper asserts the line carries a
    // `CALLOTHER_OPCODE:` marker so we know the rest can be discarded.
    std::string_view r = v0.rest;
    size_t pos = r.rfind(' ');
    std::string_view callother_opcode;
    if ( pos == std::string_view::npos )
      callother_opcode = r;
    else
      callother_opcode = r.substr(pos + 1);

    auto munch = [](std::string_view line) {
      TREX_CHECK(starts_with(line, "\tCALLOTHER_OPCODE:"),
                 "Found non-CALLOTHER_OPCODE: {}", std::string(line));
      return std::string_view();
    };

    if ( callother_opcode == "invalidInstructionException" )
    {
      result.op = Op(OpKind::ProcessorException);
      result.rest = munch(v0.rest);
      return result;
    }

    auto cpuid = [&](const std::string_view &) {
      ParseVariableResult vv = parse_variable(v0.rest, address_space_map);
      result.op = Op(OpKind::UnderspecifiedOutputModification);
      result.inputs[0] = vv.var;
      result.rest = munch(vv.rest);
    };

    if ( callother_opcode == "cpuid"
        || callother_opcode == "cpuid_Architectural_Performance_Monitoring_info"
        || callother_opcode == "cpuid_Deterministic_Cache_Parameters_info"
        || callother_opcode == "cpuid_Direct_Cache_Access_info"
        || callother_opcode == "cpuid_Extended_Feature_Enumeration_info"
        || callother_opcode == "cpuid_Extended_Topology_info"
        || callother_opcode == "cpuid_MONITOR_MWAIT_Features_info"
        || callother_opcode == "cpuid_Processor_Extended_States_info"
        || callother_opcode == "cpuid_Quality_of_Service_info"
        || callother_opcode == "cpuid_Thermal_Power_Management_info"
        || callother_opcode == "cpuid_Version_info"
        || callother_opcode == "cpuid_basic_info"
        || callother_opcode == "cpuid_brand_part1_info"
        || callother_opcode == "cpuid_brand_part2_info"
        || callother_opcode == "cpuid_brand_part3_info"
        || callother_opcode == "cpuid_cache_tlb_info"
        || callother_opcode == "cpuid_serial_info" )
    {
      cpuid(callother_opcode);
      return result;
    }

    if ( callother_opcode == "vpxor_avx" )
    {
      ParseVariableResult vv0 = parse_variable(v0.rest, address_space_map);
      ParseVariableResult vv1 = parse_variable(vv0.rest, address_space_map);
      result.op = Op(OpKind::IntXor);
      result.inputs[0] = vv0.var;
      result.inputs[1] = vv1.var;
      result.rest = munch(vv1.rest);
      return result;
    }

    if ( callother_opcode == "vpand_avx" || callother_opcode == "vpand_avx2" )
    {
      ParseVariableResult vv0 = parse_variable(v0.rest, address_space_map);
      ParseVariableResult vv1 = parse_variable(vv0.rest, address_space_map);
      result.op = Op(OpKind::IntAnd);
      result.inputs[0] = vv0.var;
      result.inputs[1] = vv1.var;
      result.rest = munch(vv1.rest);
      return result;
    }

    if ( callother_opcode == "vpadd_avx2" || callother_opcode == "vpaddq_avx2"
        || callother_opcode == "vpaddq_avx" )
    {
      ParseVariableResult vv0 = parse_variable(v0.rest, address_space_map);
      ParseVariableResult vv1 = parse_variable(vv0.rest, address_space_map);
      result.op = Op(OpKind::IntAdd);
      result.inputs[0] = vv0.var;
      result.inputs[1] = vv1.var;
      result.rest = munch(vv1.rest);
      return result;
    }

    if ( callother_opcode == "vmovdqu_avx" )
    {
      ParseVariableResult vv = parse_variable(v0.rest, address_space_map);
      result.op = Op(OpKind::Copy);
      result.inputs[0] = vv.var;
      result.rest = munch(vv.rest);
      return result;
    }

    if ( callother_opcode == "vmovd_avx" || callother_opcode == "vmovq_avx" )
    {
      ParseVariableResult vv = parse_variable(v0.rest, address_space_map);
      auto in_size = vv.var.try_size();
      auto out_size = output.try_size();
      TREX_CHECK(in_size.has_value() && out_size.has_value(),
                 "vmovd/vmovq: sizes must be present");
      if ( *in_size < *out_size )
      {
        result.op = Op(OpKind::IntZext);
        result.inputs[0] = vv.var;
      }
      else if ( *in_size == *out_size )
      {
        result.op = Op(OpKind::Copy);
        result.inputs[0] = vv.var;
      }
      else
      {
        result.op = Op(OpKind::SubPiece);
        result.inputs[0] = vv.var;
        result.inputs[1] = Variable::constant(0, 1);
      }
      result.rest = munch(vv.rest);
      return result;
    }

    if ( callother_opcode == "vpunpcklwd_avx" || callother_opcode == "vpunpckldq_avx"
        || callother_opcode == "vpunpcklqdq_avx" || callother_opcode == "vpcmpeqb_avx2"
        || callother_opcode == "vpcmpeqb_avx" || callother_opcode == "vpsubb_avx2"
        || callother_opcode == "vpsadbw_avx2" || callother_opcode == "vpextrw_avx"
        || callother_opcode == "vextracti128_avx2" || callother_opcode == "vpshufb_avx"
        || callother_opcode == "vpsrldq_avx" )
    {
      ParseVariableResult vv0 = parse_variable(v0.rest, address_space_map);
      ParseVariableResult vv1 = parse_variable(vv0.rest, address_space_map);
      result.op = Op(OpKind::UnderspecifiedOutputModification);
      result.inputs[0] = vv0.var;
      result.inputs[1] = vv1.var;
      result.rest = munch(vv1.rest);
      return result;
    }

    if ( callother_opcode == "vpmovzxbw_avx" || callother_opcode == "vpmovzxwd_avx"
        || callother_opcode == "vpmovzxdq_avx" || callother_opcode == "vpmovzxbw_avx2"
        || callother_opcode == "vpmovzxwd_avx2" || callother_opcode == "vpmovzxdq_avx2" )
    {
      ParseVariableResult vv = parse_variable(v0.rest, address_space_map);
      result.op = Op(OpKind::UnderspecifiedOutputModification);
      result.inputs[0] = vv.var;
      result.rest = munch(vv.rest);
      return result;
    }

    if ( callother_opcode == "vpinsrb_avx" || callother_opcode == "vpinsrd_avx"
        || callother_opcode == "vpinsrq_avx" )
    {
      ParseVariableResult vv0 = parse_variable(v0.rest, address_space_map);
      ParseVariableResult vv1 = parse_variable(vv0.rest, address_space_map);
      ParseVariableResult vv2 = parse_variable(vv1.rest, address_space_map);
      TREX_CHECK(vv2.var.kind == VarKind::Constant,
                 "vpinsr*: third operand must be a Constant, got {}",
                 vv2.var.debug_string());
      result.op = Op(OpKind::UnderspecifiedOutputModification);
      result.inputs[0] = vv0.var;
      result.inputs[1] = vv1.var;
      result.rest = munch(vv2.rest);
      return result;
    }

    if ( callother_opcode == "LOCK" || callother_opcode == "UNLOCK" )
    {
      result.op = Op(OpKind::Nop);
      result.rest = munch(v0.rest);
      return result;
    }

    TREX_UNREACHABLE("Unknown CALLOTHER code {:#?}, rest = {:?}",
                     v0.var.debug_string(), std::string(v0.rest));
  }

  TREX_UNREACHABLE("Lifter for `{}` (rest = `{}`)", std::string(op_name), std::string(rest));
}

// ---------------------------------------------------------------------------
// parse_pcode_line
// ---------------------------------------------------------------------------
Instruction parse_pcode_line(std::string_view line, const AddressSpaceMap &address_space_map)
{
  size_t sp = line.find(' ');
  TREX_CHECK(sp != std::string_view::npos, "expected space after address in `{}`", std::string(line));
  uint64_t address = parse_hex(line.substr(0, sp));
  std::string_view rest = line.substr(sp + 1);
  // The Rust code rejoins the pcode tokens with a single space - matching
  // the file's whitespace is not load-bearing; what matters is that
  // `parse_op` sees the same operands in the same order. Use the raw rest.
  ParseOpResult po = parse_op(rest, address_space_map);
  // `parse_op` consumes trailing whitespace and the Rust code asserts the
  // remainder is empty (or just whitespace).
  std::string_view leftover = po.rest;
  while ( !leftover.empty() && (leftover.front() == ' ' || leftover.front() == '\t') )
    leftover.remove_prefix(1);
  TREX_CHECK(leftover.empty(),
             "Line unfinished {:?}", std::string(po.rest));

  Instruction ins;
  ins.address = address;
  ins.op = po.op;
  ins.output = po.output;
  ins.inputs[0] = po.inputs[0];
  ins.inputs[1] = po.inputs[1];
  ins.indirect_targets = std::move(po.indirect_targets);
  return ins;
}

// ---------------------------------------------------------------------------
// parse_unaffected_line
// ---------------------------------------------------------------------------
std::vector<Variable> parse_unaffected_line(std::string_view line,
                                            const AddressSpaceMap &address_space_map)
{
  std::string_view trimmed = line;
  while ( !trimmed.empty() && (trimmed.front() == ' ' || trimmed.front() == '\t') )
    trimmed.remove_prefix(1);

  size_t colon = trimmed.find(':');
  TREX_CHECK(colon != std::string_view::npos, "expected ':' in unaffected line `{}`", std::string(line));
  std::string_view ident = trimmed.substr(0, colon);
  while ( !ident.empty() && (ident.back() == ' ' || ident.back() == '\t') )
    ident.remove_suffix(1);
  std::string_view body = trimmed.substr(colon + 1);
  TREX_CHECK(ident == "Unaffected",
             "Expected `Unaffected`, got `{}`", std::string(ident));

  std::vector<Variable> res;
  std::string_view cur = body;
  while ( true )
  {
    while ( !cur.empty() && (cur.front() == ' ' || cur.front() == '\t') )
      cur.remove_prefix(1);
    if ( cur.empty() )
      break;
    ParseVariableResult pv = parse_variable(cur, address_space_map);
    res.push_back(pv.var);
    cur = pv.rest;
  }
  return res;
}

// ---------------------------------------------------------------------------
// parse_pcode_listing - applies the `CallStateMachine` to each line and
// groups IL instructions by machine address.
// ---------------------------------------------------------------------------
//
// State machine kept as a tagged enum (declared here to avoid dragging a
// private header into the public namespace).
class CallStateMachine
{
public:
  enum class State
  {
    NotInCall,
    AfterCallComment,
    AfterSubtractSP,
    AfterStoreRet,
  };

  State state = State::NotInCall;
  std::string subinsn; // populated when in AfterSubtractSP / AfterStoreRet
};

// Group consecutive IL instructions sharing the same `address` into one
// vector (this is the group-by on `Instruction::address` that upstream
// feeds to `Program::add_one_machine_instruction`).
std::vector<std::vector<Instruction>> group_by_address(
    const std::vector<Instruction> &flat)
{
  std::vector<std::vector<Instruction>> out;
  for ( const Instruction &ins : flat )
  {
    if ( !out.empty() && out.back()[0].address == ins.address )
    {
      out.back().push_back(ins);
    }
    else
    {
      out.emplace_back();
      out.back().push_back(ins);
    }
  }
  return out;
}

std::vector<std::vector<Instruction>> parse_pcode_listing(
    AuxDataWhenParsingPCodeListing &aux_data,
    const std::string &func_listing,
    const AddressSpaceMap &address_space_map)
{
  CallStateMachine sm;
  std::string latest_comment = "<begin>";
  std::vector<Instruction> flat;

  // Split on '\n', trim each line, and dispatch.
  std::string_view cur(func_listing.data(), func_listing.size());
  while ( !cur.empty() )
  {
    size_t nl = cur.find('\n');
    std::string_view line_raw = (nl == std::string_view::npos) ? cur : cur.substr(0, nl);
    cur = (nl == std::string_view::npos) ? std::string_view() : cur.substr(nl + 1);

    // Trim leading whitespace (mirror `.trim()`).
    std::string_view line = line_raw;
    while ( !line.empty() && (line.front() == ' ' || line.front() == '\t') )
      line.remove_prefix(1);
    while ( !line.empty() && (line.back() == ' ' || line.back() == '\t' || line.back() == '\r') )
      line.remove_suffix(1);

    if ( line.empty() )
      continue;

    if ( starts_with(line, ";;") )
    {
      size_t pos = line.find(";; ");
      std::string_view payload = (pos == std::string_view::npos)
                                     ? line.substr(2)
                                     : line.substr(pos + 3);
      latest_comment = std::string(payload);
      if ( contains(line, ";; CALL ") )
      {
        sm.state = CallStateMachine::State::AfterCallComment;
      }
      else
      {
        sm.state = CallStateMachine::State::NotInCall;
      }
      continue;
    }

    // The leading token is the hex machine address.
    size_t sp = line.find(' ');
    std::string_view addr_tok = (sp == std::string_view::npos) ? line : line.substr(0, sp);
    uint64_t address = parse_hex(addr_tok);

    aux_data.machine_addr_comments[address] = latest_comment;

    switch ( sm.state )
    {
      case CallStateMachine::State::NotInCall:
      {
        Instruction ins = parse_pcode_line(line, address_space_map);
        flat.push_back(std::move(ins));
        break;
      }
      case CallStateMachine::State::AfterCallComment:
      {
        if ( contains(line, " COPY ") || contains(line, " INT_ADD ")
            || contains(line, " LOAD ") || contains(line, " INT_MULT ") )
        {
          Instruction ins = parse_pcode_line(line, address_space_map);
          flat.push_back(std::move(ins));
        }
        else if ( contains(line, " INT_SUB ") )
        {
          if ( config().stack_pointer_patch_after_call_fallthrough )
          {
            size_t pos1 = line.find(") INT_SUB (");
            TREX_CHECK(pos1 != std::string_view::npos,
                       "INT_SUB after CALL: expected `) INT_SUB (` in `{}`", std::string(line));
            std::string_view left_part = line.substr(0, pos1);
            std::string_view right_part = line.substr(pos1 + std::string_view::size_type(
                                                          std::string(") INT_SUB (").size()));
            size_t lparen = left_part.find('(');
            TREX_CHECK(lparen != std::string_view::npos,
                       "INT_SUB after CALL: expected `(` in left `{}`", std::string(left_part));
            std::string_view left = left_part.substr(lparen + 1);
            size_t rparen = right_part.find(')');
            TREX_CHECK(rparen != std::string_view::npos,
                       "INT_SUB after CALL: expected `)` in right `{}`", std::string(right_part));
            std::string_view right = right_part.substr(0, rparen);
            TREX_CHECK(left == right, "Expected SP to be equal");
          }
          sm.subinsn = std::string(line);
          sm.state = CallStateMachine::State::AfterSubtractSP;
          Instruction ins = parse_pcode_line(line, address_space_map);
          flat.push_back(std::move(ins));
        }
        else
        {
          TREX_UNREACHABLE("Unexpected instruction after CALL comment: {}",
                           std::string(line));
        }
        break;
      }
      case CallStateMachine::State::AfterSubtractSP:
      {
        if ( config().stack_pointer_patch_after_call_fallthrough )
        {
          TREX_CHECK(contains(line, " STORE "),
                     "Expected STORE instruction after CALL comment and INT_SUB: {}",
                     std::string(line));
        }
        sm.state = CallStateMachine::State::AfterStoreRet;
        Instruction ins = parse_pcode_line(line, address_space_map);
        flat.push_back(std::move(ins));
        break;
      }
      case CallStateMachine::State::AfterStoreRet:
      {
        // Replace the literal substring "INT_SUB" with "INT_ADD" inside the
        // captured subinsn so we can re-parse it as the compensating add.
        std::string addinsn = sm.subinsn;
        size_t sub_pos = addinsn.find("INT_SUB");
        TREX_CHECK(sub_pos != std::string::npos,
                   "AfterStoreRet: subinsn missing INT_SUB: {}", addinsn);
        addinsn.replace(sub_pos, std::string("INT_SUB").size(), "INT_ADD");

        sm.state = CallStateMachine::State::NotInCall;

        std::string_view l = line;
        bool rewrite = contains(l, "---  BRANCH ")
                    && config().fix_ghidra_branch_to_next_insn_as_call_with_fallthrough;
        if ( rewrite )
        {
          log::trace("Fixing Ghidra branch -> callwithfallthrough",
                     { { "line", std::string(l) } });
          std::string rewritten(l);
          size_t br_pos = rewritten.find("---  BRANCH ");
          TREX_CHECK(br_pos != std::string::npos,
                     "AfterStoreRet: expected `---  BRANCH ` in `{}`", rewritten);
          rewritten.replace(br_pos,
                            std::string("---  BRANCH ").size(),
                            "---  CALLWITHFALLTHROUGH ");
          Instruction line1 = parse_pcode_line(std::string_view(rewritten), address_space_map);
          flat.push_back(std::move(line1));
        }
        else
        {
          Instruction line1 = parse_pcode_line(l, address_space_map);
          flat.push_back(std::move(line1));
        }

        if ( config().stack_pointer_patch_after_call_fallthrough )
        {
          // The last pushed instruction is line1; capture its first input.
          const Instruction &line1 = flat.back();
          log::trace("Fixing Ghidra stackpointer after call",
                     { { "line", std::string(l) },
                       { "addinsn", addinsn } });

          Instruction line2 = parse_pcode_line(std::string_view(addinsn), address_space_map);
          if ( line1.inputs[0].kind == VarKind::MachineAddress )
          {
            Variable sp = line2.output;
            aux_data.sp_fixups.push_back({ sp, line1.inputs[0].addr });
          }
          else
          {
            log::trace("Non-machine address, skipping SP fixup",
                       { { "line", std::string(l) },
                         { "line1", line1.debug_string() } });
          }
          flat.push_back(std::move(line2));
        }
        break;
      }
    }
  }

  return group_by_address(flat);
}

// ---------------------------------------------------------------------------
// lift_from
// ---------------------------------------------------------------------------

} // namespace

std::shared_ptr<Program> lift_program_from_lifted_text(const std::string &text)
{
  // The fixtures are checked out with CRLF on Windows; the upstream
  // `.starts_with("PROGRAM\n")` etc. only match LF (the Rust CI runs on
  // Linux where git leaves the files as LF). Normalize CRLF -> LF so
  // every check below sees the byte sequence the Rust code does.
  std::string text_n;
  text_n.reserve(text.size());
  for ( size_t i = 0; i < text.size(); ++i )
  {
    if ( text[i] == '\r' && i + 1 < text.size() && text[i + 1] == '\n' )
    {
      text_n.push_back('\n');
      ++i;
    }
    else
    {
      text_n.push_back(text[i]);
    }
  }
  std::string &in = text_n;

   // Sanity check that we have a lift-able `.pcode-exported` file.
  TREX_CHECK(starts_with(in, "PROGRAM\n"),
              "expected `PROGRAM\\n` at start of lifted text");
  TREX_CHECK(in.find("ADDRESS_SPACES\n") != std::string::npos,
              "expected `ADDRESS_SPACES\\n` section");
  TREX_CHECK(in.find("PCODE_LISTING\n") != std::string::npos,
              "expected `PCODE_LISTING\\n` section");


  // Grab the sections. Upstream splits the trimmed text on "\n\n" so each
  // section ends at the first blank line after its header.
  auto split_sections = [](const std::string &s) -> std::vector<std::string> {
    std::vector<std::string> out;
    size_t i = 0;
    while ( i < s.size() )
    {
      size_t j = s.find("\n\n", i);
      if ( j == std::string::npos )
      {
        out.emplace_back(s.substr(i));
        break;
      }
      out.emplace_back(s.substr(i, j - i));
      i = j + 2;
    }
    return out;
  };

  std::string trimmed = in;
  // Mirror `.trim()` on the upstream side; .trim_end() would also suffice.
  size_t lead = 0;
  while ( lead < trimmed.size()
          && (trimmed[lead] == ' ' || trimmed[lead] == '\n'
              || trimmed[lead] == '\t' || trimmed[lead] == '\r') )
    ++lead;
  size_t trail = trimmed.size();
  while ( trail > lead
          && (trimmed[trail - 1] == ' ' || trimmed[trail - 1] == '\n'
              || trimmed[trail - 1] == '\t' || trimmed[trail - 1] == '\r') )
    --trail;
  trimmed = trimmed.substr(lead, trail - lead);

  std::vector<std::string> raw_sections = split_sections(trimmed);
  TREX_CHECK(raw_sections.size() >= 3,
             "expected at least three sections (PROGRAM / ADDRESS_SPACES / PCODE_LISTING)");

  // Section 1: PROGRAM
  std::string program_section = raw_sections[0];
  TREX_CHECK(starts_with(program_section, "PROGRAM\n"),
             "first section must start with `PROGRAM\\n`");
  program_section = program_section.substr(std::string("PROGRAM\n").size());
  // Trim the section body.
  size_t p_lead = 0;
  while ( p_lead < program_section.size()
          && (program_section[p_lead] == ' ' || program_section[p_lead] == '\n'
              || program_section[p_lead] == '\t' || program_section[p_lead] == '\r') )
    ++p_lead;
  size_t p_trail = program_section.size();
  while ( p_trail > p_lead
          && (program_section[p_trail - 1] == ' ' || program_section[p_trail - 1] == '\n'
              || program_section[p_trail - 1] == '\t' || program_section[p_trail - 1] == '\r') )
    --p_trail;
  program_section = program_section.substr(p_lead, p_trail - p_lead);

  // Section 2: ADDRESS_SPACES
  std::string addr_spaces_section = raw_sections[1];
  TREX_CHECK(starts_with(addr_spaces_section, "ADDRESS_SPACES\n"),
             "second section must start with `ADDRESS_SPACES\\n`");
  addr_spaces_section = addr_spaces_section.substr(std::string("ADDRESS_SPACES\n").size());
  // Trim.
  size_t a_lead = 0;
  while ( a_lead < addr_spaces_section.size()
          && (addr_spaces_section[a_lead] == ' ' || addr_spaces_section[a_lead] == '\n'
              || addr_spaces_section[a_lead] == '\t' || addr_spaces_section[a_lead] == '\r') )
    ++a_lead;
  size_t a_trail = addr_spaces_section.size();
  while ( a_trail > a_lead
          && (addr_spaces_section[a_trail - 1] == ' ' || addr_spaces_section[a_trail - 1] == '\n'
              || addr_spaces_section[a_trail - 1] == '\t' || addr_spaces_section[a_trail - 1] == '\r') )
    --a_trail;
  addr_spaces_section = addr_spaces_section.substr(a_lead, a_trail - a_lead);

  // Sections 3..N: PCODE_LISTING (everything else). Strip the prefix.
  std::vector<std::string> pcode_listing_sections;
  for ( size_t i = 2; i < raw_sections.size(); ++i )
    pcode_listing_sections.push_back(std::move(raw_sections[i]));
  TREX_CHECK(!pcode_listing_sections.empty(),
             "expected at least one PCODE_LISTING section");
  std::string first_pl = pcode_listing_sections[0];
  TREX_CHECK(starts_with(first_pl, "PCODE_LISTING"),
             "third section must start with `PCODE_LISTING`");
  first_pl = first_pl.substr(std::string("PCODE_LISTING").size());
  // Trim leading whitespace.
  size_t pl_lead = 0;
  while ( pl_lead < first_pl.size()
          && (first_pl[pl_lead] == ' ' || first_pl[pl_lead] == '\n'
              || first_pl[pl_lead] == '\t' || first_pl[pl_lead] == '\r') )
    ++pl_lead;
  first_pl = first_pl.substr(pl_lead);
  pcode_listing_sections[0] = first_pl;

  // Parse the program section: `name <name>\nbig_endian <bool>`.
  auto next_program_line = [&](size_t &i, std::string &out) -> bool {
    out.clear();
    while ( i < program_section.size() && program_section[i] == '\n' )
      ++i;
    size_t start = i;
    while ( i < program_section.size() && program_section[i] != '\n' )
      ++i;
    if ( i == start )
      return false;
    out = program_section.substr(start, i - start);
    return true;
  };

  size_t pi = 0;
  std::string line1, line2;
  TREX_CHECK(next_program_line(pi, line1), "expected `name` line in PROGRAM section");
  TREX_CHECK(next_program_line(pi, line2), "expected `big_endian` line in PROGRAM section");

  // Tokenize each line: split on spaces.
  auto tokens = [](const std::string &s) -> std::vector<std::string> {
    std::vector<std::string> out;
    size_t i = 0;
    while ( i < s.size() )
    {
      while ( i < s.size() && (s[i] == ' ' || s[i] == '\t') )
        ++i;
      size_t j = i;
      while ( j < s.size() && s[j] != ' ' && s[j] != '\t' )
        ++j;
      if ( j == i )
        break;
      out.emplace_back(s.substr(i, j - i));
      i = j;
    }
    return out;
  };

  std::vector<std::string> name_tokens = tokens(line1);
  std::string program_name;
  TREX_CHECK(name_tokens.size() == 2 && name_tokens[0] == "name",
             "Expected `name`, got `{}`", line1);
  program_name = name_tokens[1];

  std::vector<std::string> endian_tokens = tokens(line2);
  Endian endianness;
  TREX_CHECK(endian_tokens.size() == 2 && endian_tokens[0] == "big_endian",
             "Expected `big_endian`, got `{}`", line2);
  if ( endian_tokens[1] == "false" )
    endianness = Endian::Little;
  else if ( endian_tokens[1] == "true" )
    endianness = Endian::Big;
  else
    TREX_UNREACHABLE("Expected `big_endian` to be true/false, got `{}`", endian_tokens[1]);

  (void)program_name; // upstream discards the name too

  // Parse address spaces. Each non-empty line is "<idx> <name> <wordsize>".
  std::vector<std::string> addr_lines;
  {
    size_t i = 0;
    while ( i < addr_spaces_section.size() )
    {
      size_t j = i;
      while ( j < addr_spaces_section.size() && addr_spaces_section[j] != '\n' )
        ++j;
      std::string line = addr_spaces_section.substr(i, j - i);
      i = (j < addr_spaces_section.size()) ? j + 1 : addr_spaces_section.size();
      // Trim.
      size_t a = 0;
      while ( a < line.size() && (line[a] == ' ' || line[a] == '\t') )
        ++a;
      size_t b = line.size();
      while ( b > a && (line[b - 1] == ' ' || line[b - 1] == '\t' || line[b - 1] == '\r') )
        --b;
      if ( a >= b )
        continue;
      addr_lines.push_back(line.substr(a, b - a));
    }
  }

  // First pass: pull out the ram wordsize.
  size_t ram_wordsize = 0;
  bool found_ram = false;
  for ( const std::string &ln : addr_lines )
  {
    std::vector<std::string> t = tokens(ln);
    TREX_CHECK(t.size() == 3, "address-space line must have 3 tokens: `{}`", ln);
    if ( t[1] == "ram" )
    {
      ram_wordsize = parse_dec(t[2]);
      found_ram = true;
      break;
    }
  }
  TREX_CHECK(found_ram, "no address space named `ram` in ADDRESS_SPACES");

  // Build the deterministic address-space vector in source order, then
  // append the two synthetic entries (`unique`, `register`) exactly as
  // upstream's `chain(std::iter::once(...))` does.
  std::vector<AddressSpace> address_spaces;
  address_spaces.reserve(addr_lines.size() + 2);
  for ( const std::string &ln : addr_lines )
  {
    std::vector<std::string> t = tokens(ln);
    TREX_CHECK(t.size() == 3, "address-space line must have 3 tokens: `{}`", ln);
    size_t ghidra_idx = parse_dec(t[0]);
    (void)ghidra_idx; // not used directly; the index in our vector is its
                      // position, which matches upstream's `enumerate()`
                      // since upstream inserts in source order too.
    address_spaces.push_back(AddressSpace{ t[1], endianness, parse_dec(t[2]) });
  }
  address_spaces.push_back(AddressSpace{ "unique", endianness, ram_wordsize });
  address_spaces.push_back(AddressSpace{ "register", endianness, ram_wordsize });

  // Build the (key -> (our_idx, AddressSpace)) map.
  AddressSpaceMap address_space_map;
  for ( size_t i = 0; i < addr_lines.size(); ++i )
  {
    std::vector<std::string> t = tokens(addr_lines[i]);
    size_t ghidra_idx = parse_dec(t[0]);
    address_space_map[Key{ KeyKind::Ok, ghidra_idx }] = { i, address_spaces[i] };
  }
  // Synthetics point at the last two indices.
  address_space_map[Key{ KeyKind::Unique }] = {
    address_spaces.size() - 2, address_spaces[address_spaces.size() - 2]
  };
  address_space_map[Key{ KeyKind::Register }] = {
    address_spaces.size() - 1, address_spaces.back()
  };

  // Parse the p-code listing section(s). Each non-empty top-level block is
  // one function: `<hex> <name>\n[Unaffected: ...\n]<pcode lines>`.
  std::vector<std::tuple<uint64_t, std::string,
                         std::vector<Variable>, std::vector<std::vector<Instruction>>>>
      parsed_functions;

  AuxDataWhenParsingPCodeListing aux;

  for ( const std::string &func_block : pcode_listing_sections )
  {
    // Each block is a sequence of <\n-separated> lines. Split it.
    std::vector<std::string> flines;
    size_t i = 0;
    while ( i < func_block.size() )
    {
      size_t j = i;
      while ( j < func_block.size() && func_block[j] != '\n' )
        ++j;
      std::string line = func_block.substr(i, j - i);
      i = (j < func_block.size()) ? j + 1 : func_block.size();
      size_t a = 0;
      while ( a < line.size() && (line[a] == ' ' || line[a] == '\t') )
        ++a;
      size_t b = line.size();
      while ( b > a && (line[b - 1] == ' ' || line[b - 1] == '\t' || line[b - 1] == '\r') )
        --b;
      if ( a >= b )
        continue;
      flines.push_back(line.substr(a, b - a));
    }
    if ( flines.empty() )
      continue;

    // First line: `<hex> <name>`.
    std::string header = flines.front();
    std::vector<std::string> header_tokens = tokens(header);
    TREX_CHECK(header_tokens.size() >= 2,
               "function header must have at least two tokens: `{}`", header);
    uint64_t entry_point = parse_hex(header_tokens[0]);
    std::string fn_name = header_tokens[1];

    std::vector<Variable> unaffected;
    std::vector<std::vector<Instruction>> fn_ins_list;
    if ( flines.size() == 1 )
    {
      // No body.
    }
    else if ( flines.size() >= 2 )
    {
      std::string second = flines[1];
      if ( starts_with(second, "Unaffected") )
      {
        unaffected = parse_unaffected_line(second, address_space_map);
        std::string body;
        for ( size_t k = 2; k < flines.size(); ++k )
        {
          if ( k > 2 )
            body += "\n";
          body += flines[k];
        }
        fn_ins_list = parse_pcode_listing(aux, body, address_space_map);
      }
      else
      {
        std::string body;
        for ( size_t k = 1; k < flines.size(); ++k )
        {
          if ( k > 1 )
            body += "\n";
          body += flines[k];
        }
        fn_ins_list = parse_pcode_listing(aux, body, address_space_map);
      }
    }
    parsed_functions.emplace_back(entry_point, fn_name, std::move(unaffected),
                                   std::move(fn_ins_list));
  }

  // Build the program.
  Program prog = Program::create(address_spaces);
  for ( auto &[entry_point, fn_name, unaffected, fn_ins_list] : parsed_functions )
  {
    prog.begin_function(fn_name, unaffected, entry_point);
    for ( std::vector<Instruction> &il_inss : fn_ins_list )
    {
      prog.add_one_machine_instruction(il_inss);
    }
    prog.end_function();
  }
  for ( const auto &[sp, mc_target] : aux.sp_fixups )
  {
    log::trace("SP unaffected fixup",
               { { "sp", sp.debug_string() }, { "target", mc_target } });
    prog.add_aux_data_for_stack_pointer_fixups(sp, mc_target);
  }
  for ( const auto &[mc_addr, comm] : aux.machine_addr_comments )
  {
    prog.add_comment_to_machine_address(mc_addr, comm);
  }

  return std::make_shared<Program>(std::move(prog));
}

} // namespace trex