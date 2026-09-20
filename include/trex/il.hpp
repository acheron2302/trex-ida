#pragma once

// Intermediate language to aid type inference - port of upstream `trex/src/il.rs`.
//
// Every analysis pass in the port operates on these types, so their declaration order is
// load-bearing: Rust's derived Ord/Hash for `Op` and `Variable` orders by variant index and
// then by field declaration order, and those orderings are used by the deterministic
// (BTree-backed) containers that produce the compared output.

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <ostream>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <trex/aslocation.hpp>
#include <trex/error.hpp>
#include <trex/log.hpp>

namespace trex {

//--------------------------------------------------------------------------
// Op
//--------------------------------------------------------------------------

/// Discriminant for Op. Declaration order matches upstream `enum Op` exactly.
enum class OpKind : uint16_t
{
  BoolAnd = 0,
  BoolNegate,
  BoolOr,
  BoolXor,
  Branch,
  BranchIndOffset,
  CallWithFallthrough,
  CallWithNoFallthrough,
  CallWithFallthroughIndirect,
  CallWithNoFallthroughIndirect,
  Cbranch,
  Copy,
  Float2Float,
  Float2IntTrunc,
  FloatAbs,
  FloatAdd,
  FloatDiv,
  FloatEqual,
  FloatNotEqual,
  FloatLess,
  FloatLessEqual,
  FloatIsNan,
  FloatMult,
  FloatNeg,
  FloatRound,
  FloatSqrt,
  FloatSub,
  Int2Float,
  IntAdd,
  IntAnd,
  IntCarry,
  IntEqual,
  IntNotEqual,
  IntLess,
  IntMult,
  IntOr,
  IntSBorrow,
  IntSCarry,
  IntUDiv,
  IntSDiv,
  IntURem,
  IntSRem,
  IntSext,
  IntSLess,
  IntLeftShift,
  IntURightShift,
  IntSRightShift,
  IntSub,
  IntOnesComp,
  IntTwosComp,
  IntXor,
  IntZext,
  Load,
  Popcount,
  Return,
  Store,
  Piece,
  SubPiece,
  FunctionStart,
  FunctionEnd,
  Nop,
  ProcessorException,
  ScalarLowerOp,
  ScalarUpperOp,
  PackedVectorOp,
  UnderspecifiedOutputModification,
  UnderspecifiedNoOutput,
};

/// An IL vector operation that operates on scalar sub-parts of Variables.
enum class VectorScalarOp : uint8_t
{
  FloatAdd = 0,
  FloatSub,
  FloatMul,
  FloatDiv,
  LogicalShiftLeft,
};

/// An IL operation that operates on Variables.
///
/// Rust models this as an enum with a payload on the three vector variants; the port keeps a
/// discriminant plus the payload fields so that comparison and hashing stay trivial. For every
/// non-vector variant `scalar_bits`/`vsop` are the defaults below, so equality and ordering are
/// identical to the Rust enum's derived implementations.
struct Op
{
  OpKind kind = OpKind::Nop;
  uint8_t scalar_bits = 0;
  VectorScalarOp vsop = VectorScalarOp::FloatAdd;

  Op() = default;
  explicit Op(OpKind k) : kind(k) {}

  static Op simple(OpKind k) { return Op(k); }
  static Op scalar_lower(uint8_t n, VectorScalarOp v)
  {
    Op o(OpKind::ScalarLowerOp);
    o.scalar_bits = n;
    o.vsop = v;
    return o;
  }
  static Op scalar_upper(uint8_t n, VectorScalarOp v)
  {
    Op o(OpKind::ScalarUpperOp);
    o.scalar_bits = n;
    o.vsop = v;
    return o;
  }
  static Op packed_vector(uint8_t n, VectorScalarOp v)
  {
    Op o(OpKind::PackedVectorOp);
    o.scalar_bits = n;
    o.vsop = v;
    return o;
  }

  bool is_vector() const
  {
    return kind == OpKind::ScalarLowerOp || kind == OpKind::ScalarUpperOp
        || kind == OpKind::PackedVectorOp;
  }

  std::string debug_string() const;
  std::string name() const;

  friend bool operator==(const Op &a, const Op &b)
  {
    return a.kind == b.kind && a.scalar_bits == b.scalar_bits && a.vsop == b.vsop;
  }
  friend bool operator!=(const Op &a, const Op &b) { return !(a == b); }
  friend bool operator<(const Op &a, const Op &b)
  {
    if ( a.kind != b.kind )
      return (uint16_t)a.kind < (uint16_t)b.kind;
    if ( a.scalar_bits != b.scalar_bits )
      return a.scalar_bits < b.scalar_bits;
    return (uint8_t)a.vsop < (uint8_t)b.vsop;
  }
};

//--------------------------------------------------------------------------
// Variable
//--------------------------------------------------------------------------

/// Discriminant for Variable. Declaration order matches upstream `enum Variable` exactly.
enum class VarKind : uint8_t
{
  Unused = 0,
  Varnode,
  DerefVarnode,
  Constant,
  MachineAddress,
  ILAddress,
  ILOffset,
  StackVariable,
};

/// An input to or output from an Op.
///
/// Storage note: the Rust enum's variants are mutually exclusive; the port keeps all payload
/// fields in one (small, trivially copyable) struct keyed by `kind`. Only the fields that belong
/// to `kind` are meaningful, and `operator==`/`operator<` compare `kind` first and then the
/// fields in Rust declaration order, which reproduces the derived implementations exactly.
struct Variable
{
  VarKind kind = VarKind::Unused;

  // Varnode
  size_t address_space_idx = 0;
  size_t offset = 0;
  size_t size = 0;

  // DerefVarnode
  size_t derefval_address_space_idx = 0;
  size_t derefval_size = 0;
  size_t addr_address_space_idx = 0;
  size_t addr_offset = 0;

  // Constant
  uint64_t value = 0;

  // MachineAddress
  uint64_t addr = 0;

  // ILOffset
  int64_t il_offset = 0;

  // StackVariable
  int64_t stack_offset = 0;
  size_t var_size = 0;

  Variable() = default;

  static Variable unused() { return Variable(); }

  static Variable varnode(size_t as_idx, size_t off, size_t sz)
  {
    Variable v;
    v.kind = VarKind::Varnode;
    v.address_space_idx = as_idx;
    v.offset = off;
    v.size = sz;
    return v;
  }

  static Variable deref_varnode(size_t derefval_as, size_t derefval_sz, size_t addr_as, size_t addr_off)
  {
    Variable v;
    v.kind = VarKind::DerefVarnode;
    v.derefval_address_space_idx = derefval_as;
    v.derefval_size = derefval_sz;
    v.addr_address_space_idx = addr_as;
    v.addr_offset = addr_off;
    return v;
  }

  static Variable constant(uint64_t val, size_t sz)
  {
    Variable v;
    v.kind = VarKind::Constant;
    v.value = val;
    v.size = sz;
    return v;
  }

  static Variable machine_address(uint64_t a)
  {
    Variable v;
    v.kind = VarKind::MachineAddress;
    v.addr = a;
    return v;
  }

  static Variable iladdress(size_t a)
  {
    Variable v;
    v.kind = VarKind::ILAddress;
    v.offset = a;
    return v;
  }

  static Variable iloffset(int64_t o)
  {
    Variable v;
    v.kind = VarKind::ILOffset;
    v.il_offset = o;
    return v;
  }

  static Variable stack_variable(int64_t off, size_t sz)
  {
    Variable v;
    v.kind = VarKind::StackVariable;
    v.stack_offset = off;
    v.var_size = sz;
    return v;
  }

  std::optional<size_t> try_size() const;
  std::optional<ASLocation> try_to_aslocation() const;
  bool is_used() const { return kind != VarKind::Unused; }
  ASLocation to_aslocation() const;
  Variable machine_addr_to_il_if_possible(const class Program &program) const;

  std::string debug_string() const;

  friend bool operator==(const Variable &a, const Variable &b);
  friend bool operator!=(const Variable &a, const Variable &b) { return !(a == b); }
  friend bool operator<(const Variable &a, const Variable &b);
};

//--------------------------------------------------------------------------
// Program pieces
//--------------------------------------------------------------------------

enum class Endian : uint8_t
{
  Big = 0,
  Little,
};

/// Description of a specific address space.
struct AddressSpace
{
  std::string name;
  Endian endianness = Endian::Little;
  size_t wordsize = 0;

  AddressSpace() = default;
  AddressSpace(std::string n, Endian e, size_t w) : name(std::move(n)), endianness(e), wordsize(w) {}
};

/// An IL instruction.
///
/// Original processor instructions may be translated to one or more IL instructions.
struct Instruction
{
  /// The address of the original processor instruction this instruction was translated from.
  uint64_t address = 0;
  /// The actual operation performed by the instruction.
  Op op = Op(OpKind::Nop);
  /// The output of the instruction (Variable::Unused if it produces none).
  Variable output;
  /// The inputs to the instruction (unused inputs are Variable::Unused).
  Variable inputs[2];
  /// Indirect jump targets; only valid for indirect branch and indirect call instructions.
  std::vector<Variable> indirect_targets;

  std::optional<std::string> try_confirm_valid() const;
  void confirm_valid() const;
  std::string debug_string() const;

  friend bool operator==(const Instruction &a, const Instruction &b);
  friend bool operator!=(const Instruction &a, const Instruction &b) { return !(a == b); }
};

/// Per-function record: name, callee-saved set, basic block indexes and (machine, IL) entry.
struct FunctionInfo
{
  std::string name;
  std::set<Variable> unaffected;
  std::set<size_t> basic_blocks;
  /// (machine address of the entry point, IL PC of the FunctionStart sentinel)
  std::pair<uint64_t, size_t> entry = { 0, 0 };
};

/// The actual program (port of `struct Program`).
class Program
{
public:
  /// Pre-defined address-spaces in the program.
  std::vector<AddressSpace> address_spaces;
  /// The actual executable instructions.
  std::vector<Instruction> instructions;
  /// Mapping of original processor addresses to a contiguous range of IL instructions,
  /// as (offset, length). The FunctionStart/FunctionEnd sentinels are not in this mapping.
  std::map<uint64_t, std::pair<size_t, size_t>> address_mapping;
  /// List of basic blocks; each block is a list of indexes into `instructions`.
  std::vector<std::vector<size_t>> basic_blocks;
  /// List of functions in the program.
  std::vector<FunctionInfo> functions;
  /// Size of a pointer in this program.
  size_t pointer_size = 0;
  /// Auxiliary data for stack pointer fixups
  /// (invariant: only set when CONFIG.stack_pointer_patch_after_call_fallthrough).
  std::optional<std::pair<Variable, std::set<uint64_t>>> aux_data_for_stack_pointer_fixups;
  /// Comments on machine instructions, used only for debugging purposes.
  std::map<uint64_t, std::string> machine_insn_comments;

  /// Build a new empty program with the allowed address spaces.
  /// (Upstream name: `Program::new`.)
  static Program create(std::vector<AddressSpace> address_spaces);

  void begin_function(std::string name, std::vector<Variable> unaffected, uint64_t entry_point);
  void end_function();
  void add_one_machine_instruction(std::vector<Instruction> instructions);

  std::optional<std::pair<size_t, size_t>> get_il_addrs_for_machine_addr(uint64_t machine_addr) const;
  std::vector<size_t> get_successor_instruction_addresses_for(size_t il_addr) const;

  void add_aux_data_for_stack_pointer_fixups(Variable sp, uint64_t machine_addr_target);
  void add_comment_to_machine_address(uint64_t machine_addr, const std::string &comment);

  /// Get the function index for an arbitrary IL PC.
  size_t function_index_for_il_ip(size_t il_pc) const;
  /// Get the FunctionStart IL PC for an arbitrary IL PC.
  size_t function_start_il_ip_for_il_ip(size_t il_pc) const;
  /// Get the unaffected variables for a call to `target`.
  std::set<Variable> get_unaffected_variables_for_call_to(const Variable &target, size_t caller_il_pc) const;

  /// Sanity check used by the frontends: IL addresses must never be used as operands.
  void assert_no_il_addresses_in(const std::vector<Instruction> &instructions) const;
};

/// A representation of the external IL variable.
struct ExternalVariable
{
  std::string name;

  ExternalVariable() = default;
  explicit ExternalVariable(std::string n) : name(std::move(n)) {}

  std::string to_string() const { return name; }

  friend bool operator==(const ExternalVariable &a, const ExternalVariable &b) { return a.name == b.name; }
  friend bool operator!=(const ExternalVariable &a, const ExternalVariable &b) { return !(a == b); }
  friend bool operator<(const ExternalVariable &a, const ExternalVariable &b) { return a.name < b.name; }

  /// Upstream implements `Display` for ExternalVariable; this is its C++ counterpart.
  friend std::ostream &operator<<(std::ostream &os, const ExternalVariable &v) { return os << v.name; }
};

/// A mapping between the internal IL variables and the variables for which types are expected
/// to be reconstructed.
struct ILVariableMap
{
  /// external variable -> (function index, internal IL variables within that function)
  std::map<ExternalVariable, std::pair<size_t, std::vector<Variable>>> varmap;
  /// The stack pointer used in this program: (name, variable)
  std::pair<std::string, Variable> stack_pointer;
};

} // namespace trex
