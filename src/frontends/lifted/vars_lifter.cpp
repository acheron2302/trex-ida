// Reference (Ghidra-text) variable lifter for TRex - port of upstream
// `trex/src/ghidra_variable_lifter.rs::lift_from`.
//
// Parses the textual `.vars` file that the upstream `VariableExporter.java`
// script emits. The output is a `trex::ILVariableMap` mapping each
// `name@function@<8-hex-digits>` ExternalVariable to one (or more) internal
// IL `Variable`s - either a `Varnode` in one of the program's address
// spaces, or a `StackVariable` for entries located in Ghidra's "stack"
// pseudo-space.

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <trex/error.hpp>
#include <trex/il.hpp>
#include <trex/lifted_frontend.hpp>
#include <trex/log.hpp>

namespace trex {
namespace {

bool starts_with(std::string_view s, std::string_view p)
{
  return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}

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

// ---------------------------------------------------------------------------
// parse_varnode
//
// Parses one `(space, 0xOFFSET, size)` tuple from a `.vars` line. Returns
// `Some(Variable)` for spaces the program knows about, including
// `Variable::StackVariable` for Ghidra's "stack" pseudo-space.
// ---------------------------------------------------------------------------
std::optional<Variable> parse_varnode(std::string_view s,
                                      const ExternalVariable &extvar,
                                      const Program &prog)
{
  // Trim leading whitespace.
  while ( !s.empty() && (s.front() == ' ' || s.front() == '\t') )
    s.remove_prefix(1);
  TREX_CHECK(starts_with(s, "("),
             "expected `(` at start of variable `{}` (extvar {})",
             std::string(s), extvar.name);
  TREX_CHECK(s.back() == ')',
             "expected `)` at end of variable `{}` (extvar {})",
             std::string(s), extvar.name);
  std::string_view inner = s.substr(1, s.size() - 2);

  std::vector<std::string_view> parts;
  size_t i = 0;
  while ( i <= inner.size() )
  {
    size_t j = inner.find(',', i);
    if ( j == std::string_view::npos )
    {
      parts.push_back(inner.substr(i));
      break;
    }
    parts.push_back(inner.substr(i, j - i));
    i = j + 1;
  }
  // Trim each part.
  auto trim = [](std::string_view p) -> std::string_view {
    size_t a = 0;
    while ( a < p.size() && (p[a] == ' ' || p[a] == '\t') )
      ++a;
    size_t b = p.size();
    while ( b > a && (p[b - 1] == ' ' || p[b - 1] == '\t') )
      --b;
    return p.substr(a, b - a);
  };

  TREX_CHECK(parts.size() == 3, "variable `{}` (extvar {}) must have 3 parts",
             std::string(s), extvar.name);
  std::string_view addrspace = trim(parts[0]);
  std::string_view offset_sv = trim(parts[1]);
  std::string_view size_sv = trim(parts[2]);

  TREX_CHECK(starts_with(offset_sv, "0x") || starts_with(offset_sv, "0X"),
             "expected `0x` prefix on offset `{}` (extvar {})",
             std::string(offset_sv), extvar.name);
  uint64_t offset = parse_hex(offset_sv);
  uint64_t size = parse_dec(size_sv);

  // Look the space up in the program.
  for ( size_t idx = 0; idx < prog.address_spaces.size(); ++idx )
  {
    if ( prog.address_spaces[idx].name == std::string(addrspace) )
    {
      TREX_CHECK(offset <= std::numeric_limits<size_t>::max(),
                 "offset overflow");
      TREX_CHECK(size <= std::numeric_limits<size_t>::max(),
                 "size overflow");
      return Variable::varnode(idx,
                                static_cast<size_t>(offset),
                                static_cast<size_t>(size));
    }
  }
  if ( addrspace == "stack" )
  {
    TREX_CHECK(size <= std::numeric_limits<size_t>::max(),
               "size overflow");
    // Rust uses `offset as u64 as i64` which is bit-reinterpret - same
    // numeric value on both 32- and 64-bit hosts for unsigned <=2^63.
    int64_t signed_off = static_cast<int64_t>(offset);
    return Variable::stack_variable(signed_off, static_cast<size_t>(size));
  }
  log::debug("Could not find the address space. Ignoring variable.",
             { { "var", std::string(addrspace) + ",0x" + std::to_string(offset) + "," + std::to_string(size) },
               { "extvar", extvar.name } });
  (void)extvar;
  return std::nullopt;
}

// Trim leading and trailing ASCII whitespace.
std::string_view trim_view(std::string_view s)
{
  size_t a = 0;
  while ( a < s.size() && (s[a] == ' ' || s[a] == '\t' || s[a] == '\n' || s[a] == '\r') )
    ++a;
  size_t b = s.size();
  while ( b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\n' || s[b - 1] == '\r') )
    --b;
  return s.substr(a, b - a);
}

// Split `s` on the first occurrence of `d`, returning (head, tail). On
// failure panics with TREX_CHECK.
std::pair<std::string_view, std::string_view> split_once_or_panic(std::string_view s, char d)
{
  size_t p = s.find(d);
  TREX_CHECK(p != std::string_view::npos,
             "expected `{}` in `{}`", d, std::string(s));
  return { s.substr(0, p), s.substr(p + 1) };
}

} // namespace

ILVariableMap lift_variable_map_from_vars_text(const std::string &text,
                                               const std::shared_ptr<const Program> &prog)
{
  TREX_CHECK(prog != nullptr, "lift_variable_map_from_vars_text: prog is null");
  const Program &p = *prog;
  std::string in;
  in.reserve(text.size());
  for ( size_t i = 0; i < text.size(); ++i )
  {
    if ( text[i] == '\r' && i + 1 < text.size() && text[i + 1] == '\n' )
    {
      in.push_back('\n');
      ++i;
    }
    else
    {
      in.push_back(text[i]);
    }
  }


  // Collect the program-section lines: lines between `PROGRAM` and the
  // next blank line (or the end).
  std::vector<std::string_view> program_section;
  std::string_view sv(in.data(), in.size());
  size_t i = 0;
  // Find "PROGRAM\n".
  size_t program_pos = sv.find("PROGRAM\n");
  TREX_CHECK(program_pos != std::string_view::npos,
             "expected `PROGRAM\\n` (already checked)");
  i = program_pos + std::string_view::size_type(std::string("PROGRAM\n").size());

  while ( i < sv.size() )
  {
    size_t nl = sv.find('\n', i);
    std::string_view line = (nl == std::string_view::npos)
                                ? sv.substr(i)
                                : sv.substr(i, nl - i);
    i = (nl == std::string_view::npos) ? sv.size() : nl + 1;
    if ( trim_view(line).empty() )
      break;
    program_section.push_back(line);
  }

  TREX_CHECK(program_section.size() >= 2,
             "expected at least 2 lines in PROGRAM section");
  TREX_CHECK(starts_with(trim_view(program_section[0]), "name"),
             "expected `name` line in PROGRAM section, got `{}`",
             std::string(program_section[0]));
  TREX_CHECK(starts_with(trim_view(program_section[1]), "stack_pointer"),
             "expected `stack_pointer` line in PROGRAM section, got `{}`",
             std::string(program_section[1]));

  // The stack pointer line is tab-separated: `<symbol>\t<varnode>\t<index>`
  // Upstream splits by `\t` and asserts 3 fields; we follow suit.
  std::string sp_line(program_section[1]);
  std::vector<std::string_view> sp_fields;
  size_t pos = 0;
  while ( pos <= sp_line.size() )
  {
    size_t tab = sp_line.find('\t', pos);
    if ( tab == std::string::npos )
    {
      sp_fields.push_back(std::string_view(sp_line).substr(pos));
      break;
    }
    sp_fields.push_back(std::string_view(sp_line).substr(pos, tab - pos));
    pos = tab + 1;
  }
  TREX_CHECK(sp_fields.size() == 3,
             "stack_pointer line must have 3 tab-separated fields, got {}",
             sp_fields.size());
  std::string sp_name(sp_fields[1]);
  Variable sp_var = parse_varnode(sp_fields[2], ExternalVariable(sp_name), p)
                        .value_or(Variable::unused());

  // Collect the variables section.
  std::vector<std::string_view> vars;
  size_t variables_pos = sv.find("VARIABLES\n");
  TREX_CHECK(variables_pos != std::string_view::npos,
             "expected `VARIABLES\\n` (already checked)");
  i = variables_pos + std::string_view::size_type(std::string("VARIABLES\n").size());
  while ( i < sv.size() )
  {
    size_t nl = sv.find('\n', i);
    std::string_view line = (nl == std::string_view::npos)
                                ? sv.substr(i)
                                : sv.substr(i, nl - i);
    i = (nl == std::string_view::npos) ? sv.size() : nl + 1;
    if ( trim_view(line).empty() )
      break;
    vars.push_back(line);
  }

  // Parse the variables. Upstream uses a peekable iterator and a
  // "while let Some(line) = lines.next()" loop; the inner lines starting
  // with `\t\t` belong to the previous external variable.
  ILVariableMap res;
  res.stack_pointer = { sp_name, sp_var };

  size_t k = 0;
  while ( k < vars.size() )
  {
    // NOTE: the leading-tab checks must look at the *raw* line: trimming first would remove the
    // very tabs the format is defined by (upstream checks `line.starts_with('\t')` before any
    // trimming, and only uses `trim()` to detect blank separator lines).
    const std::string_view raw = vars[k];
    if ( trim_view(raw).empty() )
    {
      ++k;
      continue;
    }
    TREX_CHECK(!starts_with(raw, "\t\t"),
               "stray double-tab line in VARIABLES section: `{}`", std::string(raw));
    TREX_CHECK(starts_with(raw, "\t"),
               "expected leading `\\t` for an ExternalVariable line: `{}`",
               std::string(raw));

    std::string_view external_var_str = trim_view(raw.substr(1));
    ExternalVariable external_var{std::string(external_var_str)};

    // "<name>@<func_name>@<func_addr>" - split on '@' twice: the variable name comes first, then
    // the function name, then the function's entry address (which is what upstream reads).
    auto p1 = split_once_or_panic(external_var_str, '@');
    auto p2 = split_once_or_panic(p1.second, '@');
    std::string_view func_name = p2.first;
    std::string_view func_addr_sv = trim_view(p2.second);
    uint64_t func_addr = parse_hex(func_addr_sv);

    // Locate the function in the program.
    std::optional<size_t> func_id;
    for ( size_t fn_idx = 0; fn_idx < p.functions.size(); ++fn_idx )
    {
      const FunctionInfo &fi = p.functions[fn_idx];
      bool name_match = fi.name == std::string(func_name);
      bool addr_match = fi.entry.first == func_addr;
      if ( name_match )
      {
        if ( fi.entry.first != func_addr )
        {
          log::debug("Differing addresses for same function name found",
                     { { "fn_name", fi.name },
                       { "entry_point", fi.entry.first },
                       { "func_address", func_addr } });
        }
        func_id = fn_idx;
        break;
      }
      else if ( addr_match )
      {
        log::debug("Different function name for same address found",
                   { { "external_var", external_var.name },
                     { "real_fn_name", fi.name },
                     { "variable_claimed_func_name", std::string(func_name) } });
        func_id = fn_idx;
        break;
      }
    }

    if ( !func_id.has_value() )
    {
      log::debug("Could not find function for variable",
                 { { "external_var", external_var.name },
                   { "func_name", std::string(func_name) } });
    }

    // Inner lines: `\t\t(space, 0xOFFSET, size)`.
    std::vector<Variable> internal_vars;
    ++k;
    while ( k < vars.size() && starts_with(vars[k], "\t\t") )
    {
      std::string_view il = vars[k];
      auto opt = parse_varnode(il, external_var, p);
      if ( opt.has_value() )
        internal_vars.push_back(*opt);
      ++k;
    }

    if ( func_id.has_value() )
    {
      auto prev = res.varmap.find(external_var);
      if ( prev != res.varmap.end() )
      {
        log::warn("Ghidra variable parser found repeating variable name. Using latest.",
                  { { "prev", "<redacted>" },
                    { "latest", "<redacted>" },
                    { "external_var", external_var.name } });
      }
      res.varmap[external_var] = { *func_id, std::move(internal_vars) };
    }
    else
    {
      // Upstream's `Option` collapses the assignment entirely when func_id
      // is None; we mirror that.
    }
  }

  if ( res.varmap.empty() )
  {
    log::debug("No variables were parsed. Weird.");
  }

  return res;
}

} // namespace trex