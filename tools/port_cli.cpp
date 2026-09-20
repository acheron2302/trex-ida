// Test CLI for TRex - port of upstream `trex/src/main.rs`.
//
// Usage:
//   trex_port_cli from-ghidra <exported_pcode> [exported_vars]
//                             [--output-structural P]
//                             [--output-c-like P]
//                             [--debug-output-graphviz P]
//                             [--dump-ssa-lifted P]
//                             [--log P]
//                             [-d]...
//                             [-Z <flag>]...
//
// Mirrors upstream `main.rs::Args::FromGhidra` and the body of `main`. At
// this step the inference core (structural / aggregate / round-up /
// serialization / C-printer) does not exist yet, so the calls to
// `run_trex_pipeline` are gated behind `TREX_HAVE_INFERENCE`
// (defaulting to 0). The CLI compiles and runs today with the frontends
// working; later the inference core flips the macro on and the same CLI
// gains the full pipeline.
//
// Output order (matches upstream):
//   1. If `--output-structural P` is given, write the structural text to P.
//      Otherwise print it to stdout.
//   2. If `--output-c-like P` is given, write the C-like text to P.
//      Otherwise print it to stdout (after the structural block).
//
// `--debug-output-graphviz` and `--dump-ssa-lifted` are honoured inside
// the macro=1 branch; under macro=0 they print a clear "not built yet"
// message and exit non-zero.

// Define the inference gate before any pipeline include so the compiler
// never tries to parse the inference header tree until the core lands.
#ifndef TREX_HAVE_INFERENCE
#define TREX_HAVE_INFERENCE 1
#endif

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <trex/error.hpp>
#include <trex/il.hpp>
#include <trex/inference_config.hpp>
#include <trex/lifted_frontend.hpp>
#include <trex/log.hpp>

#if TREX_HAVE_INFERENCE
#include <trex/pipeline.hpp>
#include <trex/ssa.hpp>
#endif

namespace {

// ---------------------------------------------------------------------------
// Manual arg parser (no clap).
// ---------------------------------------------------------------------------
struct CliArgs
{
  std::string exported_pcode;
  std::optional<std::string> exported_vars;
  std::optional<std::string> output_structural;
  std::optional<std::string> output_c_like;
  std::optional<std::string> debug_output_graphviz;
  std::optional<std::string> dump_ssa_lifted;
  std::optional<std::string> log_file;
  std::optional<std::string> debug_types_path;
  bool debug_disable_terminal_logging = false;
  bool debug_forced_blocking_terminal_logging = false;
  int debug_level_count = 0; // upstream uses `from_occurrences` on `-d`
  std::vector<trex::ConfigFlag> advanced_config;
};

bool starts_with(std::string_view s, std::string_view p)
{
  return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}

std::string read_file(const std::string &path)
{
  std::ifstream f(path, std::ios::binary);
  if ( !f )
  {
    throw trex::InvariantError("trex_port_cli: could not open `" + path + "`");
  }
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}
#if TREX_HAVE_INFERENCE
 void write_file(const std::string &path, const std::string &content)
 {
   std::ofstream f(path, std::ios::binary | std::ios::trunc);
   if ( !f )
   {
     throw trex::InvariantError("trex_port_cli: could not open for write `" + path + "`");
   }
   f.write(content.data(), static_cast<std::streamsize>(content.size()));
 }
#endif

int parse_cli(int argc, char **argv, CliArgs &out)
{
  if ( argc < 2 )
    return 2;
  std::string subcommand = argv[1];
  if ( subcommand != "from-ghidra" )
  {
    std::cerr << "trex_port_cli: unknown subcommand `" << subcommand << "` (expected `from-ghidra`)\n";
    return 2;
  }

  int i = 2;
  auto need_value = [&](const std::string &flag, std::optional<std::string> &slot) -> bool {
    if ( i >= argc )
    {
      std::cerr << "trex_port_cli: missing value for `" << flag << "`\n";
      return false;
    }
    slot = std::string(argv[i++]);
    return true;
  };

  while ( i < argc )
  {
    std::string a = argv[i];
    if ( a == "--output-structural" )
    {
      ++i; // step past the flag; need_value() consumes the value
      if ( !need_value(a, out.output_structural) )
        return 2;
    }
    else if ( a == "--output-c-like" )
    {
      ++i;
      if ( !need_value(a, out.output_c_like) )
        return 2;
    }
    else if ( a == "--debug-output-graphviz" )
    {
      ++i;
      if ( !need_value(a, out.debug_output_graphviz) )
        return 2;
    }
    else if ( a == "--dump-ssa-lifted" )
    {
      ++i;
      if ( !need_value(a, out.dump_ssa_lifted) )
        return 2;
    }
    else if ( a == "--debug-types" )
    {
      ++i;
      if ( !need_value(a, out.debug_types_path) )
        return 2;
    }
    else if ( a == "--log" )
    {
      ++i;
      if ( !need_value(a, out.log_file) )
        return 2;
    }
    else if ( a == "--debug-disable-terminal-logging" )
    {
      out.debug_disable_terminal_logging = true;
      ++i;
    }
    else if ( a == "--debug-forced-blocking-terminal-logging" )
    {
      out.debug_forced_blocking_terminal_logging = true;
      ++i;
    }
    else if ( a == "-d" )
    {
      ++out.debug_level_count;
      ++i;
    }
    else if ( a == "-Z" )
    {
      if ( i + 1 >= argc )
      {
        std::cerr << "trex_port_cli: missing value for `-Z`\n";
        return 2;
      }
      trex::ConfigFlag flag;
      std::string name = argv[++i];
      if ( !trex::config_flag_from_cli_name(name, flag) )
      {
        std::cerr << "trex_port_cli: unknown -Z flag `" << name << "`\n";
        return 2;
      }
      out.advanced_config.push_back(flag);
      ++i;
    }
    else if ( starts_with(a, "--") )
    {
      std::cerr << "trex_port_cli: unknown option `" << a << "`\n";
      return 2;
    }
    else
    {
      if ( out.exported_pcode.empty() )
        out.exported_pcode = a;
      else if ( !out.exported_vars.has_value() )
        out.exported_vars = a;
      else
      {
        std::cerr << "trex_port_cli: unexpected positional `" << a << "`\n";
        return 2;
      }
      ++i;
    }
  }

  if ( out.exported_pcode.empty() )
  {
    std::cerr << "trex_port_cli: missing `<exported_pcode>` path\n";
    return 2;
  }
  return 0;
}
// Print (or write) one output, mirroring upstream's `if let Some(path)
// { write } else { println }` pattern.
#if TREX_HAVE_INFERENCE
 void emit_text(const std::optional<std::string> &path, const std::string &text)
 {
   if ( path.has_value() )
     write_file(*path, text);
   else
     std::cout << text << "\n";
 }
#endif

} // namespace

int main(int argc, char **argv)
try
{
  CliArgs args;
  int rc = parse_cli(argc, argv, args);
  if ( rc != 0 )
    return rc;

  // ---- logging ----
  switch ( args.debug_level_count )
  {
    case 0:
      trex::log::set_level(trex::log::Level::Warn);
      break;
    case 1:
      trex::log::set_level(trex::log::Level::Info);
      break;
    case 2:
      trex::log::set_level(trex::log::Level::Debug);
      break;
    default:
      trex::log::set_level(trex::log::Level::Trace);
      break;
  }
  trex::log::set_terminal_enabled(!args.debug_disable_terminal_logging);
  if ( args.log_file.has_value() )
    trex::log::set_log_file(*args.log_file);
  // `debug_forced_blocking_terminal_logging` is accepted but inert here -
  // upstream honors it through the drain, which is built around the
  // `slog` async machinery. The CLI builds its own sink chain; this option
  // is a no-op until we wire in a back-pressure-aware sink.

  // ---- initialize inference config from -Z flags ----
  trex::initialize_config(args.advanced_config);

  // ---- lift the pcode + (optional) vars ----
  std::string pcode_text = read_file(args.exported_pcode);
  std::shared_ptr<const trex::Program> prog =
      trex::lift_program_from_lifted_text(pcode_text);

  std::optional<trex::ILVariableMap> vars;
  if ( args.exported_vars.has_value() )
  {
    std::string vars_text = read_file(*args.exported_vars);
    vars = trex::lift_variable_map_from_vars_text(vars_text, prog);
  }

#if TREX_HAVE_INFERENCE
  // Full pipeline. When the inference core lands (S4/S6), this branch is
  // taken; today it is gated behind a macro defaulting to 0.
  trex::TrexPipelineResult result = trex::run_trex_pipeline(prog, vars);

  if ( args.dump_ssa_lifted.has_value() )
  {
    // Upstream: `write!(File::create(path), "{:?}", types.ssa.debug_program(true, None))`.
    trex::ssa::DebugProgram dbg{ *result.structured_types->ssa, /*show_machine_addr=*/ true,
                                 std::nullopt };
    write_file(*args.dump_ssa_lifted, trex::format_debug_program(dbg));
  }

  if ( args.debug_output_graphviz.has_value() )
  {
    // Upstream: `write!(File::create(path), "{}", structuredtypes.generate_dot(None))`.
    write_file(*args.debug_output_graphviz,
               trex::generate_dot(*result.structured_types, std::nullopt));
  }

  if ( args.debug_types_path.has_value() )
  {
    auto &st = *result.structured_types;
    std::ostringstream os;
    os << "=== FINAL type_map (size=" << st.type_map.size() << ") ===\n";
    for ( auto &kv : st.type_map )
    {
      auto canon = st.types_ref().get_canonical_index(kv.second);
      os << "  " << kv.first.debug_string() << " -> " << kv.second.to_string()
         << " (canon " << canon.to_string() << ")\n";
    }
    os << "\n=== alive types ===\n";
    for ( auto &t : st.types_ref().currently_alive_objects_iter() )
      os << t.get().debug_string() << "\n";
    write_file(*args.debug_types_path, os.str());
  }

  // Output order matches upstream: structural text first, then C-like.
  emit_text(args.output_structural, result.structural_text);
  emit_text(args.output_c_like, result.c_like_text);

  trex::log::trace("Done");
  return 0;
#else
  // Inference core not built yet: the CLI compiles and runs (so the
  // Ghidra-text frontend can be smoke-tested in isolation), but the
  // inference entry points print a clear "not built yet" message instead
  // of pretending to produce output.
  if ( args.dump_ssa_lifted.has_value() )
  {
    std::cerr << "trex_port_cli: --dump-ssa-lifted requested but inference "
                 "core is not built yet (TREX_HAVE_INFERENCE=0).\n";
    return 3;
  }
  if ( args.debug_output_graphviz.has_value() )
  {
    std::cerr << "trex_port_cli: --debug-output-graphviz requested but "
                 "inference core is not built yet (TREX_HAVE_INFERENCE=0).\n";
    return 3;
  }
  if ( args.output_structural.has_value() || args.output_c_like.has_value() )
  {
    std::cerr << "trex_port_cli: inference core is not built yet "
                 "(TREX_HAVE_INFERENCE=0); only the frontends ran. "
                 "No structural / C-like output was produced.\n";
    return 3;
  }
  std::cerr << "trex_port_cli: lifted " << prog->instructions.size()
            << " IL instructions across " << prog->functions.size()
            << " function(s) from `" << args.exported_pcode << "`."
            << " Inference core is not built yet (TREX_HAVE_INFERENCE=0);"
            << " no output produced.\n";
  return 3;
#endif
}
catch ( const trex::InvariantError &e )
{
  std::cerr << "trex_port_cli: " << e.what() << "\n";
  return 1;
}