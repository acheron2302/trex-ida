#pragma once

// Trace/debug logging for the TRex core.
//
// Rust uses slog with structured key=value arguments; the port keeps a very small sink
// (stderr + optional JSON-lines file, plus a hook the plugin uses to forward to IDA's
// Output window). Log text is never part of any compared output.

#include <cstdint>
#include <initializer_list>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace trex::log {

enum class Level : int
{
  Trace = 0,
  Debug = 1,
  Info = 2,
  Warn = 3,
  Error = 4,
};

/// One structured key=value pair.
struct KV
{
  std::string key;
  std::string value;

  KV(std::string_view k, std::string_view v) : key(k), value(v) {}
  KV(std::string_view k, const char *v) : key(k), value(v == nullptr ? "<null>" : v) {}
  KV(std::string_view k, const std::string &v) : key(k), value(v) {}

  template <typename T, std::enable_if_t<std::is_arithmetic_v<T>, int> = 0>
  KV(std::string_view k, T v) : key(k), value(std::to_string(v))
  {
  }
};

using KVList = std::initializer_list<KV>;

/// Sink function type. The default sink writes to stderr and to the JSON file (if any);
/// the plugin installs one that forwards to IDA's message window.
using SinkFn = void (*)(Level, const std::string &, const std::vector<KV> &);

void set_level(Level level);
Level level();

/// Path of the JSON-lines log file; empty string disables it.
void set_log_file(const std::string &path);
void set_terminal_enabled(bool enabled);

void set_sink(SinkFn sink);
void reset_sink();

bool enabled(Level level);

void write(Level level, const std::string &message, const std::vector<KV> &kv);

inline void trace(const std::string &message, const std::vector<KV> &kv = {}) { write(Level::Trace, message, kv); }
inline void debug(const std::string &message, const std::vector<KV> &kv = {}) { write(Level::Debug, message, kv); }
inline void info(const std::string &message, const std::vector<KV> &kv = {}) { write(Level::Info, message, kv); }
inline void warn(const std::string &message, const std::vector<KV> &kv = {}) { write(Level::Warn, message, kv); }
inline void error(const std::string &message, const std::vector<KV> &kv = {}) { write(Level::Error, message, kv); }

} // namespace trex::log
