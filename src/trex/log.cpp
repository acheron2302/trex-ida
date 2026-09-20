#include <trex/log.hpp>

#include <cstdio>
#include <mutex>

namespace trex::log {
namespace {

Level g_level = Level::Warn;
bool g_terminal_enabled = true;
std::string g_log_file;
SinkFn g_sink = nullptr;
std::mutex g_mutex;

void json_escape(const std::string &in, std::string &out)
{
  for ( char c : in )
  {
    switch ( c )
    {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if ( (unsigned char)c < 0x20 )
        {
          char buf[8];
          snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
          out += buf;
        }
        else
        {
          out += c;
        }
        break;
    }
  }
}

void default_sink(Level lvl, const std::string &message, const std::vector<KV> &kv)
{
  static const char *names[] = { "TRACE", "DEBUG", "INFO", "WARN", "ERROR" };
  int idx = (int)lvl;
  if ( idx < 0 || idx > 4 )
    idx = 4;

  std::string line;
  line += names[idx];
  line += ": ";
  line += message;
  for ( const KV &one : kv )
  {
    line += " ";
    line += one.key;
    line += "=";
    line += one.value;
  }

  if ( g_terminal_enabled )
    fprintf(stderr, "%s\n", line.c_str());

  if ( !g_log_file.empty() )
  {
    FILE *f = fopen(g_log_file.c_str(), "a");
    if ( f != nullptr )
    {
      std::string json = "{\"level\":\"";
      json += names[idx];
      json += "\",\"msg\":\"";
      json_escape(message, json);
      json += "\"";
      for ( const KV &one : kv )
      {
        json += ",\"";
        json_escape(one.key, json);
        json += "\":\"";
        json_escape(one.value, json);
        json += "\"";
      }
      json += "}\n";
      fputs(json.c_str(), f);
      fclose(f);
    }
  }
}

} // namespace

void set_level(Level lvl)
{
  std::lock_guard<std::mutex> lock(g_mutex);
  g_level = lvl;
}

Level level()
{
  std::lock_guard<std::mutex> lock(g_mutex);
  return g_level;
}

void set_log_file(const std::string &path)
{
  std::lock_guard<std::mutex> lock(g_mutex);
  g_log_file = path;
}

void set_terminal_enabled(bool enabled)
{
  std::lock_guard<std::mutex> lock(g_mutex);
  g_terminal_enabled = enabled;
}

void set_sink(SinkFn sink)
{
  std::lock_guard<std::mutex> lock(g_mutex);
  g_sink = sink;
}

void reset_sink()
{
  std::lock_guard<std::mutex> lock(g_mutex);
  g_sink = nullptr;
}

bool enabled(Level lvl)
{
  std::lock_guard<std::mutex> lock(g_mutex);
  return (int)lvl >= (int)g_level;
}

void write(Level lvl, const std::string &message, const std::vector<KV> &kv)
{
  SinkFn sink = nullptr;
  {
    std::lock_guard<std::mutex> lock(g_mutex);
    if ( (int)lvl < (int)g_level )
      return;
    sink = g_sink;
  }
  if ( sink != nullptr )
    sink(lvl, message, kv);
  else
    default_sink(lvl, message, kv);
}

} // namespace trex::log
