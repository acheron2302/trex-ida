#pragma once

// Error handling for the TRex core.
//
// Rust uses panic!/assert!/unwrap(); the C++ port funnels all of those through a single
// exception type so that the plugin entry points can catch a failed inference run and leave
// the database untouched.
//
// The message formatter is deliberately *not* a C variadic function: passing a std::string
// through `...` is ill-formed on clang-based compilers (icx-cl) and aborts at runtime under
// MSVC. Instead each argument is rendered individually against its own conversion specifier,
// which keeps argv values out of `...` entirely.

#include <cstdio>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>

// The IDA SDK deliberately shadows the C library's formatters (`#define snprintf
// dont_use_snprintf`) to push plugins towards qsnprintf(). The core must stay IDA-free, so undo the
// shadowing here; this header only ever uses snprintf internally.
#if defined(snprintf)
#  undef snprintf
#endif
#if defined(vsnprintf)
#  undef vsnprintf
#endif

namespace trex {

class InvariantError : public std::runtime_error
{
public:
  explicit InvariantError(const std::string &what) : std::runtime_error(what) {}
};

namespace detail {

/// One past the conversion character of the specifier starting at `p`.
inline const char *spec_end(const char *p)
{
  const char *q = p + 1;
  while ( *q != '\0' && strchr("-+ #0123456789.*hlLjzt", *q) != nullptr )
    ++q;
  if ( *q != '\0' )
    ++q;
  return q;
}

/// Render an argument for a Rust-style `{}`/`{:?}` placeholder.
inline std::string display_of(const std::string &v) { return v; }
inline std::string display_of(const char *v) { return v == nullptr ? "<null>" : std::string(v); }
inline std::string display_of(std::string_view v) { return std::string(v); }
inline std::string display_of(bool v) { return v ? "true" : "false"; }
template <class T, std::enable_if_t<std::is_arithmetic_v<T>, int> = 0>
inline std::string display_of(T v)
{
  return std::to_string(v);
}
template <class T, std::enable_if_t<!std::is_arithmetic_v<T>, int> = 0>
inline std::string display_of(const T &v)
{
  std::ostringstream os;
  os << v;
  return os.str();
}

/// The next conversion specifier that needs an argument: either a printf `%...` spec or a
/// Rust-style `{...}` placeholder (the ported messages use both).
/// Returns nullptr if there is none; `len` receives the placeholder's length.
inline const char *find_placeholder(const char *fmt, size_t &len, bool &braces)
{
  for ( const char *p = fmt; *p != '\0'; ++p )
  {
    if ( *p == '%' )
    {
      if ( p[1] == '%' )
      {
        ++p;
        continue;
      }
      len = (size_t)(spec_end(p) - p);
      braces = false;
      return p;
    }
    if ( *p == '{' )
    {
      const char *q = strchr(p, '}');
      if ( q != nullptr )
      {
        len = (size_t)(q - p + 1);
        braces = true;
        return p;
      }
      continue;
    }
  }
  return nullptr;
}

/// The next conversion specifier that needs an argument (skips `%%`); nullptr if none.
inline const char *next_spec(const char *fmt)
{
  for ( const char *p = fmt; *p != '\0'; ++p )
  {
    if ( *p != '%' )
      continue;
    if ( p[1] == '%' )
    {
      ++p;
      continue;
    }
    return p;
  }
  return nullptr;
}


template <class T, std::enable_if_t<std::is_arithmetic_v<T>, int> = 0>
inline void render_spec(std::string &out, const std::string &spec, T value)
{
  char buf[512];
  snprintf(buf, sizeof(buf), spec.c_str(), value);
  out += buf;
}

inline void render_spec(std::string &out, const std::string &spec, const char *value)
{
  char buf[1024];
  snprintf(buf, sizeof(buf), spec.c_str(), value == nullptr ? "<null>" : value);
  out += buf;
}

inline void render_spec(std::string &out, const std::string &spec, const std::string &value)
{
  render_spec(out, spec, value.c_str());
}

inline void render_spec(std::string &out, const std::string &spec, std::string_view value)
{
  const std::string owned(value);
  render_spec(out, spec, owned);
}

inline void render_spec(std::string &out, const std::string &spec, bool value)
{
  render_spec(out, spec, value ? "true" : "false");
}

inline void format_into(std::string &out, const char *fmt)
{
  out += fmt;
}

template <class A, class... Rest>
inline void format_into(std::string &out, const char *fmt, const A &arg, const Rest &...rest)
{
  size_t len = 0;
  bool braces = false;
  const char *p = find_placeholder(fmt, len, braces);
  if ( p == nullptr )
  {
    // More arguments than placeholders: the remainder cannot be rendered.
    out += fmt;
    return;
  }

  out.append(fmt, (size_t)(p - fmt));
  if ( braces )
  {
    out += display_of(arg);
  }
  else
  {
    const std::string spec(p, len);
    render_spec(out, spec, arg);
  }
  format_into(out, p + len, rest...);
}

inline std::string format_args()
{
  return "<no message>";
}

inline std::string format_args(const std::string &s)
{
  return s;
}

inline std::string format_args(const char *fmt)
{
  return fmt == nullptr ? std::string("<null>") : std::string(fmt);
}

template <class... Args>
inline std::string format_args(const char *fmt, const Args &...args)
{
  std::string out;
  format_into(out, fmt == nullptr ? "<null>" : fmt, args...);
  return out;
}

} // namespace detail
} // namespace trex

/// TRex's panic!()/assert!(): printf-style formatting, with std::string arguments supported.
#define TREX_CHECK(cond, ...)                                                 \
  do                                                                          \
  {                                                                           \
    if ( !(cond) )                                                            \
      throw ::trex::InvariantError(std::string("TRex invariant failed: ")     \
                                   + ::trex::detail::format_args(__VA_ARGS__) \
                                   + " [" #cond "]");                         \
  } while ( false )

#define TREX_UNREACHABLE(...)                                                 \
  do                                                                          \
  {                                                                           \
    throw ::trex::InvariantError(std::string("TRex unreachable: ")            \
                                 + ::trex::detail::format_args(__VA_ARGS__)); \
  } while ( false )
