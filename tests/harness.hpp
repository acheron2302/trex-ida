// Minimal unit-test harness for the TRex core.
//
//   TEST(name) { ... }   registers a test by name
//   CHECK(cond)          asserts a boolean
//   CHECK_EQ(a, b)       asserts two printable values are equal
//
// The harness is header-only (no third-party deps). `tests/test_main.cpp`
// defines `main`; auto-registration pushes each test into a global vector
// and `main` runs them in registration order, returning non-zero if any
// test fails.

#pragma once
#include <cstdlib>
#include <functional>
#include <exception>
#include <optional>
#include <sstream>
#include <vector>

namespace trex_test {

struct TestCase
{
  std::string name;
  std::function<void()> body;
};

inline std::vector<TestCase> &registry()
{
  static std::vector<TestCase> r;
  return r;
}

struct TestRegistrar
{
  TestRegistrar(std::string n, std::function<void()> body)
  {
    registry().push_back(TestCase{ std::move(n), std::move(body) });
  }
};

inline int run_all()
{
  // Unbuffered: a crash in a test must not swallow the output that says which test it was.
  std::setvbuf(stdout, nullptr, _IONBF, 0);

  int failed = 0;
  int passed = 0;
  for ( auto &tc : registry() )
  {
    std::printf("[ RUN      ] %s\n", tc.name.c_str());
    try
    {
      tc.body();
      std::printf("[       OK ] %s\n", tc.name.c_str());
      ++passed;
    }
    catch ( const std::exception &e )
    {
      std::printf("[  FAILED  ] %s: %s\n", tc.name.c_str(), e.what());
      ++failed;
    }
    catch ( ... )
    {
      std::printf("[  FAILED  ] %s: unknown exception\n", tc.name.c_str());
      ++failed;
    }
  }
  std::printf("\n[==========] %d passed, %d failed\n", passed, failed);
  return failed == 0 ? 0 : 1;
}

} // namespace trex_test

#define TEST(name)                                                            \
  static void test_##name();                                                  \
  static ::trex_test::TestRegistrar registrar_##name(                         \
      #name, test_##name);                                                    \
  static void test_##name()

#define CHECK(cond)                                                            \
  do                                                                           \
  {                                                                            \
    if ( !(cond) )                                                             \
    {                                                                          \
      throw std::runtime_error(std::string("CHECK failed: ") + #cond           \
                               + " at " __FILE__ ":" + std::to_string(__LINE__)); \
    }                                                                          \
  } while ( false )

namespace trex_test {

inline std::string to_test_string(bool v)
{
  return v ? "true" : "false";
}
inline std::string to_test_string(int v)             { return std::to_string(v); }
inline std::string to_test_string(unsigned v)        { return std::to_string(v); }
inline std::string to_test_string(long v)            { return std::to_string(v); }
inline std::string to_test_string(unsigned long v)   { return std::to_string(v); }
inline std::string to_test_string(long long v)       { return std::to_string(v); }
inline std::string to_test_string(unsigned long long v){ return std::to_string(v); }
inline std::string to_test_string(double v)
{
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%g", v);
  return buf;
}
inline std::string to_test_string(const char *v)     { return v ? v : "<null>"; }
inline std::string to_test_string(const std::string &v) { return v; }
inline std::string to_test_string(std::string_view v)
{
  return std::string(v);
}

template <typename T>
inline std::string to_test_string(const T *v)
{
  if ( v == nullptr ) return "<null>";
  std::ostringstream os;
  os << *v;
  return os.str();
}

template <typename T>
inline std::string to_test_string(const std::optional<T> &v)
{
  if ( !v.has_value() ) return "<none>";
  return to_test_string(*v);
}

} // namespace trex_test

#define CHECK_EQ(a, b)                                                          \
  do                                                                            \
  {                                                                             \
    auto va = (a);                                                              \
    auto vb = (b);                                                              \
    auto sa = ::trex_test::to_test_string(va);                                  \
    auto sb = ::trex_test::to_test_string(vb);                                  \
    if ( !(va == vb) )                                                          \
    {                                                                           \
      throw std::runtime_error(std::string("CHECK_EQ failed: ")                 \
                               + #a + " == " + #b                                \
                               + " (got '" + sa + "' vs '" + sb + "')"           \
                               + " at " __FILE__ ":"                            \
                               + std::to_string(__LINE__));                      \
    }                                                                           \
  } while ( false )
