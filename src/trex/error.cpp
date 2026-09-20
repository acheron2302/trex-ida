#include <trex/error.hpp>

// The message formatter lives entirely in the header (it is a template); this TU exists so the
// library has a stable object and to keep <cstdio> out of the error-path headers.
namespace trex::detail {
void trex_error_link_anchor() {}
} // namespace trex::detail
