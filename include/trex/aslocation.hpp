#pragma once

// A location in an address space (port of dataflow.rs's ASLocation).
//
// Lives in its own header because il.rs and dataflow.rs both need it.

#include <cstddef>
#include <cstdint>
#include <string>

namespace trex {

struct ASLocation
{
  size_t address_space_idx = 0;
  uint64_t offset = 0;

  ASLocation() = default;
  ASLocation(size_t as, uint64_t off) : address_space_idx(as), offset(off) {}

  friend bool operator==(const ASLocation &a, const ASLocation &b)
  {
    return a.address_space_idx == b.address_space_idx && a.offset == b.offset;
  }
  friend bool operator!=(const ASLocation &a, const ASLocation &b) { return !(a == b); }
  friend bool operator<(const ASLocation &a, const ASLocation &b)
  {
    if ( a.address_space_idx != b.address_space_idx )
      return a.address_space_idx < b.address_space_idx;
    return a.offset < b.offset;
  }

  std::string debug_string() const;
};

} // namespace trex
