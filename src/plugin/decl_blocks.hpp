#pragma once

// Split the TRex printer's C-like declarations into aggregate blocks, compute their sizes, and
// reconstruct printable C for one block. Pure std C++, no IDA / Qt dependencies, so this header
// is included in both build flavours (Qt-less and Qt-enabled).
//
// Used by:
//   - plugin.cpp: prepare_declarations() (write-back; repair-emit stays here).
//   - trex_window.cpp: populating the types-window tree from the last reconstruction.

#include <cstddef>
#include <map>
#include <string>
#include <vector>


namespace trex::decl
{

struct Member
{
  std::string indent;
  std::string type;     ///< as printed by the TRex C printer
  std::string name;     ///< `field_12` / `alt_2`
  std::size_t offset = 0; ///< from the `field_<hex>` suffix; 0 for union alternatives
};

struct Block
{
  std::string kind;                  ///< "struct" or "union"
  std::string name;                  ///< `tN`
  std::vector<std::string> head;     ///< the `struct tN {` line(s), verbatim
  std::vector<std::string> tail;     ///< the `};` line(s), verbatim
  std::vector<Member> members;
};

/// Split declarations-only text into aggregate blocks; non-block lines are dropped. The regexes
/// (`block_open`, `member_line`) move as-is from the original `prepare_declarations`.
std::vector<Block> parse_decl_blocks(const std::string &decls);

/// Aggregate name -> size, in dependency order. Cycles and unknown members leave the block absent
/// from the map. Pure memoized recursion over the parsed blocks.
std::map<std::string, std::size_t> compute_block_sizes(const std::vector<Block> &blocks);

/// Reconstruct printable C for one block: head lines, `  <type> <name>;` per member, tail lines.
/// Intended for the types window (one entry per reconstructed struct).
std::string block_text(const Block &b);

} // namespace trex::decl