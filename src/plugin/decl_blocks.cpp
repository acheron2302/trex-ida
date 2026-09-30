// Implementation of trex::decl::parse_decl_blocks / compute_block_sizes / block_text.
//
// Split out of plugin.cpp's prepare_declarations so the types window can rebuild aggregate
// listings without dragging in the IDA / repair-emit code path.

#include "decl_blocks.hpp"

#include <cstddef>
#include <functional>
#include <map>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace trex::decl
{

namespace
{

// Scalar sizes for the C types the TRex printer emits. The same coverage as plugin.cpp's
// `printed_type_size` — anything else returns std::nullopt and the containing aggregate's size
// is treated as unknown.
const std::map<std::string, std::size_t> &scalar_sizes()
{
  static const std::map<std::string, std::size_t> scalars = {
    { "char", 1 },              { "signed char", 1 },         { "unsigned char", 1 },
    { "undefined", 1 },         { "undefined1", 1 },          { "padding", 1 },      { "int8_t", 1 },
    { "uint8_t", 1 },           { "short", 2 },               { "unsigned short", 2 },
    { "undefined2", 2 },        { "int16_t", 2 },             { "uint16_t", 2 },
    { "int", 4 },               { "unsigned int", 4 },        { "undefined4", 4 },
    { "int32_t", 4 },           { "uint32_t", 4 },            { "long", 4 },         { "unsigned long", 4 },
    { "long long", 8 },         { "unsigned long long", 8 },  { "undefined8", 8 },
    { "int64_t", 8 },           { "uint64_t", 8 },            { "__int64", 8 },
    { "int128_t", 16 },         { "uint128_t", 16 },          { "__int128", 16 },
  };
  return scalars;
}

std::optional<std::size_t> printed_type_size(const std::string &type,
                                             const std::map<std::string, std::size_t> &aggregate_sizes)
{
  if ( type.find('*') != std::string::npos )
    return 8; // 64-bit database
  auto it = scalar_sizes().find(type);
  if ( it != scalar_sizes().end() )
    return it->second;
  auto ag = aggregate_sizes.find(type);
  if ( ag != aggregate_sizes.end() )
    return ag->second;
  return std::nullopt;
}

} // namespace

std::vector<Block> parse_decl_blocks(const std::string &decls)
{
  const std::regex block_open("^(struct|union)[ \t]+(t[0-9]+)[ \t]*\\{[ \t]*\\r?$");
  const std::regex member_line("^([ \t]+)(.*?)[ \t]+(field|alt)_([0-9A-Fa-f]+)[ \t]*;[ \t]*\\r?$");

  std::vector<std::string> lines;
  {
    std::string line;
    std::istringstream in(decls);
    while ( std::getline(in, line) )
      lines.push_back(line);
  }

  std::vector<Block> blocks;
  for ( std::size_t i = 0; i < lines.size(); )
  {
    std::smatch m;
    if ( !std::regex_match(lines[i], m, block_open) )
    {
      ++i;
      continue;
    }

    Block b;
    b.kind = m[1].str();
    b.name = m[2].str();
    b.head.push_back(lines[i]);
    for ( ++i; i < lines.size(); ++i )
    {
      if ( lines[i].find("};") != std::string::npos )
      {
        b.tail.push_back(lines[i]);
        ++i;
        break;
      }
      std::smatch mm;
      if ( std::regex_match(lines[i], mm, member_line) )
      {
        Member dm;
        dm.indent = mm[1].str();
        dm.type = mm[2].str();
        while ( !dm.type.empty() && dm.type.back() == ' ' )
          dm.type.pop_back();
        dm.name = mm[3].str() + "_" + mm[4].str();
        dm.offset = (mm[3].str() == "field")
                      ? (std::size_t)strtoull(mm[4].str().c_str(), nullptr, 16)
                      : 0;
        b.members.push_back(dm);
      }
    }
    blocks.push_back(std::move(b));
  }
  return blocks;
}

std::map<std::string, std::size_t> compute_block_sizes(const std::vector<Block> &blocks)
{
  std::map<std::string, const Block *> block_of;
  for ( const Block &b : blocks )
    block_of.emplace(b.name, &b);

  std::map<std::string, std::size_t> sizes;
  std::set<std::string> in_progress;

  std::function<std::optional<std::size_t>(const std::string &)> size_of_block =
    [&](const std::string &name) -> std::optional<std::size_t>
  {
    auto done = sizes.find(name);
    if ( done != sizes.end() )
      return done->second;
    auto it = block_of.find(name);
    if ( it == block_of.end() || !in_progress.insert(name).second )
      return std::nullopt; // undefined, or a cycle: unknown size

    const Block &b = *it->second;
    std::optional<std::size_t> result;
    if ( b.kind == "union" )
    {
      std::size_t best = 0;
      bool known = true;
      for ( const Member &dm : b.members )
      {
        std::optional<std::size_t> sz = printed_type_size(dm.type, sizes);
        if ( !sz.has_value() )
          sz = size_of_block(dm.type);
        if ( !sz.has_value() )
          known = false;
        else
          best = std::max(best, *sz);
      }
      result = known ? std::optional<std::size_t>(best) : std::nullopt;
    }
    else
    {
      std::size_t end = 0;
      bool known = true;
      for ( const Member &dm : b.members )
      {
        std::optional<std::size_t> sz = printed_type_size(dm.type, sizes);
        if ( !sz.has_value() )
          sz = size_of_block(dm.type);
        if ( !sz.has_value() )
          known = false;
        else
          end = std::max(end, dm.offset + *sz);
      }
      result = known ? std::optional<std::size_t>(end) : std::nullopt;
    }

    in_progress.erase(name);
    if ( result.has_value() )
      sizes[name] = *result;
    return result;
  };

  for ( const Block &b : blocks )
    size_of_block(b.name);
  return sizes;
}

std::string block_text(const Block &b)
{
  std::string out;
  for ( const std::string &l : b.head )
    out += l + "\n";
  for ( const Member &dm : b.members )
  {
    const std::string indent = dm.indent.empty() ? "  " : dm.indent;
    out += indent + dm.type + " " + dm.name + ";\n";
  }
  for ( const std::string &l : b.tail )
    out += l + "\n";
  return out;
}

} // namespace trex::decl