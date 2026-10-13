// The types window's aggregate renderer.
//
// Its own translation unit so that it is compiled (and unit-tested) in both build flavours: the
// Qt-enabled trex_window.cpp that displays it is only built when a matching Qt was found, while
// this file is always built and never touches Qt or IDA.

#include "trex_window.hpp"

#include <cstddef>
#include <string>

namespace trex::ui
{

std::string render_declaration(const StructInfo &s)
{
  std::string out;
  out += s.kind;
  out += " ";
  out += s.name;
  out += " {\n";
  for ( const MemberRow &m : s.members )
  {
    out += "  ";
    if ( m.is_gap )
    {
      // The type is unknown, the width is not: a gap member always knows exactly how wide it is,
      // so it renders as the byte blob of that width the clipboard output needs to stay valid C.
      out += "unsigned char ";
      out += m.name;
      out += "[";
      out += std::to_string(m.extent != 0 ? m.extent : 1);
      out += "];\n";
    }
    else
    {
      out += m.type;
      out += " ";
      out += m.name;
      out += ";\n";
    }
  }
  out += "};\n";
  return out;
}

} // namespace trex::ui