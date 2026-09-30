#pragma once

// Pure data + std::function callbacks shared between the Qt-enabled trex_window.cpp and the
// Qt-less plugin.cpp stubs. No IDA / Qt includes here so this translation unit builds in both
// flavours and stays testable from plain C++.

#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace trex::ui
{

struct StructInfo
{
  std::string kind;          ///< "struct" or "union"
  std::string name;          ///< `tN`
  std::string declaration;   ///< the full C-like declaration, ready to paste
  std::optional<std::size_t> size; ///< byte size from the structural pass; absent if unknown
  std::size_t member_count = 0;
};

struct VarUse
{
  std::string type_name;     ///< matches `StructInfo::name`
  std::string func;          ///< function name
  std::string lvar;          ///< local-variable name
  std::string ea_hex;        ///< function entry EA, hex, no `0x`
};

struct WindowModel
{
  std::vector<StructInfo> structs;
  std::vector<VarUse> uses;
};

struct WindowCallbacks
{
  std::function<void()> rescan_current_deep; ///< ARG_INFER_CURRENT_DEEP
  std::function<void()> rescan_all;          ///< ARG_INFER_ALL
  std::function<void()> apply;               ///< ARG_APPLY
  std::function<void()> export_files;        ///< ARG_EXPORT
};

/// True iff the plugin was built against the matching Qt (TREX_HAVE_QT=1).
bool qt_available();

/// Open (or focus + refresh) the dockable types window. When the model is empty the window still
/// opens so the user can hit a Rescan button.
void show_types_window(const WindowModel &model, const WindowCallbacks &cbs);

/// Update the window's tree + detail from a fresh model. No-op when the window is closed.
void update_types_window(const WindowModel &model);

} // namespace trex::ui