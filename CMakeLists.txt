cmake_minimum_required(VERSION 3.25)

# Must be set before the first project()/enable_language().
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

project(trexida CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Exceptions must be on for every target: the core reports invariant violations by throwing
# (see include/trex/error.hpp). Stated explicitly so a stray reconfigure cannot lose it.
add_compile_options(/EHsc)

# Convention from the upstream trexida README and from scripts/build-*.bat: callers set
# `%IDASDK%` (the SDK root, e.g. `E:\dev\ida-sdk-9.3`) and optionally `%IDADIR%`. Two
# canonical layouts exist:
#     <IDA_SDK_DIR>/             CMakeLists.txt  src/  ida-cmake/    <-- SDK + sibling checked out
#     <IDA_SDK_DIR>/src/         CMakeLists.txt                ida-cmake/    <-- SDK src layout
# Accept either: `IDA_SDK_DIR` is the SDK root; `IDA_SDK_SRC_DIR` defaults to `<root>/src`.
set(IDA_SDK_DIR "$ENV{IDASDK}" CACHE PATH "IDA SDK root (parent of src/ and lib/)")
if(NOT IDA_SDK_SRC_DIR)
  if(EXISTS "${IDA_SDK_DIR}/include/hexrays.hpp")
    set(IDA_SDK_SRC_DIR "${IDA_SDK_DIR}")
  else()
    set(IDA_SDK_SRC_DIR "${IDA_SDK_DIR}/src")
  endif()
endif()
set(IDA_SDK_SRC_DIR "${IDA_SDK_SRC_DIR}" CACHE PATH "IDA SDK src/ directory (contains include/, lib/)")
set(IDA_INSTALL_DIR "$ENV{IDADIR}" CACHE PATH "IDA installation directory (plugin DLL is deployed here)")
option(TREX_BUILD_TESTS "Build the test executables" ON)
if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
  set(TREX_COMPILER_NAME "MSVC")
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "IntelLLVM")
  if(NOT CMAKE_CXX_COMPILER MATCHES "icx-cl")
    message(FATAL_ERROR "IntelLLVM build requires the MSVC-compatible driver icx-cl, got: ${CMAKE_CXX_COMPILER}")
  endif()
  set(TREX_COMPILER_NAME "Intel oneAPI (icx-cl)")
else()
  message(FATAL_ERROR "Unsupported compiler id '${CMAKE_CXX_COMPILER_ID}': need MSVC or IntelLLVM (icx-cl)")
endif()
message(STATUS "trexida: compiler = ${TREX_COMPILER_NAME}")

if(NOT EXISTS "${IDA_SDK_SRC_DIR}/include/hexrays.hpp")
  message(FATAL_ERROR "IDA SDK headers not found at '${IDA_SDK_SRC_DIR}/include' (set -DIDA_SDK_DIR= or -DIDA_SDK_SRC_DIR=)")
endif()
# Older SDK tags (v9.2, v9.3.0-release, v9.3.0-sdk.1) put the Windows x64 import library in
# 'lib/x64_win_vc_64'; v9.3.0-sdk.2 and everything newer use 'lib/x64_win_64'. Same library, so
# accept either layout.
set(IDA_LIB "")
foreach(_ida_lib_dir "x64_win_64" "x64_win_vc_64")
  if(EXISTS "${IDA_SDK_SRC_DIR}/lib/${_ida_lib_dir}/ida.lib")
    set(IDA_LIB "${IDA_SDK_SRC_DIR}/lib/${_ida_lib_dir}/ida.lib")
  endif()
endforeach()
if(NOT IDA_LIB)
  message(FATAL_ERROR
    "IDA import library not found: no ida.lib in '${IDA_SDK_SRC_DIR}/lib/x64_win_64' or "
    "'${IDA_SDK_SRC_DIR}/lib/x64_win_vc_64' (set -DIDA_SDK_SRC_DIR=)")
endif()
message(STATUS "trexida: IDA import library = ${IDA_LIB}")

# ------------------------------------------------------------ ida settings ---
add_library(trex_ida_settings INTERFACE)
target_include_directories(trex_ida_settings INTERFACE "${IDA_SDK_SRC_DIR}/include")
target_compile_definitions(trex_ida_settings INTERFACE
  __NT__ __IDP__ __EA64__=1 _CRT_SECURE_NO_WARNINGS _CRT_NONSTDC_NO_DEPRECATE)
target_link_libraries(trex_ida_settings INTERFACE "${IDA_LIB}")
if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
  target_compile_options(trex_ida_settings INTERFACE /W3 /wd4996 /wd4267 /wd4244 /wd4100)
else()
  target_compile_options(trex_ida_settings INTERFACE /W3 /wd4996 /wd4267 /wd4244 /wd4100)
endif()

# ------------------------------------------------------------------ targets ---
# Core: IDA-free, so it builds and runs without the SDK.
file(GLOB TREX_CORE_SOURCES CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/trex/*.cpp")
add_library(trex_core STATIC ${TREX_CORE_SOURCES})
target_include_directories(trex_core PUBLIC "${CMAKE_SOURCE_DIR}/include")

# Inter-procedural type propagation: IDA-free, uses only the core's public headers. Deliberately not
# linked into trex_port_cli, so the differential gate keeps exercising the untouched upstream path.
file(GLOB TREX_INTERPROC_SOURCES CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/analysis/*.cpp")
if(TREX_INTERPROC_SOURCES)
  add_library(trex_interproc STATIC ${TREX_INTERPROC_SOURCES})
  target_include_directories(trex_interproc PUBLIC "${CMAKE_SOURCE_DIR}/src")
  target_link_libraries(trex_interproc PUBLIC trex_core)
endif()

# Reference Ghidra-text frontend: IDA-free, used by the differential tests.
file(GLOB TREX_REF_SOURCES CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/frontends/lifted/*.cpp")
if(TREX_REF_SOURCES)
  add_library(trex_ref_frontend STATIC ${TREX_REF_SOURCES})
  target_link_libraries(trex_ref_frontend PUBLIC trex_core)
endif()

if(TREX_BUILD_TESTS AND TREX_REF_SOURCES)
  add_executable(trex_port_cli "${CMAKE_SOURCE_DIR}/tools/port_cli.cpp")
  target_link_libraries(trex_port_cli PRIVATE trex_ref_frontend)

  file(GLOB TREX_TEST_SOURCES CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/tests/*.cpp")
  if(TREX_TEST_SOURCES)
    add_executable(trex_unit_tests ${TREX_TEST_SOURCES})
    target_include_directories(trex_unit_tests PRIVATE "${CMAKE_SOURCE_DIR}/tests")
    target_compile_definitions(trex_unit_tests PRIVATE TREX_FIXTURE_DIR="${CMAKE_SOURCE_DIR}/tests/fixtures/lifted")
    target_link_libraries(trex_unit_tests PRIVATE trex_ref_frontend)
    if(TARGET trex_interproc)
      target_link_libraries(trex_unit_tests PRIVATE trex_interproc)
    endif()
  endif()
endif()

# The plugin. trex_window.cpp is Qt code: pulled in only when CMake found a matching Qt (see the
# optional block at the end of this file). The Qt-less build (CI default, TREX_QT_UI=OFF) does not
# compile it, so the produced trexida.dll stays free of any Qt6 references.
file(GLOB TREX_IDA_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_SOURCE_DIR}/src/frontends/ida/*.cpp"
  "${CMAKE_SOURCE_DIR}/src/plugin/*.cpp")
list(REMOVE_ITEM TREX_IDA_SOURCES "${CMAKE_SOURCE_DIR}/src/plugin/trex_window.cpp")
add_library(trexida SHARED ${TREX_IDA_SOURCES})
set_target_properties(trexida PROPERTIES PREFIX "" OUTPUT_NAME "trexida")
target_include_directories(trexida PRIVATE
  "${CMAKE_SOURCE_DIR}/src/frontends/ida"
  "${CMAKE_SOURCE_DIR}/src/plugin")
target_link_libraries(trexida PRIVATE trex_core)
if(TARGET trex_interproc)
  target_link_libraries(trexida PRIVATE trex_interproc)
endif()
if(TREX_REF_SOURCES)
  target_link_libraries(trexida PRIVATE trex_ref_frontend)
endif()
target_link_libraries(trexida PRIVATE trex_ida_settings)

if(IDA_INSTALL_DIR)
  add_custom_command(TARGET trexida POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "$<TARGET_FILE:trexida>" "${IDA_INSTALL_DIR}/plugins/"
    COMMENT "Deploying trexida to ${IDA_INSTALL_DIR}/plugins")

  # IDA searches the per-user plugin directory before <IDADIR>/plugins, so a copy left there
  # shadows every rebuild. Refresh such a copy instead of silently shipping a stale plugin.
  # (An `if(EXISTS)` guard is used because the directory is optional.)
  set(TREX_IDA_USER_PLUGIN_DIR "$ENV{APPDATA}/Hex-Rays/IDA Pro/plugins")
  if(EXISTS "${TREX_IDA_USER_PLUGIN_DIR}/trexida.dll")
    add_custom_command(TARGET trexida POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different "$<TARGET_FILE:trexida>" "${TREX_IDA_USER_PLUGIN_DIR}/"
      COMMENT "Refreshing the per-user copy in ${TREX_IDA_USER_PLUGIN_DIR} (it would shadow this build)")
  endif()
endif()

option(TREX_QT_UI "Build the Qt types window" ON)
set(TREX_QT_ROOT "" CACHE PATH
    "Qt installation built with QT_NAMESPACE=QT matching the target IDA (e.g. <build>/qt-install from the SDK's build_qt target)")
if(TREX_QT_UI)
  # The SDK ships a self-contained Qt6 builder (Qt 6.8.2, QT_NAMESPACE=QT) - expose its target.
  set(TREX_QT_SUPPORT "${IDA_SDK_DIR}/../ida-cmake/cmake/QtSupport.cmake")
  if(EXISTS "${TREX_QT_SUPPORT}")
    include("${TREX_QT_SUPPORT}")
  endif()
  if(NOT TREX_QT_ROOT AND EXISTS "${CMAKE_BINARY_DIR}/qt-install/lib/cmake/Qt6")
    set(TREX_QT_ROOT "${CMAKE_BINARY_DIR}/qt-install")
  endif()
  if(TREX_QT_ROOT)
    list(PREPEND CMAKE_PREFIX_PATH "${TREX_QT_ROOT}")
    find_package(Qt6 COMPONENTS Core Gui Widgets QUIET)
  endif()
  if(TARGET Qt6::Core AND TARGET Qt6::Gui AND TARGET Qt6::Widgets)
    target_sources(trexida PRIVATE "${CMAKE_SOURCE_DIR}/src/plugin/trex_window.cpp")
    target_link_libraries(trexida PRIVATE Qt6::Core Qt6::Gui Qt6::Widgets)
    target_compile_definitions(trexida PRIVATE
      TREX_HAVE_QT=1 QT_NAMESPACE=QT QT_DLL QT_CORE_LIB QT_GUI_LIB QT_THREAD_SUPPORT QT_WIDGETS_LIB)
    # Qt needs RTTI and its headers need the SDK's own warning suppressions (plugins/qtplugin.mak).
    set_source_files_properties("${CMAKE_SOURCE_DIR}/src/plugin/trex_window.cpp" PROPERTIES
      COMPILE_OPTIONS "/GR;/wd4946;/wd4826;/wd4628;/wd4718")
    message(STATUS "trexida: Qt ${Qt6_VERSION} found - types window enabled")
  else()
    target_compile_definitions(trexida PRIVATE TREX_HAVE_QT=0)
    message(STATUS "trexida: Qt not found - building without the types window "
                   "(run 'cmake --build <build> --target build_qt' once, or set TREX_QT_ROOT)")
  endif()
else()
  target_compile_definitions(trexida PRIVATE TREX_HAVE_QT=0)
endif()
