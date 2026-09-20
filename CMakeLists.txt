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

set(IDA_SDK_DIR "$ENV{IDASDK}/src" CACHE PATH "IDA SDK root (must contain include/ and lib/)")
set(IDA_INSTALL_DIR "$ENV{IDADIR}" CACHE PATH "IDA installation directory (plugin DLL is deployed here)")
option(TREX_BUILD_TESTS "Build the test executables" ON)

# ---------------------------------------------------------------- compiler ---
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

if(NOT EXISTS "${IDA_SDK_DIR}/include/hexrays.hpp")
  message(FATAL_ERROR "IDA SDK headers not found at '${IDA_SDK_DIR}/include' (set -DIDA_SDK_DIR=...)")
endif()
set(IDA_LIB "${IDA_SDK_DIR}/lib/x64_win_vc_64/ida.lib")
if(NOT EXISTS "${IDA_LIB}")
  message(FATAL_ERROR "IDA import library not found at '${IDA_LIB}'")
endif()

# ------------------------------------------------------------ ida settings ---
add_library(trex_ida_settings INTERFACE)
target_include_directories(trex_ida_settings INTERFACE "${IDA_SDK_DIR}/include")
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

# The plugin.
file(GLOB TREX_IDA_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_SOURCE_DIR}/src/frontends/ida/*.cpp"
  "${CMAKE_SOURCE_DIR}/src/plugin/*.cpp")
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
