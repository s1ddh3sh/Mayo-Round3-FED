cmake_minimum_required(VERSION 3.20)

project(mayo_round3_llvm)

# Use system LLVM instead of /usr/local
set(LLVM_DIR "/usr/lib/llvm-20/lib/cmake/llvm")
set(CLANG_DIR "/usr/lib/llvm-20/lib/cmake/clang")
set(CMAKE_PREFIX_PATH "/usr/lib/llvm-20")

find_package(LLVM REQUIRED CONFIG HINTS ${LLVM_DIR} NO_DEFAULT_PATH)
find_package(Clang REQUIRED CONFIG HINTS ${CLANG_DIR} NO_DEFAULT_PATH)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

# LLVM / Clang setup
include_directories(${LLVM_INCLUDE_DIRS})
include_directories(SYSTEM ${CLANG_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

# Z3 setup
find_package(Z3 QUIET)
if(NOT Z3_FOUND)
  # Fall back to pkg-config if find_package fails
  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    pkg_check_modules(Z3 REQUIRED z3)
  else()
    message(Error "Z3 not found and pkg-config not available")
  endif()
endif()

# --------------------
# llvmgen: MAYO round-3 C sources -> ../no_struct/mayo{1,2,3,5}.ll
# --------------------
add_executable(llvmgen llvmgen.cpp)

# Link Clang *components*
target_link_libraries(llvmgen
  PRIVATE
  clangFrontend
  clangDriver
  clangSerialization
  clangCodeGen
  clangParse
  clangSema
  clangAnalysis
  clangAST
  clangASTMatchers
  clangEdit
  clangLex
  clangBasic
)

# --------------------
# level_prop: .ll -> ../taintResults/<function>.json
# --------------------
add_executable(level_prop level_prop.cpp)

# Map needed LLVM components to library names
llvm_map_components_to_libnames(LLVM_LIBS
  core
  support
  irreader
  analysis
  passes
)

target_link_libraries(level_prop
  PRIVATE
  ${LLVM_LIBS}
  ${Z3_LIBRARIES}
)

target_include_directories(level_prop
  PRIVATE
  ${Z3_INCLUDE_DIRS}
)
