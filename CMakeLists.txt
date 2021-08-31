cmake_minimum_required(VERSION 3.13)
project(sneik NONE)
include(FetchContent)

enable_language(C)
enable_language(CXX)
set (CMAKE_CXX_STANDARD 11)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

FetchContent_Declare(
  benchmark
  SOURCE_DIR     ${PROJECT_SOURCE_DIR}/3rd/benchmark
  GIT_REPOSITORY https://github.com/kriskwiatkowski/benchmark.git
  GIT_TAG        49862ab56b6b7c3afd87b80bd5d787ed78ce3b96
)
FetchContent_Populate(benchmark)

FetchContent_Declare(
  libtomcrypt
  SOURCE_DIR     ${PROJECT_SOURCE_DIR}/3rd/libtomcrypt
  GIT_REPOSITORY https://github.com/libtom/libtomcrypt.git
  GIT_TAG        cfbd7f8d364e1438555ff2a247f7e17add11840e
)
FetchContent_Populate(libtomcrypt)

FetchContent_Declare(
  pqc
  SOURCE_DIR     ${PROJECT_SOURCE_DIR}/3rd/pqc
  GIT_REPOSITORY https://github.com/kriskwiatkowski/pqc.git
  GIT_TAG        944543c9b9d00586c7e739b39f3cbebc7cc3ddc1
)
FetchContent_Populate(pqc)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -fsanitize=address,leak,undefined -Wall -Werror -Wpedantic")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -fsanitize=address,leak,undefined -Wall -Werror -Wpedantic")
set(LDFLAGS_DEBUG "${LDFLAGS_DEBUG} -fsanitize=address,leak,undefined")
set(CMAKE_VERBOSE_MAKEFILE ON)
set(LIBTOMCRYPT_ROOT ${PROJECT_SOURCE_DIR}/3rd/libtomcrypt)
set(PQC_ROOT ${PROJECT_SOURCE_DIR}/3rd/pqc/)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/3rd/libpqc/src)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(ExternalProject)
find_program(MAKE_PROGRAM make)
find_package(OpenSSL REQUIRED)

message(${CMAKE_BUILD_TYPE})

# Target for benchmark - it also builds gtest library
set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "Disable testing of the benchmark library." FORCE)
set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "Disable benchmark tests" FORCE)
set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
add_subdirectory(3rd/benchmark)

ExternalProject_Add(LibTomCrypt
    SOURCE_DIR ${LIBTOMCRYPT_ROOT}
    BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/libtomcrypt-build
	CONFIGURE_COMMAND cp -rf <SOURCE_DIR> <BINARY_DIR>
	BUILD_COMMAND CFLAGS=-g ${MAKE_PROGRAM} -C <BINARY_DIR>/libtomcrypt
	INSTALL_COMMAND "")

ExternalProject_Add(LibPQC
    SOURCE_DIR ${PQC_ROOT}
    BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/libpqc-build
	INSTALL_COMMAND "")

include_directories(
	${LIBTOMCRYPT_ROOT}/src/headers
	${PQC_ROOT}/public)

# SNEIK library
add_library(
	sneik
	src/utils.c
	src/pqscake.c)

# SNEIK test exec
add_executable(
	sneik_test
	src/test.c)

add_dependencies(
	sneik
	LibTomCrypt
	LibPQC)

target_link_libraries(
	sneik
	${CMAKE_CURRENT_BINARY_DIR}/libtomcrypt-build/libtomcrypt/libtomcrypt.a
	${CMAKE_CURRENT_BINARY_DIR}/libpqc-build/libpqc_s.a
	${CMAKE_CURRENT_BINARY_DIR}/libpqc-build/3rd/cpu_features/libcpu_features.a
	OpenSSL::Crypto)

target_link_libraries(
	sneik_test
	sneik)

# SNEIK benchmark
add_executable(
	sneik_bench
	src/bench.cc)

add_dependencies(
	sneik_bench
	sneik
	LibTomCrypt
	LibPQC)

target_link_libraries(
	sneik_bench
	sneik
	benchmark::benchmark)

target_include_directories(
	sneik_bench
	PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}/3rd/benchmark/include)
