cmake_minimum_required(VERSION 3.24)
project(chat_server LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=native")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -g3")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3")

file(GLOB_RECURSE SOURCES
  "src/*.c"
  "generated/*.c"
)

add_executable(${CMAKE_PROJECT_NAME}
  ${SOURCES}
  "third_party/mongoose/mongoose.c"
)

add_subdirectory(third_party/protobuf-c/build-cmake)

find_package(OpenSSL REQUIRED)

set(RS_CRYPTO_DIR "${CMAKE_SOURCE_DIR}/../rs-crypto")
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  set(CARGO_BUILD_TYPE "--release")
  set(CARGO_TARGET_DIR "release")
else()
  set(CARGO_BUILD_TYPE "")
  set(CARGO_TARGET_DIR "debug")
endif()

set(RS_CRYPTO_LIB "${RS_CRYPTO_DIR}/target/${CARGO_TARGET_DIR}/libcrypto.dylib")

add_custom_command(
  OUTPUT ${RS_CRYPTO_LIB}
  COMMAND cargo build ${CARGO_BUILD_TYPE}
  WORKING_DIRECTORY ${RS_CRYPTO_DIR}
  COMMENT "Building rs-crypto Rust library"
)

add_custom_target(rs_crypto DEPENDS ${RS_CRYPTO_LIB})

target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE
  protobuf-c
  sqlite3
  OpenSSL::SSL
  OpenSSL::Crypto
  ${RS_CRYPTO_LIB}
)

target_include_directories(${CMAKE_PROJECT_NAME}
  PUBLIC
    "include"
    "generated"
  PRIVATE
    "third_party/protobuf-c"
    "third_party/protobuf-c/protobuf-c"
    "third_party/mongoose"
    "../rs-crypto/include"
)

set_source_files_properties(${SOURCES} PROPERTIES COMPILE_FLAGS "-Wall -Wextra -Wpedantic -Werror")
