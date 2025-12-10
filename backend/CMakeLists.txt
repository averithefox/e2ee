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

target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE protobuf-c sqlite3 OpenSSL::SSL OpenSSL::Crypto)

target_include_directories(${CMAKE_PROJECT_NAME}
  PUBLIC
    "include"
    "generated"
  PRIVATE
    "third_party/protobuf-c"
    "third_party/protobuf-c/protobuf-c"
    "third_party/mongoose"
)

set_source_files_properties(${SOURCES} PROPERTIES COMPILE_FLAGS "-Wall -Wextra -Wpedantic -Werror")
