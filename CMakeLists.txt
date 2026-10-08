cmake_minimum_required(VERSION 3.10)
project(binary_http CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_options(-Wall -Wextra)

# Shared protocol headers.
set(HEADERS
    include/protocol.hpp
    include/frame_io.hpp
)

add_executable(bserve src/bserve.cpp ${HEADERS})
target_include_directories(bserve PRIVATE include)

add_executable(bcurl src/bcurl.cpp ${HEADERS})
target_include_directories(bcurl PRIVATE include)
