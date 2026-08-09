cmake_minimum_required(VERSION 3.20)

project(Collector LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR})

file(GLOB_RECURSE SOURCES
    CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp"
)

list(FILTER SOURCES EXCLUDE REGEX ".*/build/.*")

add_executable(collector ${SOURCES})

target_include_directories(collector PRIVATE
    .
    include
)

target_link_libraries(collector PRIVATE wevtapi)