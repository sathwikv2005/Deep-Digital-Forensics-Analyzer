cmake_minimum_required(VERSION 3.20)

project(correlation)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR})

add_executable(correlation
    src/main.cpp
    src/correlationEngine.cpp
    src/correlationRule.cpp
    src/indicatorExtractor.cpp
)

target_include_directories(correlation PRIVATE
    include
)

if(MSVC)
    target_compile_options(correlation PRIVATE /W4)
else()
    target_compile_options(correlation PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -O2
    )
endif()