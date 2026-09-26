cmake_minimum_required(VERSION 3.20)

project(constructor)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(constructor
    main.cpp
    timelineConstructor.cpp
)

target_include_directories(constructor PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../collector/include
)

target_compile_options(constructor PRIVATE
    -O2
)

set_target_properties(constructor PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)