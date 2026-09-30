cmake_minimum_required(VERSION 3.20)

project(risk)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR})

file(GLOB_RECURSE SOURCES
    CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
)

add_executable(risk
    ${SOURCES}
)

target_include_directories(risk PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(MSVC)

    target_compile_options(risk PRIVATE
        /W4
    )

else()

    target_compile_options(risk PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -O2
    )

endif()