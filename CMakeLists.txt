cmake_minimum_required(VERSION 3.30)
project(loompa LANGUAGES CXX)

set(CMAKE_CXX_STANDARD_23 ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

file(GLOB SOURCES CONFIGURE_DEPENDS "src/*.cpp")

add_executable(${PROJECT_NAME} ${SOURCES})

target_include_directories(${PROJECT_NAME}
    PRIVATE
        include
)

target_compile_options(${PROJECT_NAME}
    PRIVATE
        -Wall
        -Wextra
        -pedantic
)

target_precompile_headers(${PROJECT_NAME}
    PRIVATE 
        include/dependencies.hpp
)

target_compile_definitions(${PROJECT_NAME} 
    PRIVATE 
        PROJECT_ROOT="${CMAKE_SOURCE_DIR}"
)