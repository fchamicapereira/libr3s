cmake_minimum_required(VERSION 3.10)

# set the project name
project(libr3s)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG")
set(CMAKE_DEBUG_POSTFIX d)

include_directories(includes)
file(GLOB SOURCES ${PROJECT_SOURCE_DIR}/src/*.c)

include(ExternalProject)

ExternalProject_Add(Z3Download
    PREFIX              z3-prefix
    GIT_REPOSITORY      https://github.com/Z3Prover/z3.git
    CMAKE_ARGS          -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/z3-prefix/bin
    UPDATE_COMMAND      "" # Skip annoying updates for every build
)

set(Z3_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/z3-prefix/bin/include)
set(Z3_LIB_DIR ${CMAKE_CURRENT_BINARY_DIR}/z3-prefix/bin/lib)

add_library(z3 SHARED IMPORTED)
set_target_properties(z3 PROPERTIES IMPORTED_LOCATION ${Z3_LIB_DIR}/libz3.so)
include_directories(${Z3_INCLUDE_DIR})

add_library(r3s SHARED ${SOURCES})
set_target_properties(r3s PROPERTIES DEBUG_POSTFIX ${CMAKE_DEBUG_POSTFIX})
target_link_libraries(r3s z3)

include(${PROJECT_SOURCE_DIR}/examples.cmake)

foreach( example_src ${EXAMPLES_SOURCES} )
    get_filename_component(example ${example_src} NAME_WE)
    MESSAGE(${example_src} ${example})
    add_executable(${example} ${example_src})
    target_link_libraries(${example} r3s)
endforeach( example_src ${EXAMPLES_SOURCES} )
