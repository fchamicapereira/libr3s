cmake_minimum_required(VERSION 3.10)

# set the project name
project(libr3s)

include_directories(includes)
file(GLOB SOURCES "src/*.c")

include(ExternalProject)

ExternalProject_Add(Z3Download
    PREFIX              z3-prefix
    GIT_REPOSITORY      https://github.com/Z3Prover/z3.git
    #CMAKE_ARGS         -DCMAKE_INSTALL_PREFIX=.
    UPDATE_COMMAND      "" # Skip annoying updates for every build
    INSTALL_COMMAND     ""
)

SET(Z3_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/z3-prefix/src/z3-build/include)
SET(Z3_LIB_DIR ${CMAKE_CURRENT_BINARY_DIR}/z3-prefix/src/z3-build/lib)

add_library(z3 SHARED IMPORTED)
set_target_properties(z3 PROPERTIES IMPORTED_LOCATION ${Z3_LIB_DIR}/libz3.so)

include_directories(${Z3_INCLUDE_DIR})
add_library(r3s SHARED ${SOURCES})
target_link_libraries(r3s z3)
