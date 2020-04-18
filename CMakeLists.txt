###############################################################################
# Project version
###############################################################################

cmake_minimum_required(VERSION 3.10)

project(libr3s)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)


################################################################################
# Arguments
################################################################################

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG")
set(CMAKE_DEBUG_POSTFIX d)

set(BUILD_EXAMPLES OFF CACHE BOOL "Build examples")


################################################################################
# Sanity check - Disallow building in source.
# Otherwise we would overwrite the Makefiles of the old build system.
################################################################################

if ("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
  message(FATAL_ERROR "In source builds are not allowed. You should invoke "
          "CMake from a different directory.")
endif()


###############################################################################
# Configure external projects
###############################################################################

set(EXTERNAL_INSTALL_LOCATION ${CMAKE_BINARY_DIR}/external)
include(ExternalProject)

ExternalProject_Add(Z3Download
    PREFIX              z3-prefix
    GIT_REPOSITORY      https://github.com/Z3Prover/z3.git
    CMAKE_ARGS          -DCMAKE_INSTALL_PREFIX=${EXTERNAL_INSTALL_LOCATION}
    UPDATE_COMMAND      "" # Skip annoying updates for every build
)

include_directories(${EXTERNAL_INSTALL_LOCATION}/include)
link_directories(${EXTERNAL_INSTALL_LOCATION}/lib)


###############################################################################
# Create r3s library
###############################################################################

file(GLOB SOURCES ${PROJECT_SOURCE_DIR}/src/*.c)
add_library(r3s SHARED ${SOURCES})

target_include_directories(r3s
    PUBLIC 
        $<INSTALL_INTERFACE:include>    
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_options(r3s PRIVATE -Werror)
add_dependencies(r3s Z3Download)

set_target_properties(r3s PROPERTIES DEBUG_POSTFIX ${CMAKE_DEBUG_POSTFIX})
target_link_libraries(r3s PUBLIC z3)


###############################################################################
# Build examples
###############################################################################

if (${BUILD_EXAMPLES})
    include(${PROJECT_SOURCE_DIR}/examples.cmake)

    foreach( example_src ${EXAMPLES_SOURCES} )
        get_filename_component(example ${example_src} NAME_WE)
        add_executable(${example} ${example_src})
        target_link_libraries(${example} r3s)
    endforeach( example_src ${EXAMPLES_SOURCES} )
endif ()