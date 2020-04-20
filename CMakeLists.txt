###############################################################################
# Project version
###############################################################################

cmake_minimum_required(VERSION 3.10)

project("r3s")

include(GNUInstallDirs)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)


################################################################################
# Add our CMake module directory to the list of module search directories
################################################################################

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")


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
# Create r3s library
###############################################################################

file(GLOB SOURCES ${PROJECT_SOURCE_DIR}/src/*.c)
add_library(${PROJECT_NAME} SHARED ${SOURCES})

target_include_directories(${PROJECT_NAME}
    PUBLIC 
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>    
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_options(${PROJECT_NAME} PRIVATE -Werror)

set_target_properties(${PROJECT_NAME} PROPERTIES DEBUG_POSTFIX ${CMAKE_DEBUG_POSTFIX})


###############################################################################
# Configure external projects
###############################################################################

include(${CMAKE_SOURCE_DIR}/cmake/find_z3.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/find_pcap.cmake)


###############################################################################
# Build examples
###############################################################################

if (${BUILD_EXAMPLES})
    include(${PROJECT_SOURCE_DIR}/cmake/examples.cmake)

    foreach( example_src ${EXAMPLES_SOURCES} )
        get_filename_component(example ${example_src} NAME_WE)
        add_executable(${example} ${example_src})
        target_link_libraries(${example} ${PROJECT_NAME})
    endforeach( example_src ${EXAMPLES_SOURCES} )
endif ()


###############################################################################
# Installation
###############################################################################

install(
    TARGETS ${PROJECT_NAME}
    EXPORT  ${PROJECT_NAME}_Targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

INSTALL (
    DIRECTORY       ${CMAKE_SOURCE_DIR}/include/
    DESTINATION     include
    FILES_MATCHING  PATTERN "*.h*"
)
