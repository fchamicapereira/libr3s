###############################################################################
# Find Z3
###############################################################################

find_package(Z3)

if (Z3_FOUND)
    message(STATUS "Found Z3")
    
    include_directories(${Z3_INCLUDE_DIRS})
    link_directories(${Z3_LIBRARIES})

    target_link_libraries(${PROJECT_NAME} PUBLIC ${Z3_LIBRARIES})
else()
    message (FATAL_ERROR "Z3 not found. Installing.")

    # TODO: download the missing library (is this the right thing to do?)
    include(include(ExternalProject))
    set(EXTERNAL_INSTALL_LOCATION ${CMAKE_BINARY_DIR}/external)
    ExternalProject_Add(Z3Download
        PREFIX              z3-prefix
        GIT_REPOSITORY      https://github.com/Z3Prover/z3.git
        CMAKE_ARGS          -DCMAKE_INSTALL_PREFIX=${EXTERNAL_INSTALL_LOCATION}
        UPDATE_COMMAND      "" # Skip annoying updates for every build
    )

    include_directories(${EXTERNAL_INSTALL_LOCATION}/include)
    link_directories(${EXTERNAL_INSTALL_LOCATION}/lib)
endif()
