###############################################################################
# Find pcap
###############################################################################

find_package(SCTP)

if (SCTP_FOUND)
    message(STATUS "Found SCTP")
    
    include_directories(${SCTP_INCLUDE_DIRS})
    link_directories(${SCTP_LIBRARIES})

    target_link_libraries(${PROJECT_NAME} PUBLIC ${SCTP_LIBRARIES})
else()
    message (FATAL_ERROR "SCTP not found. If you are using Ubuntu, you need to install it: `sudo apt install libsctp-dev`.")
endif()

