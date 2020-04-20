###############################################################################
# Find pcap
###############################################################################

find_package(PCAP)

if (PCAP_FOUND)
    message(STATUS "Found PCAP")
    
    include_directories(${PCAP_INCLUDE_DIRS})
    link_directories(${PCAP_LIBRARIES})

    target_link_libraries(${PROJECT_NAME} PUBLIC ${PCAP_LIBRARIES})
else()
    message (FATAL_ERROR "PCAP not found.")
endif()

