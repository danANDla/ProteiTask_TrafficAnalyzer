cmake_minimum_required(VERSION 3.25)
project(trafficAnalyzer)

set(CMAKE_CXX_STANDARD 20)

set(SRC_DIR ${PROJECT_SOURCE_DIR}/src)

set(PROJECT_LIB_NAME ${PROJECT_NAME})
set(LIB_SRC
        src/packetReader/packetReader.cpp
        src/packetCapture/packetCapturer.cpp
        src/utils/deviceManager.cpp)
add_library(${PROJECT_LIB_NAME} STATIC ${LIB_SRC})

target_include_directories(${PROJECT_LIB_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_include_directories(${PROJECT_LIB_NAME} PRIVATE ${SRC_DIR})
target_link_libraries(${PROJECT_LIB_NAME} PRIVATE Pcap++ Packet++ Common++ pcap pthread)

#
# trafficAnalyzer executable
#
set(PROJECT_EXEC_NAME ${PROJECT_NAME}_exec)
set(EXEC_SRC ${SRC_DIR}/main.cpp src/packetCapture/packetCapturer.cpp include/packetCapturer.h src/utils/deviceManager.cpp include/deviceManager.h src/packetParsing/packetParser.cpp)
add_executable(${PROJECT_EXEC_NAME} ${EXEC_SRC})
target_link_libraries(${PROJECT_EXEC_NAME} ${PROJECT_LIB_NAME})
















#cmake_minimum_required(VERSION 3.12)
#project(Tutorial-HelloWorld)
#
## Set C++11
#set(CMAKE_CXX_STANDARD 11)
## popen()/pclose() are not C++ standards
#set(CMAKE_CXX_EXTENSIONS ON)
#
#set(SRC_DIR ${PROJECT_SOURCE_DIR}/src)
#
#set(PROJECT_LIB_NAME ${PROJECT_NAME})
#set(LIB_SRC src/packetReader/packetReader.cpp)
#add_library(${PROJECT_LIB_NAME} STATIC ${LIB_SRC})
#target_include_directories(${PROJECT_LIB_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/include)
#target_include_directories(${PROJECT_LIB_NAME} PRIVATE ${SRC_DIR})
#
##
## trafficAnalyzer executable
##
#set(PROJECT_EXEC_NAME ${PROJECT_NAME}_exec)
#set(EXEC_SRC ${SRC_DIR}/main.cpp)
#add_executable(${PROJECT_EXEC_NAME} ${EXEC_SRC})
#target_link_libraries(${PROJECT_EXEC_NAME} ${PROJECT_LIB_NAME})
#
#
##
## addingPcapLibrary
##
#
### repo level
##set(PCAPPP_VERSION "22.11+")
### MAIN_PROJECT CHECK
##set(PCAPPP_MAIN_PROJECT OFF)
##if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
##    set(PCAPPP_MAIN_PROJECT ON)
##endif()
##
### Declare install folders location
##set(PCAPPP_INSTALL_BINDIR ${CMAKE_INSTALL_BINDIR})
##set(PCAPPP_INSTALL_CMAKEDIR ${CMAKE_INSTALL_LIBDIR}/cmake/pcapplusplus)
##set(PCAPPP_INSTALL_INCLUDEDIR ${CMAKE_INSTALL_INCLUDEDIR}/pcapplusplus)
##set(PCAPPP_INSTALL_LIBDIR ${CMAKE_INSTALL_LIBDIR})
##
##find_package(PCAP)
##if(NOT PCAP_FOUND)
##    if(WIN32)
##        message(FATAL_ERROR "Please specify Npcap/WinPcap SDK directory with -DPCAP_ROOT=<PCAP_SDK_PATH>")
##    else()
##        message(FATAL_ERROR "PCAP library not found!")
##    endif()
##endif()