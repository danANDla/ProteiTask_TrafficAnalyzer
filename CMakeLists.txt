cmake_minimum_required(VERSION 3.25)
project(trafficAnalyzer)

set(CMAKE_CXX_STANDARD 20)

set(SRC_DIR ${PROJECT_SOURCE_DIR}/src)

set(PROJECT_LIB_NAME ${PROJECT_NAME})
set(LIB_SRC
        src/packetReader/packetReader.cpp
        src/packetCapture/packetCapturer.cpp
        src/utils/deviceManager.cpp
        src/packetParsing/packetParser.cpp)
add_library(${PROJECT_LIB_NAME} STATIC ${LIB_SRC})

target_include_directories(${PROJECT_LIB_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_include_directories(${PROJECT_LIB_NAME} PRIVATE ${SRC_DIR})
target_link_libraries(${PROJECT_LIB_NAME} PRIVATE Pcap++ Packet++ Common++ pcap pthread)

#
# trafficAnalyzer executable
#
set(PROJECT_EXEC_NAME ${PROJECT_NAME}_exec)
set(EXEC_SRC ${SRC_DIR}/main.cpp src/packetCapture/packetCapturer.cpp include/packetCapturer.h src/utils/deviceManager.cpp include/deviceManager.h src/packetParsing/packetParser.cpp include/packetParser.h include/SSLStatsCollector.h)
add_executable(${PROJECT_EXEC_NAME} ${EXEC_SRC})
target_link_libraries(${PROJECT_EXEC_NAME} ${PROJECT_LIB_NAME})