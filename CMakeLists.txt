cmake_minimum_required(VERSION 3.20)

project(network_scanner LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(network_scanner
    src/main.cpp
    src/core/scanner.cpp
    src/discovery/icmp_discovery.cpp
    src/discovery/target_resolver.cpp
    src/ports/tcp_port_scanner.cpp
    src/output/formatter.cpp
)

target_include_directories(network_scanner PRIVATE
    include
    src
)

target_link_libraries(network_scanner PRIVATE
    iphlpapi
    ws2_32
)
