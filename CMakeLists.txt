cmake_minimum_required(VERSION 3.15)
project(httpflow)

set(CMAKE_CXX_STANDARD 98)

include_directories(. /usr/local/include)

add_executable(httpflow
        stream_parser.cpp
        stream_parser.h
        data_link.cpp
        data_link.h
        http_flow.cpp
        http_parser.cpp
        http_parser.h
        util.cpp
        util.h)

target_link_libraries(httpflow z pcap pcre)
