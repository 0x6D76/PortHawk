cmake_minimum_required(VERSION 3.26)
project(PortHawk)

set(CMAKE_CXX_STANDARD 17)

include_directories(.)
include_directories(include)

add_executable(PortHawk
        include/logger.hpp
        source/logger.cpp
        source/porthawk.cpp
)
