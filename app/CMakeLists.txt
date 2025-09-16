cmake_minimum_required(VERSION 3.16)
project(BCordServer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Boost REQUIRED COMPONENTS system)
add_executable(BCordServer server/src/main.cpp)
target_link_libraries(BCordServer PRIVATE Boost::system)

