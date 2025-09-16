cmake_minimum_required(VERSION 3.16)
project(BCordServer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Boost REQUIRED COMPONENTS system)

# try CMake package first…
find_package(pqxx QUIET)

add_executable(BCordServer server/src/main.cpp)
target_link_libraries(BCordServer PRIVATE Boost::system)

if(pqxx_FOUND)
  message(STATUS "Using pqxx via CMake package")
  target_link_libraries(BCordServer PRIVATE pqxx::pqxx)
else()
  message(STATUS "pqxx CMake package not found; falling back to pkg-config")
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(PQXX REQUIRED libpqxx)

  target_include_directories(BCordServer PRIVATE ${PQXX_INCLUDE_DIRS})
  target_link_libraries(BCordServer PRIVATE ${PQXX_LIBRARIES})
  add_definitions(${PQXX_CFLAGS_OTHER})
endif()

