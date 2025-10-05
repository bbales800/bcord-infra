cmake_minimum_required(VERSION 3.16)
project(BCordServer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(Threads REQUIRED)
find_package(Boost 1.74 REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED)

# Prefer CMake package for pqxx; fall back to pkg-config
find_package(pqxx QUIET)
if (NOT pqxx_FOUND)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(PQXX REQUIRED IMPORTED_TARGET libpqxx)
endif()

add_executable(BCordServer
  server/src/main.cpp
)

target_compile_definitions(BCordServer PRIVATE
  BOOST_SYSTEM_DYN_LINK
  BOOST_SYSTEM_NO_LIB
  BOOST_SYSTEM_NO_DEPRECATED
)

if (TARGET pqxx::pqxx)
  target_link_libraries(BCordServer PRIVATE Boost::system Threads::Threads OpenSSL::Crypto pqxx::pqxx)
else()
  target_link_libraries(BCordServer PRIVATE Boost::system Threads::Threads OpenSSL::Crypto PkgConfig::PQXX)
endif()
