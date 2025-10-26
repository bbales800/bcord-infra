cmake_minimum_required(VERSION 3.16)
project(BCordServer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Threads REQUIRED)
find_package(Boost 1.74 REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED)

# Try modern CMake package for pqxx, else fall back to pkg-config
find_package(pqxx QUIET)
if (NOT pqxx_FOUND)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(PQXX REQUIRED IMPORTED_TARGET libpqxx)
endif()

# hiredis and redis++
find_package(PkgConfig REQUIRED)
pkg_check_modules(HIREDIS REQUIRED hiredis)

include_directories(
  ${Boost_INCLUDE_DIRS}
  ${PQXX_INCLUDE_DIRS}
  ${HIREDIS_INCLUDE_DIRS}
  /usr/local/include
)

link_directories(
  ${PQXX_LIBRARY_DIRS}
  ${HIREDIS_LIBRARY_DIRS}
  /usr/local/lib
)

add_executable(BCordServer src/main.cpp)

target_compile_features(BCordServer PRIVATE cxx_std_23)
target_compile_definitions(BCordServer PRIVATE BOOST_SYSTEM_DYN_LINK)

if (TARGET pqxx::pqxx)
  target_link_libraries(BCordServer PRIVATE
    Boost::system
    Threads::Threads
    OpenSSL::Crypto
    pqxx::pqxx
    pq
    redis++          # ✅ Redis++ shared library
    hiredis          # ✅ hiredis dependency
  )
else()
  target_link_libraries(BCordServer PRIVATE
    Boost::system
    Threads::Threads
    OpenSSL::Crypto
    PkgConfig::PQXX
    pq
    redis++
    hiredis
  )
endif()

