cmake_minimum_required(VERSION 3.16)
project(BCordServer LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

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

# ✅ Enforce C++23 ABI everywhere
target_compile_features(BCordServer PRIVATE cxx_std_23)
target_compile_options(BCordServer PRIVATE -std=c++23)

# Explicitly link libpqxx and libpq
if (TARGET pqxx::pqxx)
  target_link_libraries(BCordServer PRIVATE Boost::system Threads::Threads OpenSSL::Crypto pqxx::pqxx pq)
else()
  target_link_libraries(BCordServer PRIVATE Boost::system Threads::Threads OpenSSL::Crypto PkgConfig::PQXX pq)
endif()

# ✅ If linker still complains, force static stdc++lib resolution
set_target_properties(BCordServer PROPERTIES
  LINK_FLAGS "-Wl,--allow-multiple-definition -static-libstdc++"
)

