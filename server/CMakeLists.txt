cmake_minimum_required(VERSION 3.16)
project(BCordServer CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_package(Boost 1.74 REQUIRED COMPONENTS system)
find_package(PkgConfig REQUIRED)

# hiredis / libpqxx via pkg-config (headers + lib dirs)
pkg_check_modules(HIREDIS REQUIRED hiredis)
pkg_check_modules(PQXX    REQUIRED libpqxx)

# Source
add_executable(BCordServer
  src/main.cpp
  # If you later split auth to src/auth.cpp, add it here:
  # src/auth.cpp
)

# Include dirs
target_include_directories(BCordServer PRIVATE
  ${HIREDIS_INCLUDE_DIRS}
  ${PQXX_INCLUDE_DIRS}
  /usr/local/include      # redis++ headers if needed
)

# Lib dirs
target_link_directories(BCordServer PRIVATE
  ${HIREDIS_LIBRARY_DIRS}
  ${PQXX_LIBRARY_DIRS}
  /usr/local/lib          # redis++ installed here by your Dockerfile
)

# Link everything needed
target_link_libraries(BCordServer PRIVATE
  Boost::system
  OpenSSL::Crypto
  CURL::libcurl
  Threads::Threads
  pq                     # libpq (PostgreSQL client)
  pqxx                   # libpqxx (C++ wrapper)
  redis++                # libredis++ (from /usr/local/lib)
  hiredis                # libhiredis
  argon2                 # 👈 *** THIS IS THE FIX *** (libargon2)
)

# Prefer rpath so /usr/local/lib is used in the runtime container
set_target_properties(BCordServer PROPERTIES
  BUILD_RPATH "/usr/local/lib"
  INSTALL_RPATH "/usr/local/lib"
)

