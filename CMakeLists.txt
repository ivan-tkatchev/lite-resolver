cmake_minimum_required(VERSION 3.10)
project(dns_resolver)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(INCLUDE_DIRS
    "${CMAKE_CURRENT_SOURCE_DIR}")

set(SOURCES
    resolver.cc
  )
set(src_total ${SOURCES})
add_library(dns_resolver STATIC ${SOURCES})

target_include_directories(dns_resolver PUBLIC ${INCLUDE_DIRS})
