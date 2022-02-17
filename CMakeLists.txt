cmake_minimum_required(VERSION 3.10)
project(dns_resolver)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "-Wall -Wextra")
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

set(INCLUDE_DIRS
    "${CMAKE_CURRENT_SOURCE_DIR}")

set(SOURCES
    resolver.cc
  )
set(src_total ${SOURCES})
add_library(dns_resolver STATIC ${SOURCES})
target_compile_options(dns_resolver PRIVATE -fPIC)

target_include_directories(dns_resolver PUBLIC ${INCLUDE_DIRS})

install(FILES resolver.hh DESTINATION include)
install(TARGETS dns_resolver DESTINATION lib)
install(FILES DNSResolverConfig.cmake DESTINATION lib/cmake/DNSResolver)
