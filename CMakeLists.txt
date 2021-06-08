cmake_minimum_required(VERSION 3.10)
project(dns_client)

set(CMAKE_CXX_STANDARD 20)

include_directories(third_party/asio/include third_party/cmdline third_party/fmt/include third_party/tabulate)

add_executable(dns_client main.cpp dns.cpp)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)
target_compile_definitions(dns_client PUBLIC ASIO_HAS_CO_AWAIT ASIO_HAS_STD_COROUTINE FMT_HEADER_ONLY )
target_compile_options(dns_client PRIVATE -fcoroutines)
target_link_libraries(dns_client Threads::Threads)
