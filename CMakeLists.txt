cmake_minimum_required(VERSION 3.27)
project(wif C)

set(CMAKE_C_STANDARD 23)

add_executable(a.out wif.c)

target_link_libraries(a.out -lpcap)
