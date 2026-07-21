cmake_minimum_required(VERSION 3.10)

project(mini_tcpip C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_options(-Wall -Wextra -g)

add_executable(mtcp
    src/main.c
    src/tap.c
    src/ethernet.c
    src/arp.c
    src/checksum.c
    src/ip.c
    src/icmp.c
    src/udp.c
    src/tcp.c
)
