# Minimum CMake version that understands the features we use.
cmake_minimum_required(VERSION 3.10)

# Project name and the language (C). This also sets variables like
# PROJECT_NAME and enables the C compiler detection.
project(mini_tcpip C)

# Use the C11 standard, and require it (don't silently fall back).
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler flags applied to every target below:
#   -Wall -Wextra : enable a broad set of warnings (treat them as bugs-to-be)
#   -g            : embed debug symbols so gdb can show source + variables
add_compile_options(-Wall -Wextra -g)

# Build one executable named "mtcp" from these three translation units.
# Headers are NOT listed: they are #included into the .c files, not compiled.
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
