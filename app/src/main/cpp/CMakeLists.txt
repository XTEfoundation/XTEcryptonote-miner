cmake_minimum_required(VERSION 3.22.1)
project(xte_chukwa)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -Wall")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -Wall -std=c++17")

# Official phc-winner-argon2 (ref implementation — portable for ARM)
set(ARGON2_DIR ${CMAKE_SOURCE_DIR}/argon2)
add_library(argon2_ref STATIC
    ${ARGON2_DIR}/src/argon2.c
    ${ARGON2_DIR}/src/core.c
    ${ARGON2_DIR}/src/encoding.c
    ${ARGON2_DIR}/src/blake2/blake2b.c
    ${ARGON2_DIR}/src/thread.c
    ${ARGON2_DIR}/src/ref.c
)
target_include_directories(argon2_ref PUBLIC
    ${ARGON2_DIR}/include
    ${ARGON2_DIR}/src
)
target_compile_definitions(argon2_ref PRIVATE ARGON2_NO_THREADS)

add_library(xte_chukwa SHARED native-lib.cpp)
target_include_directories(xte_chukwa PRIVATE
    ${ARGON2_DIR}/include
    ${ARGON2_DIR}/src
)
target_compile_options(xte_chukwa PRIVATE
    -fstack-protector-strong
    -fno-strict-overflow
    -Wformat
    -Werror=format-security
)
target_link_options(xte_chukwa PRIVATE
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
)
set_target_properties(xte_chukwa PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)
target_link_libraries(xte_chukwa argon2_ref log)
