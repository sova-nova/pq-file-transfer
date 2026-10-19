cmake_minimum_required(VERSION 3.16)
project(pq-file-transfer VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# The relay server has no GUI or liboqs dependency, so it can be built alone
# on a headless machine with -DPQ_BUILD_CLIENT=OFF.
option(PQ_BUILD_CLIENT "Build the Qt client" ON)

find_package(Threads REQUIRED)
find_package(OpenSSL 1.1.1 REQUIRED)

function(pq_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /utf-8 /permissive-)
        target_compile_definitions(${target} PRIVATE _CRT_SECURE_NO_WARNINGS)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
    endif()
endfunction()

# --- Protocol library (shared by server and client) ---
add_library(protocol STATIC protocol/protocol.cpp)
target_include_directories(protocol PUBLIC ${CMAKE_SOURCE_DIR}/protocol)
pq_warnings(protocol)
if(WIN32)
    target_link_libraries(protocol PUBLIC ws2_32)
    target_compile_definitions(protocol PUBLIC WIN32_LEAN_AND_MEAN NOMINMAX)
endif()

# --- Relay server ---
add_executable(pq-server server/main.cpp)
target_link_libraries(pq-server PRIVATE protocol Threads::Threads OpenSSL::Crypto)
pq_warnings(pq-server)

# --- Client (Qt 6 + liboqs + OpenSSL) ---
if(PQ_BUILD_CLIENT)
    set(CMAKE_AUTOMOC ON)
    find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets)

    # Prefer liboqs's installed CMake package; fall back to a manual search.
    find_package(liboqs CONFIG QUIET)
    if(TARGET OQS::oqs)
        set(PQ_OQS OQS::oqs)
    else()
        find_library(OQS_LIBRARY NAMES oqs liboqs PATHS /usr/local/lib)
        find_path(OQS_INCLUDE_DIR NAMES oqs/oqs.h PATHS /usr/local/include)
        if(NOT OQS_LIBRARY OR NOT OQS_INCLUDE_DIR)
            message(FATAL_ERROR
                "liboqs not found. Install it (see README), pass -DOQS_LIBRARY=... and "
                "-DOQS_INCLUDE_DIR=..., or configure with -DPQ_BUILD_CLIENT=OFF to build only the server.")
        endif()
        add_library(pq_oqs INTERFACE)
        target_link_libraries(pq_oqs INTERFACE ${OQS_LIBRARY})
        target_include_directories(pq_oqs INTERFACE ${OQS_INCLUDE_DIR})
        set(PQ_OQS pq_oqs)
    endif()

    add_executable(pq-client
        client/main.cpp
        client/main_window.h
        client/main_window.cpp
        client/transfer_engine.cpp
        client/crypto_engine.cpp
        client/key_store.cpp
    )
    target_link_libraries(pq-client PRIVATE
        protocol
        Qt6::Core
        Qt6::Gui
        Qt6::Widgets
        Threads::Threads
        ${PQ_OQS}
        OpenSSL::Crypto
    )
    pq_warnings(pq-client)
endif()
