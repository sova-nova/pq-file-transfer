cmake_minimum_required(VERSION 3.16)
project(pq-file-transfer VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_AUTOMOC ON)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# --- Protocol library ---
add_library(protocol
    protocol/protocol.cpp
)
target_include_directories(protocol PUBLIC ${CMAKE_SOURCE_DIR}/protocol)

# --- Relay Server ---
add_executable(pq-server server/main.cpp)
target_link_libraries(pq-server PRIVATE protocol Threads::Threads)

# --- Client (Qt 6 + liboqs + OpenSSL) ---
find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets)

find_library(OQS_LIBRARY NAMES oqs PATHS /usr/local/lib)
find_path(OQS_INCLUDE_DIR NAMES oqs/oqs.h PATHS /usr/local/include)

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
    ${OQS_LIBRARY}
    OpenSSL::SSL
    OpenSSL::Crypto
)

target_include_directories(pq-client PRIVATE ${OQS_INCLUDE_DIR})

# Windows-specific: link ws2_32
if(WIN32)
    target_link_libraries(pq-server PRIVATE ws2_32)
    target_link_libraries(pq-client PRIVATE ws2_32)
endif()