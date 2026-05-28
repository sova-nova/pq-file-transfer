cmake_minimum_required(VERSION 3.16)
project(pq-file-transfer VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_AUTOMOC ON)

# --- Protocol library (now compiled, shared by server and client) ---
add_library(protocol
    protocol/protocol.cpp
)
target_include_directories(protocol PUBLIC ${CMAKE_SOURCE_DIR}/protocol)

# --- Relay Server ---
add_executable(pq-server server/main.cpp)
target_link_libraries(pq-server PRIVATE protocol)

# --- Client (Qt 6) ---
find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets)

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
)