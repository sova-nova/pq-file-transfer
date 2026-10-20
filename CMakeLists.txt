cmake_minimum_required(VERSION 3.16)
project(pq-file-transfer VERSION 0.7.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# The relay server and the command-line tools need liboqs and SQLite but not Qt, so a headless
# machine can build them with -DPQ_BUILD_CLIENT=OFF.
option(PQ_BUILD_CLIENT "Build the Qt client" ON)
# Make the build fail if QtKeychain (OS keychain support) can't be found, instead of quietly
# building a client that can't remember the passphrase. The release workflow turns this on.
option(PQ_REQUIRE_KEYCHAIN "Fail if QtKeychain is not found" OFF)
# Tests need liboqs and SQLite. Run them with: ctest --test-dir build --output-on-failure
option(PQ_BUILD_TESTS "Build the test suite" OFF)

find_package(Threads REQUIRED)
find_package(OpenSSL 1.1.1 REQUIRED)
find_package(SQLite3 REQUIRED)

function(pq_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /utf-8 /permissive-)
        target_compile_definitions(${target} PRIVATE _CRT_SECURE_NO_WARNINGS)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
    endif()
endfunction()

# --- liboqs (ML-KEM, ML-DSA): needed by the relay (it verifies and signs) as well as the client ---
# Prefer liboqs's installed CMake package; fall back to a manual search.
find_package(liboqs CONFIG QUIET)
if(TARGET OQS::oqs)
    set(PQ_OQS OQS::oqs)
else()
    find_library(OQS_LIBRARY NAMES oqs liboqs PATHS /usr/local/lib)
    find_path(OQS_INCLUDE_DIR NAMES oqs/oqs.h PATHS /usr/local/include)
    if(NOT OQS_LIBRARY OR NOT OQS_INCLUDE_DIR)
        message(FATAL_ERROR
            "liboqs not found. Install it (see README), or pass -DOQS_LIBRARY=... and -DOQS_INCLUDE_DIR=...")
    endif()
    add_library(pq_oqs INTERFACE)
    target_link_libraries(pq_oqs INTERFACE ${OQS_LIBRARY})
    target_include_directories(pq_oqs INTERFACE ${OQS_INCLUDE_DIR})
    set(PQ_OQS pq_oqs)
endif()

# --- Protocol library: framing and message encodings, shared by relay and clients ---
add_library(protocol STATIC protocol/protocol.cpp protocol/relay_protocol.cpp)
target_include_directories(protocol PUBLIC ${CMAKE_SOURCE_DIR}/protocol)
pq_warnings(protocol)
if(WIN32)
    target_link_libraries(protocol PUBLIC ws2_32)
    target_compile_definitions(protocol PUBLIC WIN32_LEAN_AND_MEAN NOMINMAX)
endif()

# --- Crypto wrappers (liboqs + OpenSSL), used by relay and client ---
add_library(pq_crypto STATIC client/crypto_engine.cpp)
target_include_directories(pq_crypto PUBLIC ${CMAKE_SOURCE_DIR}/client)
target_link_libraries(pq_crypto PUBLIC protocol ${PQ_OQS} OpenSSL::Crypto)
pq_warnings(pq_crypto)

# --- The relay: mailbox store and service (protocol v3) ---
add_library(pq_relay STATIC server/relay_store.cpp server/relay_service.cpp)
target_include_directories(pq_relay PUBLIC ${CMAKE_SOURCE_DIR}/server)
target_link_libraries(pq_relay PUBLIC pq_crypto protocol SQLite::SQLite3 Threads::Threads ${CMAKE_DL_LIBS})
pq_warnings(pq_relay)

# --- Relay server: protocol v3 mailboxes plus the v2 file transfer ---
add_executable(pq-server server/main.cpp)
target_link_libraries(pq-server PRIVATE pq_relay pq_crypto protocol Threads::Threads OpenSSL::Crypto)
pq_warnings(pq-server)

# --- Client core (everything except the GUI) ---
add_library(pq_core STATIC
    client/key_store.cpp
    client/transfer_engine.cpp
    client/sharing.cpp
    client/identity_bundle.cpp
    client/relay_client.cpp
    client/message_record.cpp
    client/envelope.cpp
    client/history_store.cpp
    client/messaging_engine.cpp
)
target_include_directories(pq_core PUBLIC ${CMAKE_SOURCE_DIR}/client)
target_link_libraries(pq_core PUBLIC pq_crypto protocol Threads::Threads OpenSSL::Crypto SQLite::SQLite3)
pq_warnings(pq_core)

# --- Command-line check for a relay (no Qt) ---
add_executable(pq-relay-check tools/relay_check.cpp)
target_link_libraries(pq-relay-check PRIVATE pq_core)
pq_warnings(pq-relay-check)

# --- Qt GUI client ---
if(PQ_BUILD_CLIENT)
    set(CMAKE_AUTOMOC ON)
    find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets)

    add_executable(pq-client
        client/main.cpp
        client/main_window.h
        client/main_window.cpp
        client/key_dialogs.cpp
        client/keychain.cpp
        client/chat_widget.h
        client/chat_widget.cpp
    )
    target_link_libraries(pq-client PRIVATE pq_core Qt6::Core Qt6::Gui Qt6::Widgets)
    pq_warnings(pq-client)

    # Optional: remember the key passphrase in the OS keychain via QtKeychain
    # (https://github.com/frankosterfeld/qtkeychain, built with -DBUILD_WITH_QT6=ON).
    find_package(Qt6 QUIET OPTIONAL_COMPONENTS DBus)  # QtKeychain's Linux backend needs it
    find_package(Qt6Keychain CONFIG QUIET)
    set(PQ_KEYCHAIN_TARGET "")
    if(TARGET Qt6Keychain::Qt6Keychain)
        set(PQ_KEYCHAIN_TARGET Qt6Keychain::Qt6Keychain)
    elseif(TARGET qt6keychain)
        set(PQ_KEYCHAIN_TARGET qt6keychain)
    elseif(QTKEYCHAIN_LIBRARIES)
        set(PQ_KEYCHAIN_TARGET ${QTKEYCHAIN_LIBRARIES})
    endif()

    if(PQ_KEYCHAIN_TARGET)
        target_link_libraries(pq-client PRIVATE ${PQ_KEYCHAIN_TARGET})
        target_compile_definitions(pq-client PRIVATE PQ_HAVE_KEYCHAIN)
        if(QTKEYCHAIN_INCLUDE_DIRS)
            target_include_directories(pq-client PRIVATE ${QTKEYCHAIN_INCLUDE_DIRS})
        endif()
        message(STATUS "OS keychain support: ON (${PQ_KEYCHAIN_TARGET})")
    elseif(PQ_REQUIRE_KEYCHAIN)
        message(FATAL_ERROR "QtKeychain for Qt 6 was not found, but PQ_REQUIRE_KEYCHAIN is ON. "
                            "Install it or add its install prefix to CMAKE_PREFIX_PATH.")
    else()
        message(STATUS "OS keychain support: OFF (the passphrase will be asked for at every start; "
                       "install QtKeychain for Qt 6 to enable remembering it)")
    endif()
endif()

# --- Tests ---
if(PQ_BUILD_TESTS)
    enable_testing()

    add_executable(pq-test-sharing tests/test_sharing.cpp)
    target_link_libraries(pq-test-sharing PRIVATE pq_core)
    pq_warnings(pq-test-sharing)
    add_test(NAME sharing COMMAND pq-test-sharing)

    add_executable(pq-test-chat-formats tests/test_chat_formats.cpp)
    target_link_libraries(pq-test-chat-formats PRIVATE pq_core)
    pq_warnings(pq-test-chat-formats)
    add_test(NAME chat_formats COMMAND pq-test-chat-formats)

    add_executable(pq-test-relay-protocol tests/test_relay_protocol.cpp)
    target_link_libraries(pq-test-relay-protocol PRIVATE pq_core)
    pq_warnings(pq-test-relay-protocol)
    add_test(NAME relay_protocol COMMAND pq-test-relay-protocol)

    # These switch $HOME, use temporary directories or start processes (fork/exec), so POSIX only.
    if(NOT WIN32)
        add_executable(pq-test-keys tests/test_keys.cpp)
        target_link_libraries(pq-test-keys PRIVATE pq_core)
        pq_warnings(pq-test-keys)
        add_test(NAME keys COMMAND pq-test-keys)

        add_executable(pq-test-contacts tests/test_contacts.cpp)
        target_link_libraries(pq-test-contacts PRIVATE pq_core)
        pq_warnings(pq-test-contacts)
        add_test(NAME contacts COMMAND pq-test-contacts)

        add_executable(pq-test-history tests/test_history.cpp)
        target_link_libraries(pq-test-history PRIVATE pq_core)
        pq_warnings(pq-test-history)
        add_test(NAME history COMMAND pq-test-history)

        add_executable(pq-test-relay-store tests/test_relay_store.cpp)
        target_link_libraries(pq-test-relay-store PRIVATE pq_relay)
        pq_warnings(pq-test-relay-store)
        add_test(NAME relay_store COMMAND pq-test-relay-store)

        add_executable(pq-test-e2e tests/test_e2e.cpp)
        target_link_libraries(pq-test-e2e PRIVATE pq_core)
        pq_warnings(pq-test-e2e)
        add_dependencies(pq-test-e2e pq-server)
        add_test(NAME e2e COMMAND pq-test-e2e $<TARGET_FILE:pq-server>)
        set_tests_properties(e2e PROPERTIES TIMEOUT 120)

        add_executable(pq-test-chat tests/test_chat.cpp)
        target_link_libraries(pq-test-chat PRIVATE pq_core)
        pq_warnings(pq-test-chat)
        add_dependencies(pq-test-chat pq-server)
        add_test(NAME chat COMMAND pq-test-chat $<TARGET_FILE:pq-server>)
        set_tests_properties(chat PROPERTIES TIMEOUT 300)

        add_executable(pq-test-relay tests/test_relay.cpp)
        target_link_libraries(pq-test-relay PRIVATE pq_core)
        pq_warnings(pq-test-relay)
        add_dependencies(pq-test-relay pq-server)
        add_test(NAME relay COMMAND pq-test-relay $<TARGET_FILE:pq-server>)
        set_tests_properties(relay PROPERTIES TIMEOUT 240)

        add_executable(pq-test-relay-setup tests/test_relay_setup.cpp)
        target_link_libraries(pq-test-relay-setup PRIVATE pq_relay)
        pq_warnings(pq-test-relay-setup)
        add_dependencies(pq-test-relay-setup pq-server)
        add_test(NAME relay_setup COMMAND pq-test-relay-setup $<TARGET_FILE:pq-server>)
        set_tests_properties(relay_setup PROPERTIES TIMEOUT 60)

        add_executable(pq-test-group tests/test_group.cpp)
        target_link_libraries(pq-test-group PRIVATE pq_core)
        pq_warnings(pq-test-group)
        add_dependencies(pq-test-group pq-server)
        add_test(NAME group COMMAND pq-test-group $<TARGET_FILE:pq-server>)
        set_tests_properties(group PROPERTIES TIMEOUT 600)
    endif()
endif()
