#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>

#include "key_store.h"
#include "platform.h"

// Runs one upload or download at a time on the calling (worker) thread and
// reports progress through the callbacks. Never throws: every failure is
// reported through on_error.
class TransferEngine {
public:
    TransferEngine() = default;

    // Encrypts `filepath` (UTF-8) for `recipient`, signs it with this user's
    // ML-DSA key and uploads it to the relay.
    void upload_file(const std::string& filepath,
                     const std::string& server_host,
                     uint16_t server_port,
                     const KeyStore::Contact& recipient);

    // Downloads a transfer, verifies the sender against the contact list,
    // decrypts it into `output_dir` (UTF-8), then tells the relay to delete it.
    void download_file(const std::string& transfer_id,
                       const std::string& server_host,
                       uint16_t server_port,
                       const std::string& output_dir);

    // Thread-safe. Aborts the running transfer promptly (closes its socket).
    void cancel();

    std::function<void(double fraction)> on_progress;
    std::function<void(const std::string& msg)> on_status;
    std::function<void(const std::string& error)> on_error;
    std::function<void(const std::string& filepath)> on_complete;
    std::function<void(const std::string& transfer_id)> on_transfer_id;

private:
    std::atomic<bool> cancel_flag_{false};
    std::mutex socket_mutex_;
    socket_t active_socket_ = INVALID_SOCKET_VAL;

    void upload_impl(const std::string& filepath, const std::string& host, uint16_t port,
                     const KeyStore::Contact& recipient);
    void download_impl(const std::string& transfer_id, const std::string& host, uint16_t port,
                       const std::string& output_dir);

    socket_t connect_to_server(const std::string& host, uint16_t port);
    void release_socket(socket_t sock);
    void check_cancelled() const;

    void status(const std::string& msg);
    void progress(double fraction);
};
