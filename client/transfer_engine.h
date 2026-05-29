#pragma once

#include <string>
#include <functional>
#include <cstdint>
#include <atomic>
#include <vector>
#include "messages.h"

class TransferEngine {
public:
    TransferEngine();

    void upload_file(const std::string& filepath,
                     const std::string& server_addr,
                     uint16_t server_port,
                     const std::string& recipient);

    void download_file(const std::string& transfer_id,
                       const std::string& server_addr,
                       uint16_t server_port,
                       const std::string& output_dir);

    void cancel();

    std::function<void(double percent)> on_progress;
    std::function<void(const std::string& msg)> on_status;
    std::function<void(const std::string& error)> on_error;
    std::function<void(const std::string& filepath)> on_complete;
    std::function<void(const std::string& transfer_id)> on_transfer_id;

private:
    std::atomic<bool> cancel_flag_{false};

    int connect_to_server(const std::string& addr, uint16_t port);

    static std::vector<uint8_t> compute_chunk_nonce(
        const std::vector<uint8_t>& base_nonce, uint32_t chunk_index);

    static std::vector<uint8_t> build_signing_payload(const FileHeader& header);
};