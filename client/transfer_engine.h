#pragma once

#include <string>
#include <functional>
#include <cstdint>

class TransferEngine {
public:
    TransferEngine() = default;

    void upload_file(const std::string& filepath,
                     const std::string& server_addr,
                     uint16_t server_port);

    void download_file(const std::string& transfer_id,
                       const std::string& server_addr,
                       uint16_t server_port,
                       const std::string& output_dir);

    // Callbacks — the GUI will hook into these
    std::function<void(double percent)> on_progress;
    std::function<void(const std::string& msg)> on_status;
    std::function<void(const std::string& error)> on_error;
    std::function<void(const std::string& filepath)> on_complete;
};