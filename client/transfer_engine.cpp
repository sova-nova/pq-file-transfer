#include "transfer_engine.h"

void TransferEngine::upload_file(const std::string& filepath,
                                 const std::string& server_addr,
                                 uint16_t server_port) {
    // TODO: Phase 4
    if (on_status) on_status("Upload not yet implemented");
}

void TransferEngine::download_file(const std::string& transfer_id,
                                   const std::string& server_addr,
                                   uint16_t server_port,
                                   const std::string& output_dir) {
    // TODO: Phase 4
    if (on_status) on_status("Download not yet implemented");
}