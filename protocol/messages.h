#pragma once

#include <cstdint>
#include <string>
#include <vector>

// Every message on the wire: [4 bytes: total_length] [1 byte: type] [payload...]
enum class MessageType : uint8_t {
    UPLOAD_REQUEST    = 0x01,  // sender → server: "I want to send a file"
    UPLOAD_CHUNK      = 0x02,  // sender → server: a chunk of file data
    UPLOAD_DONE       = 0x03,  // sender → server: "all chunks sent"
    DOWNLOAD_REQUEST  = 0x04,  // receiver → server: "give me file X"
    DOWNLOAD_CHUNK    = 0x05,  // server → receiver: a chunk of file data
    DOWNLOAD_DONE     = 0x06,  // server → receiver: "all chunks sent"
    LIST_FILES        = 0x07,  // receiver → server: "what files are available?"
    FILE_LIST         = 0x08,  // server → receiver: list of available files
    ACK               = 0xFF,  // generic acknowledgment
};

struct FileHeader {
    std::string filename;
    uint64_t file_size = 0;
    uint32_t chunk_size = 65536;
    uint32_t total_chunks = 0;
    std::string sender_id;

    // Crypto placeholders — unused for now, reserved for Phase 7
    std::vector<uint8_t> kem_ciphertext;
    std::vector<uint8_t> signature;
    std::vector<uint8_t> nonce;
    bool encrypted = false;
};

struct FileChunk {
    uint32_t chunk_index = 0;
    std::vector<uint8_t> data;
};

struct TransferInfo {
    std::string transfer_id;
    std::string filename;
    uint64_t file_size = 0;
    std::string sender_id;
};