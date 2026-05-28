#pragma once

#include "messages.h"
#include <cstdint>
#include <vector>
#include <string>
#include <optional>
#include <sys/socket.h>

// --- Serialization ---

// Serialize a FileHeader into bytes
std::vector<uint8_t> serialize_file_header(const FileHeader& header);

// Serialize a FileChunk into bytes
std::vector<uint8_t> serialize_file_chunk(const FileChunk& chunk);

// Serialize a TransferInfo into bytes
std::vector<uint8_t> serialize_transfer_info(const TransferInfo& info);

// Serialize a list of TransferInfo into bytes (for FILE_LIST messages)
std::vector<uint8_t> serialize_file_list(const std::vector<TransferInfo>& files);

// --- Deserialization ---

// Deserialize a FileHeader from bytes. Returns std::nullopt on failure.
std::optional<FileHeader> deserialize_file_header(const uint8_t* data, size_t len);

// Deserialize a FileChunk from bytes. Returns std::nullopt on failure.
std::optional<FileChunk> deserialize_file_chunk(const uint8_t* data, size_t len);

// Deserialize a TransferInfo from bytes. Returns {info, bytes_consumed} or std::nullopt.
struct TransferInfoResult {
    TransferInfo info;
    size_t bytes_consumed;
};
std::optional<TransferInfoResult> deserialize_transfer_info(const uint8_t* data, size_t len);

// Deserialize a list of TransferInfo from bytes. Returns std::nullopt on failure.
std::optional<std::vector<TransferInfo>> deserialize_file_list(const uint8_t* data, size_t len);

// --- Wire Message ---

// A complete message read from the wire
struct WireMessage {
    MessageType type;
    std::vector<uint8_t> payload;
};

// Serialize a complete wire message (length + type + payload)
std::vector<uint8_t> serialize_wire_message(MessageType type, const std::vector<uint8_t>& payload);

// --- Socket I/O ---

// Send exactly `len` bytes over a socket. Returns true on success.
bool send_exact(int sockfd, const uint8_t* data, size_t len);

// Receive exactly `len` bytes from a socket. Returns true on success.
bool recv_exact(int sockfd, uint8_t* buffer, size_t len);

// Send a wire message over a socket. Returns true on success.
bool send_message(int sockfd, MessageType type, const std::vector<uint8_t>& payload);

// Receive a wire message from a socket. Returns std::nullopt on failure/disconnect.
std::optional<WireMessage> recv_message(int sockfd);

// --- Low-level helpers (used internally, but exposed for testing) ---

void write_u32(std::vector<uint8_t>& buf, uint32_t val);
void write_u64(std::vector<uint8_t>& buf, uint64_t val);
void write_bytes(std::vector<uint8_t>& buf, const uint8_t* data, size_t len);
void write_string(std::vector<uint8_t>& buf, const std::string& s);

std::optional<uint32_t> read_u32(const uint8_t* data, size_t len, size_t& offset);
std::optional<uint64_t> read_u64(const uint8_t* data, size_t len, size_t& offset);
std::optional<std::vector<uint8_t>> read_bytes(const uint8_t* data, size_t len, size_t& offset, size_t count);
std::optional<std::string> read_string(const uint8_t* data, size_t len, size_t& offset);