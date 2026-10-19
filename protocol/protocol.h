#pragma once

#include "messages.h"
#include "platform.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// --- File header ---

std::vector<uint8_t> serialize_file_header(const FileHeader& header);

// The header without sealed_metadata. These bytes are hashed into the key
// derivation salt and covered by the sender's signature, which binds every
// public field to the encrypted content.
std::vector<uint8_t> serialize_header_public_fields(const FileHeader& header);

// Returns std::nullopt on malformed input or a magic/version mismatch.
std::optional<FileHeader> deserialize_file_header(const uint8_t* data, size_t len);

// Structural checks shared by server and client. Returns an empty string if the
// header is acceptable, otherwise a human-readable reason.
std::string validate_file_header(const FileHeader& header);

// Plaintext size of chunk `index` (the last chunk may be short; empty files have
// a single zero-length chunk).
uint64_t expected_chunk_plaintext_size(const FileHeader& header, uint32_t index);

// --- Sealed metadata ---

std::vector<uint8_t> serialize_file_metadata(const FileMetadata& meta);
std::optional<FileMetadata> deserialize_file_metadata(const uint8_t* data, size_t len);

// --- Chunks ---

std::vector<uint8_t> serialize_file_chunk(const FileChunk& chunk);
std::optional<FileChunk> deserialize_file_chunk(const uint8_t* data, size_t len);

// --- Hex helpers ---

std::string bytes_to_hex(const uint8_t* data, size_t len);
inline std::string bytes_to_hex(const std::vector<uint8_t>& v) { return bytes_to_hex(v.data(), v.size()); }

// True if `s` is exactly `expected_len` lowercase hex characters.
bool is_lower_hex(const std::string& s, size_t expected_len);

// --- Wire messages ---

struct WireMessage {
    MessageType type;
    std::vector<uint8_t> payload;
};

std::vector<uint8_t> serialize_wire_message(MessageType type, const std::vector<uint8_t>& payload);

// --- Socket I/O ---

// Send/receive exactly `len` bytes. Return false on error, timeout or disconnect.
bool send_exact(socket_t sock, const uint8_t* data, size_t len);
bool recv_exact(socket_t sock, uint8_t* buffer, size_t len);

bool send_message(socket_t sock, MessageType type, const std::vector<uint8_t>& payload);
bool send_text_message(socket_t sock, MessageType type, const std::string& text);

// Receives one message. Returns std::nullopt on error/disconnect, or if the
// declared payload is larger than `max_payload` (protects against memory DoS).
std::optional<WireMessage> recv_message(socket_t sock, uint32_t max_payload);

// --- Low-level helpers (exposed for testing and for building signed payloads) ---

void write_u32(std::vector<uint8_t>& buf, uint32_t val);
void write_u64(std::vector<uint8_t>& buf, uint64_t val);
void write_bytes(std::vector<uint8_t>& buf, const uint8_t* data, size_t len);
void write_blob(std::vector<uint8_t>& buf, const std::vector<uint8_t>& blob);  // u32 length + bytes
void write_string(std::vector<uint8_t>& buf, const std::string& s);             // u32 length + bytes

std::optional<uint32_t> read_u32(const uint8_t* data, size_t len, size_t& offset);
std::optional<uint64_t> read_u64(const uint8_t* data, size_t len, size_t& offset);
std::optional<std::vector<uint8_t>> read_bytes(const uint8_t* data, size_t len, size_t& offset, size_t count);
std::optional<std::vector<uint8_t>> read_blob(const uint8_t* data, size_t len, size_t& offset, size_t max_len);
std::optional<std::string> read_string(const uint8_t* data, size_t len, size_t& offset, size_t max_len);
