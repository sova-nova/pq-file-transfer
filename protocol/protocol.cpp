#include "protocol.h"
#include "platform.h"
#include <cstring>
#ifndef _WIN32
#include <unistd.h>
#endif

// --- Low-level write helpers ---

void write_u32(std::vector<uint8_t>& buf, uint32_t val) {
    uint32_t net_val = htonl(val);
    const uint8_t* p = reinterpret_cast<const uint8_t*>(&net_val);
    buf.insert(buf.end(), p, p + 4);
}

void write_u64(std::vector<uint8_t>& buf, uint64_t val) {
    write_u32(buf, static_cast<uint32_t>(val >> 32));
    write_u32(buf, static_cast<uint32_t>(val & 0xFFFFFFFF));
}

void write_bytes(std::vector<uint8_t>& buf, const uint8_t* data, size_t len) {
    buf.insert(buf.end(), data, data + len);
}

void write_string(std::vector<uint8_t>& buf, const std::string& s) {
    write_u32(buf, static_cast<uint32_t>(s.size()));
    write_bytes(buf, reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

// --- Low-level read helpers ---

std::optional<uint32_t> read_u32(const uint8_t* data, size_t len, size_t& offset) {
    if (offset + 4 > len) return std::nullopt;
    uint32_t net_val;
    std::memcpy(&net_val, data + offset, 4);
    offset += 4;
    return ntohl(net_val);
}

std::optional<uint64_t> read_u64(const uint8_t* data, size_t len, size_t& offset) {
    auto high = read_u32(data, len, offset);
    if (!high) return std::nullopt;
    auto low = read_u32(data, len, offset);
    if (!low) return std::nullopt;
    return (static_cast<uint64_t>(*high) << 32) | static_cast<uint64_t>(*low);
}

std::optional<std::vector<uint8_t>> read_bytes(const uint8_t* data, size_t len, size_t& offset, size_t count) {
    if (offset + count > len) return std::nullopt;
    std::vector<uint8_t> result(data + offset, data + offset + count);
    offset += count;
    return result;
}

std::optional<std::string> read_string(const uint8_t* data, size_t len, size_t& offset) {
    auto str_len = read_u32(data, len, offset);
    if (!str_len) return std::nullopt;
    if (offset + *str_len > len) return std::nullopt;
    std::string result(reinterpret_cast<const char*>(data + offset), *str_len);
    offset += *str_len;
    return result;
}

// --- Serialization ---

std::vector<uint8_t> serialize_file_header(const FileHeader& header) {
    std::vector<uint8_t> buf;
    write_string(buf, header.filename);
    write_u64(buf, header.file_size);
    write_u32(buf, header.chunk_size);
    write_u32(buf, header.total_chunks);
    write_string(buf, header.sender_id);
    write_u32(buf, header.encrypted ? 1 : 0);
    write_u32(buf, static_cast<uint32_t>(header.kem_ciphertext.size()));
    write_bytes(buf, header.kem_ciphertext.data(), header.kem_ciphertext.size());
    write_u32(buf, static_cast<uint32_t>(header.nonce.size()));
    write_bytes(buf, header.nonce.data(), header.nonce.size());
    write_u32(buf, static_cast<uint32_t>(header.signature.size()));
    write_bytes(buf, header.signature.data(), header.signature.size());
    return buf;
}

std::vector<uint8_t> serialize_file_chunk(const FileChunk& chunk) {
    std::vector<uint8_t> buf;
    write_u32(buf, chunk.chunk_index);
    write_u32(buf, static_cast<uint32_t>(chunk.data.size()));
    write_bytes(buf, chunk.data.data(), chunk.data.size());
    return buf;
}

std::vector<uint8_t> serialize_transfer_info(const TransferInfo& info) {
    std::vector<uint8_t> buf;
    write_string(buf, info.transfer_id);
    write_string(buf, info.filename);
    write_u64(buf, info.file_size);
    write_string(buf, info.sender_id);
    return buf;
}

std::vector<uint8_t> serialize_file_list(const std::vector<TransferInfo>& files) {
    std::vector<uint8_t> buf;
    write_u32(buf, static_cast<uint32_t>(files.size()));
    for (const auto& f : files) {
        auto serialized = serialize_transfer_info(f);
        buf.insert(buf.end(), serialized.begin(), serialized.end());
    }
    return buf;
}

// --- Deserialization ---

std::optional<FileHeader> deserialize_file_header(const uint8_t* data, size_t len) {
    size_t offset = 0;
    FileHeader header;

    auto filename = read_string(data, len, offset);
    if (!filename) return std::nullopt;
    header.filename = *filename;

    auto file_size = read_u64(data, len, offset);
    if (!file_size) return std::nullopt;
    header.file_size = *file_size;

    auto chunk_size = read_u32(data, len, offset);
    if (!chunk_size) return std::nullopt;
    header.chunk_size = *chunk_size;

    auto total_chunks = read_u32(data, len, offset);
    if (!total_chunks) return std::nullopt;
    header.total_chunks = *total_chunks;

    auto sender_id = read_string(data, len, offset);
    if (!sender_id) return std::nullopt;
    header.sender_id = *sender_id;

    auto encrypted_flag = read_u32(data, len, offset);
    if (!encrypted_flag) return std::nullopt;
    header.encrypted = (*encrypted_flag != 0);

    auto kem_ct_len = read_u32(data, len, offset);
    if (!kem_ct_len) return std::nullopt;
    auto kem_ct = read_bytes(data, len, offset, *kem_ct_len);
    if (!kem_ct) return std::nullopt;
    header.kem_ciphertext = std::move(*kem_ct);

    auto nonce_len = read_u32(data, len, offset);
    if (!nonce_len) return std::nullopt;
    auto nonce = read_bytes(data, len, offset, *nonce_len);
    if (!nonce) return std::nullopt;
    header.nonce = std::move(*nonce);

    auto sig_len = read_u32(data, len, offset);
    if (!sig_len) return std::nullopt;
    auto sig = read_bytes(data, len, offset, *sig_len);
    if (!sig) return std::nullopt;
    header.signature = std::move(*sig);

    return header;
}

std::optional<FileChunk> deserialize_file_chunk(const uint8_t* data, size_t len) {
    size_t offset = 0;
    FileChunk chunk;

    auto chunk_index = read_u32(data, len, offset);
    if (!chunk_index) return std::nullopt;
    chunk.chunk_index = *chunk_index;

    auto data_len = read_u32(data, len, offset);
    if (!data_len) return std::nullopt;
    auto chunk_data = read_bytes(data, len, offset, *data_len);
    if (!chunk_data) return std::nullopt;
    chunk.data = std::move(*chunk_data);

    return chunk;
}

std::optional<TransferInfoResult> deserialize_transfer_info(const uint8_t* data, size_t len) {
    size_t offset = 0;
    TransferInfo info;

    auto transfer_id = read_string(data, len, offset);
    if (!transfer_id) return std::nullopt;
    info.transfer_id = *transfer_id;

    auto filename = read_string(data, len, offset);
    if (!filename) return std::nullopt;
    info.filename = *filename;

    auto file_size = read_u64(data, len, offset);
    if (!file_size) return std::nullopt;
    info.file_size = *file_size;

    auto sender_id = read_string(data, len, offset);
    if (!sender_id) return std::nullopt;
    info.sender_id = *sender_id;

    return TransferInfoResult{info, offset};
}

std::optional<std::vector<TransferInfo>> deserialize_file_list(const uint8_t* data, size_t len) {
    size_t offset = 0;

    auto count = read_u32(data, len, offset);
    if (!count) return std::nullopt;

    std::vector<TransferInfo> result;
    for (uint32_t i = 0; i < *count; i++) {
        if (offset >= len) return std::nullopt;
        auto info_result = deserialize_transfer_info(data + offset, len - offset);
        if (!info_result) return std::nullopt;
        offset += info_result->bytes_consumed;
        result.push_back(std::move(info_result->info));
    }

    return result;
}

// --- Wire Message ---

std::vector<uint8_t> serialize_wire_message(MessageType type, const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> buf;
    write_u32(buf, static_cast<uint32_t>(payload.size()));
    buf.push_back(static_cast<uint8_t>(type));
    buf.insert(buf.end(), payload.begin(), payload.end());
    return buf;
}

// --- Socket I/O ---

bool send_exact(int sockfd, const uint8_t* data, size_t len) {
    size_t total_sent = 0;
    while (total_sent < len) {
        ssize_t sent = ::send(sockfd, reinterpret_cast<const char*>(data + total_sent),
                               len - total_sent, SEND_FLAGS);
        if (sent <= 0) return false;
        total_sent += static_cast<size_t>(sent);
    }
    return true;
}

bool recv_exact(int sockfd, uint8_t* buffer, size_t len) {
    size_t total_recv = 0;
    while (total_recv < len) {
        ssize_t recvd = ::recv(sockfd, reinterpret_cast<char*>(buffer + total_recv),
                                len - total_recv, 0);
        if (recvd <= 0) return false;
        total_recv += static_cast<size_t>(recvd);
    }
    return true;
}

bool send_message(int sockfd, MessageType type, const std::vector<uint8_t>& payload) {
    auto wire = serialize_wire_message(type, payload);
    return send_exact(sockfd, wire.data(), wire.size());
}

std::optional<WireMessage> recv_message(int sockfd) {
    uint8_t len_buf[4];
    if (!recv_exact(sockfd, len_buf, 4)) return std::nullopt;

    uint32_t net_len;
    std::memcpy(&net_len, len_buf, 4);
    uint32_t payload_len = ntohl(net_len);

    if (payload_len > 256 * 1024 * 1024) return std::nullopt;

    uint8_t type_byte;
    if (!recv_exact(sockfd, &type_byte, 1)) return std::nullopt;
    MessageType type = static_cast<MessageType>(type_byte);

    std::vector<uint8_t> payload(payload_len);
    if (payload_len > 0) {
        if (!recv_exact(sockfd, payload.data(), payload_len)) return std::nullopt;
    }

    return WireMessage{type, std::move(payload)};
}