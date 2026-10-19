#include "protocol.h"

#include <algorithm>
#include <cerrno>
#include <cstring>

// --- Low-level write helpers (big-endian) ---

void write_u32(std::vector<uint8_t>& buf, uint32_t val) {
    buf.push_back(static_cast<uint8_t>(val >> 24));
    buf.push_back(static_cast<uint8_t>(val >> 16));
    buf.push_back(static_cast<uint8_t>(val >> 8));
    buf.push_back(static_cast<uint8_t>(val));
}

void write_u64(std::vector<uint8_t>& buf, uint64_t val) {
    write_u32(buf, static_cast<uint32_t>(val >> 32));
    write_u32(buf, static_cast<uint32_t>(val & 0xFFFFFFFFu));
}

void write_bytes(std::vector<uint8_t>& buf, const uint8_t* data, size_t len) {
    if (len > 0) buf.insert(buf.end(), data, data + len);
}

void write_blob(std::vector<uint8_t>& buf, const std::vector<uint8_t>& blob) {
    write_u32(buf, static_cast<uint32_t>(blob.size()));
    write_bytes(buf, blob.data(), blob.size());
}

void write_string(std::vector<uint8_t>& buf, const std::string& s) {
    write_u32(buf, static_cast<uint32_t>(s.size()));
    write_bytes(buf, reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

// --- Low-level read helpers ---
// All bounds checks are written as `count <= len - offset` so they cannot overflow.

static bool has_bytes(size_t len, size_t offset, size_t count) {
    return offset <= len && count <= len - offset;
}

std::optional<uint32_t> read_u32(const uint8_t* data, size_t len, size_t& offset) {
    if (!has_bytes(len, offset, 4)) return std::nullopt;
    const uint8_t* p = data + offset;
    uint32_t val = (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
                   (static_cast<uint32_t>(p[2]) << 8)  |  static_cast<uint32_t>(p[3]);
    offset += 4;
    return val;
}

std::optional<uint64_t> read_u64(const uint8_t* data, size_t len, size_t& offset) {
    auto high = read_u32(data, len, offset);
    if (!high) return std::nullopt;
    auto low = read_u32(data, len, offset);
    if (!low) return std::nullopt;
    return (static_cast<uint64_t>(*high) << 32) | static_cast<uint64_t>(*low);
}

std::optional<std::vector<uint8_t>> read_bytes(const uint8_t* data, size_t len, size_t& offset, size_t count) {
    if (!has_bytes(len, offset, count)) return std::nullopt;
    std::vector<uint8_t> result(data + offset, data + offset + count);
    offset += count;
    return result;
}

std::optional<std::vector<uint8_t>> read_blob(const uint8_t* data, size_t len, size_t& offset, size_t max_len) {
    auto blob_len = read_u32(data, len, offset);
    if (!blob_len || *blob_len > max_len) return std::nullopt;
    return read_bytes(data, len, offset, *blob_len);
}

std::optional<std::string> read_string(const uint8_t* data, size_t len, size_t& offset, size_t max_len) {
    auto bytes = read_blob(data, len, offset, max_len);
    if (!bytes) return std::nullopt;
    return std::string(bytes->begin(), bytes->end());
}

// --- File header ---

static void write_public_fields(std::vector<uint8_t>& buf, const FileHeader& h) {
    write_u32(buf, PROTOCOL_MAGIC);
    write_u32(buf, PROTOCOL_VERSION);
    write_u64(buf, h.file_size);
    write_u32(buf, h.chunk_size);
    write_u32(buf, h.total_chunks);
    write_blob(buf, h.kem_ciphertext);
    write_blob(buf, h.nonce);
}

std::vector<uint8_t> serialize_header_public_fields(const FileHeader& header) {
    std::vector<uint8_t> buf;
    write_public_fields(buf, header);
    return buf;
}

std::vector<uint8_t> serialize_file_header(const FileHeader& header) {
    std::vector<uint8_t> buf;
    write_public_fields(buf, header);
    write_blob(buf, header.sealed_metadata);
    return buf;
}

std::optional<FileHeader> deserialize_file_header(const uint8_t* data, size_t len) {
    size_t offset = 0;
    FileHeader h;

    auto magic = read_u32(data, len, offset);
    if (!magic || *magic != PROTOCOL_MAGIC) return std::nullopt;
    auto version = read_u32(data, len, offset);
    if (!version || *version != PROTOCOL_VERSION) return std::nullopt;

    auto file_size = read_u64(data, len, offset);
    auto chunk_size = read_u32(data, len, offset);
    auto total_chunks = read_u32(data, len, offset);
    if (!file_size || !chunk_size || !total_chunks) return std::nullopt;
    h.file_size = *file_size;
    h.chunk_size = *chunk_size;
    h.total_chunks = *total_chunks;

    auto kem_ct = read_blob(data, len, offset, MAX_KEM_CIPHERTEXT_SIZE);
    if (!kem_ct) return std::nullopt;
    h.kem_ciphertext = std::move(*kem_ct);

    auto nonce = read_blob(data, len, offset, NONCE_SIZE);
    if (!nonce) return std::nullopt;
    h.nonce = std::move(*nonce);

    auto sealed = read_blob(data, len, offset, MAX_SEALED_METADATA_SIZE);
    if (!sealed) return std::nullopt;
    h.sealed_metadata = std::move(*sealed);

    if (offset != len) return std::nullopt;  // reject trailing garbage
    return h;
}

std::string validate_file_header(const FileHeader& h) {
    if (h.chunk_size < MIN_CHUNK_SIZE || h.chunk_size > MAX_CHUNK_SIZE)
        return "Invalid chunk size";
    if (h.file_size > MAX_FILE_SIZE)
        return "File is larger than the 16 GiB limit";
    if (h.total_chunks != expected_total_chunks(h.file_size, h.chunk_size))
        return "Chunk count does not match file size";
    if (h.nonce.size() != NONCE_SIZE)
        return "Invalid nonce";
    if (h.kem_ciphertext.empty())
        return "Missing key encapsulation";
    if (h.sealed_metadata.size() < AEAD_TAG_SIZE)
        return "Missing encrypted metadata";
    return {};
}

uint64_t expected_chunk_plaintext_size(const FileHeader& h, uint32_t index) {
    uint64_t start = static_cast<uint64_t>(index) * h.chunk_size;
    if (start >= h.file_size) return 0;
    return std::min<uint64_t>(h.chunk_size, h.file_size - start);
}

// --- Sealed metadata ---

std::vector<uint8_t> serialize_file_metadata(const FileMetadata& meta) {
    std::vector<uint8_t> buf;
    write_string(buf, meta.filename);
    write_string(buf, meta.sender_fingerprint);
    write_blob(buf, meta.signature);
    return buf;
}

std::optional<FileMetadata> deserialize_file_metadata(const uint8_t* data, size_t len) {
    size_t offset = 0;
    FileMetadata meta;

    auto filename = read_string(data, len, offset, MAX_FILENAME_BYTES);
    if (!filename) return std::nullopt;
    meta.filename = std::move(*filename);

    auto fp = read_string(data, len, offset, MAX_FINGERPRINT_CHARS);
    if (!fp) return std::nullopt;
    meta.sender_fingerprint = std::move(*fp);

    auto sig = read_blob(data, len, offset, MAX_SIGNATURE_SIZE);
    if (!sig) return std::nullopt;
    meta.signature = std::move(*sig);

    if (offset != len) return std::nullopt;
    return meta;
}

// --- Chunks ---

std::vector<uint8_t> serialize_file_chunk(const FileChunk& chunk) {
    std::vector<uint8_t> buf;
    buf.reserve(8 + chunk.data.size());
    write_u32(buf, chunk.chunk_index);
    write_blob(buf, chunk.data);
    return buf;
}

std::optional<FileChunk> deserialize_file_chunk(const uint8_t* data, size_t len) {
    size_t offset = 0;
    FileChunk chunk;

    auto index = read_u32(data, len, offset);
    if (!index) return std::nullopt;
    chunk.chunk_index = *index;

    auto bytes = read_blob(data, len, offset, MAX_CHUNK_SIZE + AEAD_TAG_SIZE);
    if (!bytes) return std::nullopt;
    chunk.data = std::move(*bytes);

    if (offset != len) return std::nullopt;
    return chunk;
}

// --- Hex helpers ---

std::string bytes_to_hex(const uint8_t* data, size_t len) {
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0x0F]);
    }
    return out;
}

std::optional<std::vector<uint8_t>> hex_to_bytes(const std::string& hex) {
    if (hex.size() % 2 != 0) return std::nullopt;
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = nibble(hex[i]), lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out.push_back(static_cast<uint8_t>(hi * 16 + lo));
    }
    return out;
}

bool is_lower_hex(const std::string& s, size_t expected_len) {
    if (s.size() != expected_len) return false;
    return std::all_of(s.begin(), s.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}

// --- Wire messages ---

std::vector<uint8_t> serialize_wire_message(MessageType type, const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> buf;
    buf.reserve(5 + payload.size());
    write_u32(buf, static_cast<uint32_t>(payload.size()));
    buf.push_back(static_cast<uint8_t>(type));
    write_bytes(buf, payload.data(), payload.size());
    return buf;
}

// --- Socket I/O ---

static bool interrupted() {
#ifdef _WIN32
    return false;
#else
    return errno == EINTR;
#endif
}

bool send_exact(socket_t sock, const uint8_t* data, size_t len) {
    size_t total = 0;
    while (total < len) {
        size_t piece = std::min<size_t>(len - total, 1u << 20);
        auto sent = ::send(sock, reinterpret_cast<const char*>(data + total),
                           static_cast<int>(piece), SEND_FLAGS);
        if (sent < 0 && interrupted()) continue;
        if (sent <= 0) return false;
        total += static_cast<size_t>(sent);
    }
    return true;
}

bool recv_exact(socket_t sock, uint8_t* buffer, size_t len) {
    size_t total = 0;
    while (total < len) {
        size_t piece = std::min<size_t>(len - total, 1u << 20);
        auto got = ::recv(sock, reinterpret_cast<char*>(buffer + total),
                          static_cast<int>(piece), 0);
        if (got < 0 && interrupted()) continue;
        if (got <= 0) return false;  // 0 = orderly shutdown by peer
        total += static_cast<size_t>(got);
    }
    return true;
}

bool send_message(socket_t sock, MessageType type, const std::vector<uint8_t>& payload) {
    if (payload.size() > 0xFFFFFFFFu) return false;
    // Send the 5-byte prefix separately so large payloads aren't copied.
    std::vector<uint8_t> prefix;
    write_u32(prefix, static_cast<uint32_t>(payload.size()));
    prefix.push_back(static_cast<uint8_t>(type));
    if (!send_exact(sock, prefix.data(), prefix.size())) return false;
    return payload.empty() || send_exact(sock, payload.data(), payload.size());
}

bool send_text_message(socket_t sock, MessageType type, const std::string& text) {
    return send_message(sock, type, std::vector<uint8_t>(text.begin(), text.end()));
}

std::optional<WireMessage> recv_message(socket_t sock, uint32_t max_payload) {
    uint8_t prefix[5];
    if (!recv_exact(sock, prefix, sizeof(prefix))) return std::nullopt;

    size_t offset = 0;
    auto payload_len = read_u32(prefix, sizeof(prefix), offset);
    if (!payload_len || *payload_len > max_payload) return std::nullopt;

    WireMessage msg;
    msg.type = static_cast<MessageType>(prefix[4]);
    msg.payload.resize(*payload_len);
    if (*payload_len > 0 && !recv_exact(sock, msg.payload.data(), *payload_len)) return std::nullopt;
    return msg;
}
