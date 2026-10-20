#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// --- Protocol constants ---

// Every serialized FileHeader starts with this magic and version, so mismatched
// clients and servers fail with a clear error instead of misreading each other.
constexpr uint32_t PROTOCOL_MAGIC   = 0x50514654;  // "PQFT"
constexpr uint32_t PROTOCOL_VERSION = 2;

constexpr uint32_t DEFAULT_CHUNK_SIZE = 64 * 1024;
constexpr uint32_t MIN_CHUNK_SIZE     = 4 * 1024;
constexpr uint32_t MAX_CHUNK_SIZE     = 1024 * 1024;

constexpr size_t AEAD_TAG_SIZE = 16;  // AES-GCM tag
constexpr size_t NONCE_SIZE    = 12;  // AES-GCM nonce

constexpr uint64_t MAX_FILE_SIZE = 16ull * 1024 * 1024 * 1024;  // 16 GiB

constexpr size_t MAX_KEM_CIPHERTEXT_SIZE  = 4096;
constexpr size_t MAX_SEALED_METADATA_SIZE = 16 * 1024;
constexpr size_t MAX_FILENAME_BYTES       = 255;
constexpr size_t MAX_FINGERPRINT_CHARS    = 128;
constexpr size_t MAX_SIGNATURE_SIZE       = 8192;

// Upper bounds on a single wire-message payload, by message kind.
constexpr uint32_t MAX_HEADER_MESSAGE  = 64 * 1024;
constexpr uint32_t MAX_CONTROL_MESSAGE = 4 * 1024;
constexpr uint32_t MAX_CHUNK_MESSAGE   = MAX_CHUNK_SIZE + static_cast<uint32_t>(AEAD_TAG_SIZE) + 64;

// Transfer IDs are 128-bit random values, hex encoded. Knowing the ID is what
// authorizes a download, so it has to be unguessable.
constexpr size_t TRANSFER_ID_BYTES   = 16;
constexpr size_t TRANSFER_ID_HEX_LEN = TRANSFER_ID_BYTES * 2;

// Every message on the wire: [4 bytes: payload length] [1 byte: type] [payload...]
enum class MessageType : uint8_t {
    UPLOAD_REQUEST   = 0x01,  // sender → server: serialized FileHeader
    UPLOAD_CHUNK     = 0x02,  // sender → server: FileChunk
    UPLOAD_DONE      = 0x03,  // sender → server: all chunks sent
    DOWNLOAD_REQUEST = 0x04,  // receiver → server: transfer ID
    DOWNLOAD_CHUNK   = 0x05,  // server → receiver: FileChunk
    DOWNLOAD_DONE    = 0x06,  // server → receiver: all chunks sent
    // 0x07 / 0x08 were LIST_FILES / FILE_LIST in v1. Removed: listing every
    // transfer let anyone discover and download (and so delete) any of them.
    DOWNLOAD_HEADER  = 0x09,  // server → receiver: the stored FileHeader

    // --- Protocol v3: mailbox relay (see relay_protocol.h). A relay tells v3 from v2 by the
    // first message: RELAY_HELLO starts a v3 session, anything else is handled as v2. ---
    RELAY_HELLO        = 0x20,  // client → relay: version + client nonce
    RELAY_HELLO_REPLY  = 0x21,  // relay → client: relay key, signature, auth challenge
    RELAY_REGISTER     = 0x22,  // client → relay: create a mailbox (invite + proof of key)
    RELAY_REGISTER_OK  = 0x23,
    RELAY_AUTH         = 0x24,  // client → relay: sign the challenge for a mailbox
    RELAY_AUTH_OK      = 0x25,
    RELAY_DEPOSIT      = 0x26,  // anyone with a send token → relay: store a sealed envelope
    RELAY_DEPOSIT_OK   = 0x27,  // relay → depositor: envelope ID
    RELAY_COLLECT      = 0x28,  // mailbox owner → relay: start delivering envelopes
    RELAY_ENVELOPE     = 0x29,  // relay → owner: one stored envelope
    RELAY_COLLECT_END  = 0x2A,  // relay → owner: the backlog has been delivered
    RELAY_ACK          = 0x2B,  // owner → relay: these envelopes are stored safely, delete them
    RELAY_ACK_OK       = 0x2C,
    RELAY_TOKEN_ADD    = 0x2D,  // owner → relay: accept this send token (hash)
    RELAY_TOKEN_REVOKE = 0x2E,  // owner → relay: stop accepting this send token (hash)
    RELAY_TOKEN_OK     = 0x2F,
    RELAY_INVITE_CREATE = 0x32,  // mailbox owner → relay: make me one single-use invite for a friend
    RELAY_INVITE_OK     = 0x33,  // relay → owner: the invite (INVITE_BYTES)
    RELAY_INVITE_LIST   = 0x34,  // mailbox owner → relay: show the invites I made (empty payload)
    RELAY_INVITE_LIST_OK = 0x35, // relay → owner: relay::InviteStatus
    RELAY_INVITE_CANCEL = 0x36,  // mailbox owner → relay: cancel one of my unused invites (its hash)
    RELAY_INVITE_CANCEL_OK = 0x37,
    // --- Chat archives (M4): an encrypted, hash-chained copy of a chat that its members can append to ---
    ARCHIVE_CREATE     = 0x40,  // mailbox owner → relay: make an archive for N members (hashes of their join tokens)
    ARCHIVE_CREATE_OK  = 0x41,
    ARCHIVE_JOIN       = 0x42,  // a member with a join token → relay: register this chat's public key (no mailbox needed)
    ARCHIVE_JOIN_OK    = 0x43,
    ARCHIVE_AUTH       = 0x44,  // a registered member → relay: sign the challenge for one archive
    ARCHIVE_AUTH_OK    = 0x45,
    ARCHIVE_APPEND     = 0x46,  // member → relay: add an entry, naming the head it extends
    ARCHIVE_APPEND_OK  = 0x47,  // relay → member: the new head
    ARCHIVE_STALE      = 0x48,  // relay → member: someone else got in first; here is the current head
    ARCHIVE_FETCH      = 0x49,  // member → relay: send entries from a number onwards
    ARCHIVE_ENTRY      = 0x4A,  // relay → member: one entry
    ARCHIVE_FETCH_END  = 0x4B,  // relay → member: that was all; here is the head
    RELAY_PING         = 0x30,
    RELAY_PONG         = 0x31,
    ERROR_MSG        = 0xFE,  // either direction: UTF-8 error text
    ACK              = 0xFF,  // generic acknowledgment (payload depends on context)
};

// The public part of a transfer: the only thing the relay server can read.
// Filename, sender identity and signature are inside sealed_metadata.
struct FileHeader {
    uint64_t file_size = 0;
    uint32_t chunk_size = DEFAULT_CHUNK_SIZE;
    uint32_t total_chunks = 0;
    std::vector<uint8_t> kem_ciphertext;   // ML-KEM-768 encapsulation to the recipient
    std::vector<uint8_t> nonce;            // random 12-byte base nonce
    std::vector<uint8_t> sealed_metadata;  // AES-GCM(FileMetadata)
};

// Encrypted inside FileHeader::sealed_metadata; readable only by the recipient.
struct FileMetadata {
    std::string filename;
    std::string sender_fingerprint;   // SHA-256 of the sender's ML-DSA public key, hex
    std::vector<uint8_t> signature;   // ML-DSA-65 over the public header + these fields
};

struct FileChunk {
    uint32_t chunk_index = 0;
    std::vector<uint8_t> data;  // ciphertext || 16-byte GCM tag
};

// Number of chunks a file of `file_size` is split into. Empty files still
// carry one (empty) chunk so the receiver gets an authenticated end marker.
inline uint32_t expected_total_chunks(uint64_t file_size, uint32_t chunk_size) {
    if (chunk_size == 0) return 0;
    if (file_size == 0) return 1;
    return static_cast<uint32_t>((file_size + chunk_size - 1) / chunk_size);
}
