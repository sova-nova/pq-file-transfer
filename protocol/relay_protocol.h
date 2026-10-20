#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// Protocol v3 payloads: the messages a mailbox relay and its clients exchange, and the exact
// byte strings that get signed. Everything here is plain encoding: no cryptography, no
// sockets. Hashing and signing are done by the callers (CryptoEngine).
//
// A session starts with Hello / HelloReply. The relay proves it holds the key a client has
// pinned by signing the client's nonce. A mailbox owner then proves it holds the mailbox's
// access key by signing the relay's challenge (Auth). Anyone holding a send token can Deposit.
namespace relay {

constexpr uint32_t WIRE_VERSION = 3;

constexpr size_t NONCE_BYTES = 32;
constexpr size_t MAILBOX_ID_BYTES = 16;
constexpr size_t SEND_TOKEN_BYTES = 32;
constexpr size_t HASH_BYTES = 32;         // SHA-256: token hashes, relay IDs, invite hashes
constexpr size_t INVITE_BYTES = 16;
constexpr size_t ENVELOPE_ID_BYTES = 16;

constexpr size_t MAX_ENVELOPE_BYTES = 64 * 1024 + 2048;  // 64 KiB padded record plus headers
constexpr uint32_t MIN_TTL_SECONDS = 1;
constexpr uint32_t MAX_TTL_SECONDS = 30u * 24 * 3600;    // nothing is held longer than 30 days
constexpr size_t MAX_ACK_IDS = 256;
constexpr size_t MAX_KEY_BLOB = 8192;
constexpr uint32_t MAX_MESSAGE_PAYLOAD = static_cast<uint32_t>(MAX_ENVELOPE_BYTES) + 1024;

// --- Payloads ---

struct Hello {
    uint32_t version = WIRE_VERSION;
    std::vector<uint8_t> client_nonce;  // NONCE_BYTES
};

struct HelloReply {
    std::vector<uint8_t> relay_public_key;  // ML-DSA-65; its SHA-256 is the relay ID
    std::vector<uint8_t> signature;         // over hello_signing_input()
    std::vector<uint8_t> auth_challenge;    // NONCE_BYTES, used once by Auth
};

struct Register {
    std::vector<uint8_t> invite;            // INVITE_BYTES, single use
    std::vector<uint8_t> mailbox_id;        // MAILBOX_ID_BYTES, chosen by the client
    std::vector<uint8_t> access_public_key; // ML-DSA-65, made for this mailbox only
    std::vector<uint8_t> send_token_hash;   // SHA-256 of the first send token
    std::vector<uint8_t> signature;         // by the access key over register_signing_input()
};

struct Auth {
    std::vector<uint8_t> mailbox_id;
    std::vector<uint8_t> signature;         // by the access key over auth_signing_input()
};

struct Deposit {
    std::vector<uint8_t> mailbox_id;
    std::vector<uint8_t> send_token;        // the secret itself; the relay compares its hash
    std::vector<uint8_t> envelope;          // opaque to the relay
    uint32_t ttl_seconds = 0;               // how long the relay may keep it, from its own clock
};

struct StoredEnvelope {
    std::vector<uint8_t> id;                // ENVELOPE_ID_BYTES
    uint64_t deposited_at = 0;              // unix seconds, the relay's clock
    std::vector<uint8_t> token_hash;        // HASH_BYTES: which send token the depositor used (all zero for
                                            // envelopes stored before this was recorded). Lets the owner notice
                                            // a card that was passed on; it never identifies the sender.
    std::vector<uint8_t> envelope;
};

struct IdList {                              // Ack: envelope IDs; DepositOk: a single ID
    std::vector<std::vector<uint8_t>> ids;
};

struct HashOp {                              // TokenAdd / TokenRevoke
    std::vector<uint8_t> token_hash;
};

// What one member has done with their invites: the unused ones (identified by hash, since the relay
// never keeps the invite itself), and when the people they invited joined.
struct InviteStatus {
    uint32_t max_unused = 0;  // how many unused invites this relay lets a member hold at once
    uint32_t max_total = 0;   // how many people it lets a member invite in all
    struct Unused {
        std::vector<uint8_t> hash;  // HASH_BYTES: SHA-256 of the invite, which is how one is cancelled
        uint64_t expires_at = 0;
    };
    struct Joined {
        std::vector<uint8_t> mailbox_id;  // MAILBOX_ID_BYTES
        uint64_t joined_at = 0;
    };
    std::vector<Unused> unused;
    std::vector<Joined> joined;
};
constexpr size_t MAX_INVITE_STATUS_ENTRIES = 4096;

// --- Encoding. decode_* validate every length and reject trailing bytes. ---

std::vector<uint8_t> encode(const Hello&);
std::vector<uint8_t> encode(const HelloReply&);
std::vector<uint8_t> encode(const Register&);
std::vector<uint8_t> encode(const Auth&);
std::vector<uint8_t> encode(const Deposit&);
std::vector<uint8_t> encode(const StoredEnvelope&);
std::vector<uint8_t> encode(const IdList&);
std::vector<uint8_t> encode(const HashOp&);
std::vector<uint8_t> encode(const InviteStatus&);

std::optional<Hello> decode_hello(const std::vector<uint8_t>&);
std::optional<HelloReply> decode_hello_reply(const std::vector<uint8_t>&);
std::optional<Register> decode_register(const std::vector<uint8_t>&);
std::optional<Auth> decode_auth(const std::vector<uint8_t>&);
std::optional<Deposit> decode_deposit(const std::vector<uint8_t>&);
std::optional<StoredEnvelope> decode_stored_envelope(const std::vector<uint8_t>&);
std::optional<IdList> decode_id_list(const std::vector<uint8_t>&);
std::optional<HashOp> decode_hash_op(const std::vector<uint8_t>&);
std::optional<InviteStatus> decode_invite_status(const std::vector<uint8_t>&);

// --- What gets signed. Each starts with its own label, and includes the relay ID, so a
// signature made for one purpose or one relay can't be accepted for another. ---

std::vector<uint8_t> hello_signing_input(const std::vector<uint8_t>& client_nonce,
                                         const std::vector<uint8_t>& relay_id,
                                         uint32_t version,
                                         const std::vector<uint8_t>& auth_challenge);
std::vector<uint8_t> register_signing_input(const std::vector<uint8_t>& relay_id,
                                            const std::vector<uint8_t>& mailbox_id,
                                            const std::vector<uint8_t>& access_public_key,
                                            const std::vector<uint8_t>& send_token_hash);
std::vector<uint8_t> auth_signing_input(const std::vector<uint8_t>& auth_challenge,
                                        const std::vector<uint8_t>& relay_id,
                                        const std::vector<uint8_t>& mailbox_id);

}  // namespace relay
