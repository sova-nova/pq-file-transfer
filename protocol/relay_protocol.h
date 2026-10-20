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

// --- Chat archives ---
//
// An archive is one chat's encrypted log on the relay. The relay can't read it: each entry is
// ciphertext under a key only the members hold. What the relay does enforce is the order. Entries
// are numbered from 1; entry n's hash covers the archive ID, n, the previous entry's hash and its own
// ciphertext, so the chain can be checked by anyone who holds a copy. An append names the head it
// extends and is accepted only if that is still the head (compare-and-swap), which gives one linear
// chain even with simultaneous senders.
constexpr size_t ARCHIVE_ID_BYTES = 16;       // the chat's conversation ID
constexpr size_t JOIN_TOKEN_BYTES = 32;
constexpr size_t MAX_ARCHIVE_MEMBERS = 16;
constexpr size_t MAX_ARCHIVE_ENTRY_BYTES = 64 * 1024;
constexpr uint32_t MAX_FETCH_ENTRIES = 256;

struct ArchiveCreate {
    std::vector<uint8_t> archive_id;                    // ARCHIVE_ID_BYTES
    std::vector<std::vector<uint8_t>> join_token_hashes; // one per member (1 to MAX_ARCHIVE_MEMBERS), HASH_BYTES each
};
struct ArchiveJoin {
    std::vector<uint8_t> archive_id;
    std::vector<uint8_t> join_token;        // JOIN_TOKEN_BYTES: the secret itself
    std::vector<uint8_t> public_key;        // ML-DSA-65, made for this chat only
    std::vector<uint8_t> signature;         // by that key over archive_join_signing_input()
};
struct ArchiveAuth {
    std::vector<uint8_t> archive_id;
    std::vector<uint8_t> key_hash;          // HASH_BYTES: SHA-256 of the registered public key
    std::vector<uint8_t> signature;         // over archive_auth_signing_input()
};
struct ArchiveAppend {
    uint64_t expected_number = 0;           // how many entries the sender believes there are
    std::vector<uint8_t> expected_hash;     // HASH_BYTES: the hash of that head (the genesis hash when there are none)
    std::vector<uint8_t> ciphertext;        // 1 to MAX_ARCHIVE_ENTRY_BYTES
};
struct ArchiveHead {                         // APPEND_OK, STALE and FETCH_END
    uint64_t number = 0;
    std::vector<uint8_t> hash;
};
struct ArchiveFetch {
    uint64_t from_number = 1;
    uint32_t limit = 0;                     // 1 to MAX_FETCH_ENTRIES
};
struct ArchiveEntry {
    uint64_t number = 0;
    std::vector<uint8_t> hash;
    std::vector<uint8_t> ciphertext;  // empty exactly when `tombstone`
    bool tombstone = false;           // the content was removed by agreement; the hash is kept, so the chain still holds
};

// Deleting (the whole archive) or redacting (named entries) needs the agreement of every member. Each
// registered member key signs the same order; the relay checks one signature from each before it acts.
// An order has an operation ID, so a signature made for one order can't be used for another, and an
// expiry, after which the relay refuses it.
constexpr size_t MAX_DELETE_ENTRIES = 64;
constexpr uint32_t DELETE_SCOPE_CHAT = 1;
constexpr uint32_t DELETE_SCOPE_ENTRIES = 2;
struct ArchiveSignature {
    std::vector<uint8_t> key_hash;   // HASH_BYTES: which registered key
    std::vector<uint8_t> signature;  // over archive_delete_signing_input()
};
struct ArchiveDelete {
    uint32_t scope = DELETE_SCOPE_CHAT;
    std::vector<uint8_t> op_id;      // 16 bytes
    uint64_t expires_at = 0;         // unix seconds
    std::vector<std::vector<uint8_t>> entry_hashes;  // for DELETE_SCOPE_ENTRIES: 1 to MAX_DELETE_ENTRIES chain hashes; none for the whole chat
    std::vector<ArchiveSignature> signatures;        // 1 to MAX_ARCHIVE_MEMBERS
};

// --- Keyring ---
//
// A mailbox owner can keep one opaque, encrypted blob on the relay: what a reinstalled app needs, beyond
// the keys folder, to find and open its chats' archives. The relay can't read it. It is sent in chunks,
// because it can be much larger than one message, and replaces the previous one only when the last chunk
// has arrived.
constexpr size_t KEYRING_CHUNK_BYTES = 48 * 1024;
constexpr uint32_t MAX_KEYRING_BYTES = 16u * 1024 * 1024;  // the most the format allows; a relay sets its own lower limit

struct KeyringChunk {
    uint32_t total_size = 0;  // the whole keyring
    uint32_t index = 0;       // this chunk's place, from 0
    uint32_t count = 0;       // how many chunks there are
    std::vector<uint8_t> data;
};

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
std::vector<uint8_t> encode(const ArchiveCreate&);
std::vector<uint8_t> encode(const ArchiveJoin&);
std::vector<uint8_t> encode(const ArchiveAuth&);
std::vector<uint8_t> encode(const ArchiveAppend&);
std::vector<uint8_t> encode(const ArchiveHead&);
std::vector<uint8_t> encode(const ArchiveFetch&);
std::vector<uint8_t> encode(const ArchiveEntry&);
std::vector<uint8_t> encode(const KeyringChunk&);
std::vector<uint8_t> encode(const ArchiveDelete&);

std::optional<Hello> decode_hello(const std::vector<uint8_t>&);
std::optional<HelloReply> decode_hello_reply(const std::vector<uint8_t>&);
std::optional<Register> decode_register(const std::vector<uint8_t>&);
std::optional<Auth> decode_auth(const std::vector<uint8_t>&);
std::optional<Deposit> decode_deposit(const std::vector<uint8_t>&);
std::optional<StoredEnvelope> decode_stored_envelope(const std::vector<uint8_t>&);
std::optional<IdList> decode_id_list(const std::vector<uint8_t>&);
std::optional<HashOp> decode_hash_op(const std::vector<uint8_t>&);
std::optional<InviteStatus> decode_invite_status(const std::vector<uint8_t>&);
std::optional<ArchiveCreate> decode_archive_create(const std::vector<uint8_t>&);
std::optional<ArchiveJoin> decode_archive_join(const std::vector<uint8_t>&);
std::optional<ArchiveAuth> decode_archive_auth(const std::vector<uint8_t>&);
std::optional<ArchiveAppend> decode_archive_append(const std::vector<uint8_t>&);
std::optional<ArchiveHead> decode_archive_head(const std::vector<uint8_t>&);
std::optional<ArchiveFetch> decode_archive_fetch(const std::vector<uint8_t>&);
std::optional<ArchiveEntry> decode_archive_entry(const std::vector<uint8_t>&);
// A chunk is valid only if its numbers fit together: the count is what the total needs, the index is in
// range, and the data is a full chunk (or the remainder, for the last). An all-zero chunk with no data
// means "no keyring".
std::optional<KeyringChunk> decode_keyring_chunk(const std::vector<uint8_t>&);
std::optional<ArchiveDelete> decode_archive_delete(const std::vector<uint8_t>&);

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
std::vector<uint8_t> archive_join_signing_input(const std::vector<uint8_t>& relay_id,
                                                const std::vector<uint8_t>& archive_id,
                                                const std::vector<uint8_t>& public_key,
                                                const std::vector<uint8_t>& join_token_hash);
std::vector<uint8_t> archive_auth_signing_input(const std::vector<uint8_t>& auth_challenge,
                                                const std::vector<uint8_t>& relay_id,
                                                const std::vector<uint8_t>& archive_id,
                                                const std::vector<uint8_t>& key_hash);

std::vector<uint8_t> archive_delete_signing_input(const std::vector<uint8_t>& relay_id, const std::vector<uint8_t>& archive_id, uint32_t scope,
                                                  const std::vector<uint8_t>& op_id, uint64_t expires_at,
                                                  const std::vector<std::vector<uint8_t>>& entry_hashes);

// What gets hashed (with SHA-256, by the caller) to make an archive's chain. The genesis hash is the
// head of an empty archive; entry n's hash is over the previous head, so each entry commits to
// everything before it.
std::vector<uint8_t> archive_genesis_input(const std::vector<uint8_t>& archive_id);
std::vector<uint8_t> archive_entry_hash_input(const std::vector<uint8_t>& archive_id, uint64_t number,
                                              const std::vector<uint8_t>& previous_hash,
                                              const std::vector<uint8_t>& ciphertext);

}  // namespace relay
