#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// Signed message records: the unit of a conversation. A record says who sent what, to whom, in
// which conversation, and what the sender had already seen, and is signed with the sender's
// identity key. Everything a Saved chat keeps as evidence is a sequence of these.
//
// Wire format (big-endian, blobs are u32 length + bytes):
//   raw  = blob(body) || blob(signature)
//   body = u32 magic "PQMR" | u32 version | blob conversation_id | blob message_id | blob sender
//          | blob recipients_hash | u64 sent_at | u32 type | blob payload | blob own_prev | blob seen
//   signature = ML-DSA-65 over string("pq-suite v3 message") || body
//   entry hash = SHA-256(raw)
namespace chat {

using Bytes = std::vector<uint8_t>;

constexpr size_t ID_BYTES = 16;
constexpr size_t HASH_BYTES = 32;
constexpr size_t MAX_TEXT_BYTES = 32 * 1024;   // longer content is sent as an attachment (later milestone)
constexpr size_t MAX_RECORD_BYTES = 40 * 1024;

enum class RecordType : uint32_t {
    Text = 1,        // payload: the message, UTF-8
    Receipt = 2,     // payload: see receipt_payload()
    TokenGrant = 3,  // payload: a 32-byte send token for the recipient to use when writing back
};

enum class ReceiptKind : uint8_t { Delivered = 1, Read = 2 };

struct Record {
    Bytes conversation_id;    // ID_BYTES
    Bytes message_id;         // ID_BYTES, random
    Bytes sender;             // HASH_BYTES: SHA-256 of the sender's signing key (their fingerprint)
    Bytes recipients_hash;    // HASH_BYTES: binds the record to exactly these people (see recipients_hash_for)
    uint64_t sent_at = 0;     // unix seconds, the sender's clock
    RecordType type = RecordType::Text;
    Bytes payload;
    // What the sender had committed to when writing this. Without a relay-ordered log there is no
    // single chain, so each record names the previous record the sender wrote ("own_prev") and the
    // latest one it had received ("seen"). Each is empty or HASH_BYTES.
    Bytes own_prev;
    Bytes seen;
};

struct SignedRecord {
    Record record;
    Bytes raw;         // exactly what is sent and stored
    Bytes entry_hash;  // SHA-256(raw)
    Bytes body;
    Bytes signature;
};

// The conversation ID of the one Saved chat between two identities: the same on both sides, so no
// handshake is needed. `a` and `b` are fingerprints (HASH_BYTES each), in either order.
Bytes conversation_id_for(const Bytes& a, const Bytes& b);

// Hash over the sorted fingerprints of everyone a record is for, so it can't be redirected.
Bytes recipients_hash_for(const std::vector<Bytes>& fingerprints);

// Signs a record. Throws std::runtime_error if the record is malformed or too large.
Bytes sign_record(const Record& record, const Bytes& signing_private_key);

// Parses the structure only. Check the signature with verify_record before trusting anything in it.
std::optional<SignedRecord> parse_record(const Bytes& raw);
bool verify_record(const SignedRecord& signed_record, const Bytes& signing_public_key);

// A receipt tells the sender that these messages were delivered or read.
Bytes receipt_payload(ReceiptKind kind, const std::vector<Bytes>& message_ids);
struct ReceiptInfo {
    ReceiptKind kind = ReceiptKind::Delivered;
    std::vector<Bytes> message_ids;
};
std::optional<ReceiptInfo> parse_receipt_payload(const Bytes& payload);

}  // namespace chat
