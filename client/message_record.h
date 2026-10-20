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
//          | blob recipients_hash | u64 sent_at | u32 type | blob payload | blob own_prev | seen
//   seen (version 2) = u32 count | blob hash x count      (count <= 15, hashes distinct, 32 bytes each)
//   seen (version 1) = blob hash                          (empty or 32 bytes; read as a list of 0 or 1)
//   signature = ML-DSA-65 over string("pq-suite v3 message") || body
//   entry hash = SHA-256(raw)
//
// Records are written as version 2. Version 1 records (made by the first one-to-one chats) are
// still read, so history keeps working; type 4 (Conversation) exists only in version 2.
namespace chat {

using Bytes = std::vector<uint8_t>;

constexpr size_t ID_BYTES = 16;
constexpr size_t HASH_BYTES = 32;
constexpr size_t MAX_TEXT_BYTES = 32 * 1024;   // longer content is sent as an attachment (later milestone)
constexpr size_t MAX_RECORD_BYTES = 40 * 1024;
constexpr size_t MAX_SEEN = 15;                      // the other members of a 16-person group
constexpr size_t MAX_GROUP_MEMBERS = 16;             // including the creator
constexpr size_t MAX_TITLE_BYTES = 64;
constexpr size_t MAX_CONVERSATION_PAYLOAD = 1024;    // 16 members and a full title take about 700
constexpr size_t MAX_FORWARD_ENVELOPE_BYTES = 8 * 1024;  // an envelope holding one token grant is about 5 KB

enum class RecordType : uint32_t {
    Text = 1,          // payload: the message, UTF-8
    Receipt = 2,       // payload: see receipt_payload()
    TokenGrant = 3,    // payload: a 32-byte send token for the recipient to use when writing back
    Conversation = 4,  // payload: see conversation_payload(); creates a group (version 2 only)
    Forward = 5,       // payload: see forward_payload(); asks a group's creator to pass a sealed envelope to another member (version 2 only)
    ArchiveGrant = 6,  // payload: see archive_grant_payload(); gives one member what they need to use the chat's archive (version 2 only)
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
    // single chain, so each record names the previous record the sender wrote ("own_prev", empty
    // or HASH_BYTES) and the latest record it had received from each other member ("seen": up to
    // MAX_SEEN distinct hashes of HASH_BYTES each; in a one-to-one chat that is zero or one).
    Bytes own_prev;
    std::vector<Bytes> seen;
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

// --- Conversation (creation) records ---
//
// A group is created by one signed record, which the creator sends to every member separately.
// It names the members by fingerprint only (their bundles, at about 6.5 KB each, travel beside
// it in the envelope; see envelope.h). Membership, mode and timer never change afterwards.
//
//   payload = u32 payload_version (1) | blob title | u32 mode | u64 timer_seconds | blob previous_id
//             | u32 member_count | blob fingerprint x member_count
//
// The record's `sender` is the creator, who must be one of the members, and its
// `recipients_hash` must be the hash of exactly the listed members.
enum class ConversationMode : uint32_t { Saved = 1 };  // Private (timed) chats arrive with a later milestone

struct ConversationInfo {
    std::string title;             // optional; 0 to MAX_TITLE_BYTES of UTF-8 with no control or direction-override characters
    ConversationMode mode = ConversationMode::Saved;
    uint64_t timer_seconds = 0;    // must be 0 for Saved chats
    Bytes previous_id;             // the conversation this one replaces (a changed group): empty or ID_BYTES
    std::vector<Bytes> members;    // everyone including the creator, in the creator's order: 2 to MAX_GROUP_MEMBERS
                                   // distinct fingerprints of HASH_BYTES each
};

// Encodes the payload. Throws std::runtime_error if `info` is not valid.
Bytes conversation_payload(const ConversationInfo& info);
// Decodes and validates a payload. std::nullopt for anything malformed or invalid.
std::optional<ConversationInfo> parse_conversation_payload(const Bytes& payload);
// For a record of type Conversation: its payload is valid, its sender is one of the listed
// members, and its recipients hash matches the member list. Check the signature separately
// with verify_record. std::nullopt otherwise.
std::optional<ConversationInfo> conversation_from_record(const SignedRecord& signed_record);

// --- Forwarding through a group's creator ---
//
// Members of a group who aren't each other's contacts have no way to write to each other, so a
// member makes a send token for each of the others and seals it to its new owner, inside an
// envelope the creator can't open. The creator is the one person everyone can write to, so the
// member sends that envelope to the creator in a Forward record, and the creator deposits it,
// unread, in the target's mailbox.
//
//   payload = blob target_fingerprint (32 bytes) | blob sealed_envelope
//
// Like receipts, a Forward record is not part of the conversation's transcript: it has no
// previous entry and has seen nothing.
struct ForwardInfo {
    Bytes target;    // HASH_BYTES: the member the envelope is for
    Bytes envelope;  // sealed to that member; the creator deposits it as it is
};
// Throws std::runtime_error if the target isn't HASH_BYTES or the envelope is empty or too large.
Bytes forward_payload(const Bytes& target, const Bytes& sealed_envelope);
// std::nullopt for anything malformed, including trailing bytes.
std::optional<ForwardInfo> parse_forward_payload(const Bytes& payload);

// --- Archive grants ---
//
// A chat's archive is made by one person (a group's creator; in a one-to-one chat, whoever has the
// smaller fingerprint). They give each other member a grant, sealed in that member's own envelope: where
// the archive is, the key its entries are encrypted under, and a one-time token that lets that member
// register their key with the relay. Like receipts and forwards, a grant is outside the transcript.
//
//   payload = blob relay_address | blob relay_id | blob archive_key | blob join_token
constexpr size_t MAX_RELAY_ADDRESS_BYTES = 255;
constexpr size_t MAX_ARCHIVE_GRANT_PAYLOAD = 512;

struct ArchiveGrantInfo {
    std::string relay_address;  // host:port of the relay that holds the archive (visible printable characters only)
    Bytes relay_id;             // HASH_BYTES: that relay's identity, to pin
    Bytes archive_key;          // 32 bytes: every entry is encrypted under it
    Bytes join_token;           // 32 bytes: this member's one-time permission to join
};
// Throws std::runtime_error if any part has the wrong size or the address has unprintable characters.
Bytes archive_grant_payload(const ArchiveGrantInfo& info);
// std::nullopt for anything malformed, including trailing bytes.
std::optional<ArchiveGrantInfo> parse_archive_grant_payload(const Bytes& payload);

// A receipt tells the sender that these messages were delivered or read.
Bytes receipt_payload(ReceiptKind kind, const std::vector<Bytes>& message_ids);
struct ReceiptInfo {
    ReceiptKind kind = ReceiptKind::Delivered;
    std::vector<Bytes> message_ids;
};
std::optional<ReceiptInfo> parse_receipt_payload(const Bytes& payload);

}  // namespace chat
