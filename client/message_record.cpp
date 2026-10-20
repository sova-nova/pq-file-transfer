#include "message_record.h"

#include "crypto_engine.h"
#include "protocol.h"

#include <algorithm>
#include <stdexcept>

namespace chat {

namespace {

constexpr uint32_t RECORD_MAGIC = 0x50514D52;  // "PQMR"
constexpr uint32_t RECORD_VERSION = 2;      // what is written
constexpr uint32_t MIN_RECORD_VERSION = 1;  // the oldest still read
constexpr uint32_t CONVERSATION_PAYLOAD_VERSION = 1;
const char SIGNATURE_LABEL[] = "pq-suite v3 message";
const char CONVERSATION_LABEL[] = "pq-suite v3 one-to-one conversation";
const char RECIPIENTS_LABEL[] = "pq-suite v3 recipients";
constexpr size_t MAX_RECEIPT_IDS = 256;

Bytes signing_input(const Bytes& body) {
    Bytes in;
    write_string(in, SIGNATURE_LABEL);
    write_bytes(in, body.data(), body.size());
    return in;
}

bool empty_or(const Bytes& b, size_t size) { return b.empty() || b.size() == size; }

bool well_formed(const Record& r) {
    if (r.conversation_id.size() != ID_BYTES || r.message_id.size() != ID_BYTES) return false;
    if (r.sender.size() != HASH_BYTES || r.recipients_hash.size() != HASH_BYTES) return false;
    if (!empty_or(r.own_prev, HASH_BYTES)) return false;
    if (r.seen.size() > MAX_SEEN) return false;
    for (size_t i = 0; i < r.seen.size(); i++) {
        if (r.seen[i].size() != HASH_BYTES) return false;
        for (size_t j = 0; j < i; j++)
            if (r.seen[i] == r.seen[j]) return false;  // naming the same entry twice says nothing more
    }
    switch (r.type) {
        case RecordType::Text: return r.payload.size() <= MAX_TEXT_BYTES;
        case RecordType::Receipt: return r.payload.size() <= 1 + 4 + MAX_RECEIPT_IDS * (4 + ID_BYTES);
        case RecordType::TokenGrant: return r.payload.size() == 32;
        // The first thing in a conversation: nothing came before it, and it has seen nothing.
        case RecordType::Conversation: return r.payload.size() <= MAX_CONVERSATION_PAYLOAD && r.own_prev.empty() && r.seen.empty();
        // Control records, outside the transcript like receipts.
        case RecordType::Forward: return r.payload.size() <= 4 + HASH_BYTES + 4 + MAX_FORWARD_ENVELOPE_BYTES && r.own_prev.empty() && r.seen.empty();
        case RecordType::ArchiveGrant: return r.payload.size() <= MAX_ARCHIVE_GRANT_PAYLOAD && r.own_prev.empty() && r.seen.empty();
    }
    return false;
}

// True for well-formed UTF-8 that is safe to show as a label: no overlong forms, surrogates or
// values beyond U+10FFFF, no control characters, and none of the bidirectional embedding,
// override or isolate characters that can make text read in a different order than it is typed.
bool valid_label(const std::string& s) {
    static const uint32_t MIN_FOR_LENGTH[] = {0, 0, 0x80, 0x800, 0x10000};
    size_t i = 0;
    while (i < s.size()) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        uint32_t cp;
        size_t len;
        if (c < 0x80) { cp = c; len = 1; }
        else if ((c & 0xE0) == 0xC0) { cp = c & 0x1Fu; len = 2; }
        else if ((c & 0xF0) == 0xE0) { cp = c & 0x0Fu; len = 3; }
        else if ((c & 0xF8) == 0xF0) { cp = c & 0x07u; len = 4; }
        else return false;
        if (i + len > s.size()) return false;
        for (size_t k = 1; k < len; k++) {
            const unsigned char cc = static_cast<unsigned char>(s[i + k]);
            if ((cc & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (cc & 0x3Fu);
        }
        if (len > 1 && cp < MIN_FOR_LENGTH[len]) return false;  // overlong
        if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
        if (cp < 0x20 || (cp >= 0x7F && cp <= 0x9F)) return false;
        if ((cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069)) return false;
        i += len;
    }
    return true;
}

bool valid_info(const ConversationInfo& c) {
    if (c.title.size() > MAX_TITLE_BYTES || !valid_label(c.title)) return false;
    if (c.mode != ConversationMode::Saved || c.timer_seconds != 0) return false;
    if (!c.previous_id.empty() && c.previous_id.size() != ID_BYTES) return false;
    if (c.members.size() < 2 || c.members.size() > MAX_GROUP_MEMBERS) return false;
    for (size_t i = 0; i < c.members.size(); i++) {
        if (c.members[i].size() != HASH_BYTES) return false;
        for (size_t j = 0; j < i; j++)
            if (c.members[i] == c.members[j]) return false;
    }
    return true;
}

}  // namespace

Bytes conversation_id_for(const Bytes& a, const Bytes& b) {
    const Bytes& low = std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end()) ? a : b;
    const Bytes& high = &low == &a ? b : a;
    Bytes in;
    write_string(in, CONVERSATION_LABEL);
    write_blob(in, low);
    write_blob(in, high);
    Bytes digest = CryptoEngine::sha256(in);
    digest.resize(ID_BYTES);
    return digest;
}

Bytes recipients_hash_for(const std::vector<Bytes>& fingerprints) {
    std::vector<Bytes> sorted = fingerprints;
    std::sort(sorted.begin(), sorted.end());
    Bytes in;
    write_string(in, RECIPIENTS_LABEL);
    write_u32(in, static_cast<uint32_t>(sorted.size()));
    for (const auto& f : sorted) write_blob(in, f);
    return CryptoEngine::sha256(in);
}

Bytes sign_record(const Record& r, const Bytes& signing_private_key) {
    if (!well_formed(r)) throw std::runtime_error("The message record is malformed or too large");
    Bytes body;
    write_u32(body, RECORD_MAGIC);
    write_u32(body, RECORD_VERSION);
    write_blob(body, r.conversation_id);
    write_blob(body, r.message_id);
    write_blob(body, r.sender);
    write_blob(body, r.recipients_hash);
    write_u64(body, r.sent_at);
    write_u32(body, static_cast<uint32_t>(r.type));
    write_blob(body, r.payload);
    write_blob(body, r.own_prev);
    write_u32(body, static_cast<uint32_t>(r.seen.size()));
    for (const auto& s : r.seen) write_blob(body, s);

    Bytes signature = CryptoEngine::sign(signing_input(body), signing_private_key);
    Bytes raw;
    write_blob(raw, body);
    write_blob(raw, signature);
    return raw;
}

std::optional<SignedRecord> parse_record(const Bytes& raw) {
    if (raw.size() > MAX_RECORD_BYTES) return std::nullopt;
    size_t off = 0;
    auto body = read_blob(raw.data(), raw.size(), off, MAX_RECORD_BYTES);
    auto signature = read_blob(raw.data(), raw.size(), off, 8192);
    if (!body || !signature || off != raw.size()) return std::nullopt;

    size_t b = 0;
    const Bytes& bd = *body;
    auto magic = read_u32(bd.data(), bd.size(), b);
    auto version = read_u32(bd.data(), bd.size(), b);
    if (!magic || *magic != RECORD_MAGIC || !version || *version < MIN_RECORD_VERSION || *version > RECORD_VERSION) return std::nullopt;

    Record r;
    auto conv = read_blob(bd.data(), bd.size(), b, ID_BYTES);
    auto msg = read_blob(bd.data(), bd.size(), b, ID_BYTES);
    auto sender = read_blob(bd.data(), bd.size(), b, HASH_BYTES);
    auto rh = read_blob(bd.data(), bd.size(), b, HASH_BYTES);
    auto sent = read_u64(bd.data(), bd.size(), b);
    auto type = read_u32(bd.data(), bd.size(), b);
    auto payload = read_blob(bd.data(), bd.size(), b, MAX_TEXT_BYTES + 1);
    auto prev = read_blob(bd.data(), bd.size(), b, HASH_BYTES);
    if (!conv || !msg || !sender || !rh || !sent || !type || !payload || !prev) return std::nullopt;

    std::vector<Bytes> seen;
    if (*version == 1) {
        // The first one-to-one chats: a single hash, or nothing.
        auto one = read_blob(bd.data(), bd.size(), b, HASH_BYTES);
        if (!one) return std::nullopt;
        if (!one->empty()) seen.push_back(std::move(*one));
    } else {
        auto count = read_u32(bd.data(), bd.size(), b);
        if (!count || *count > MAX_SEEN) return std::nullopt;
        for (uint32_t i = 0; i < *count; i++) {
            auto hash = read_blob(bd.data(), bd.size(), b, HASH_BYTES);
            if (!hash) return std::nullopt;
            seen.push_back(std::move(*hash));
        }
    }
    if (b != bd.size()) return std::nullopt;
    const uint32_t newest_type = *version == 1 ? 3 : 6;  // Conversation, Forward and ArchiveGrant records came with version 2
    if (*type < 1 || *type > newest_type) return std::nullopt;

    r.conversation_id = std::move(*conv);
    r.message_id = std::move(*msg);
    r.sender = std::move(*sender);
    r.recipients_hash = std::move(*rh);
    r.sent_at = *sent;
    r.type = static_cast<RecordType>(*type);
    r.payload = std::move(*payload);
    r.own_prev = std::move(*prev);
    r.seen = std::move(seen);
    if (!well_formed(r)) return std::nullopt;

    SignedRecord out;
    out.record = std::move(r);
    out.raw = raw;
    out.entry_hash = CryptoEngine::sha256(raw);
    out.body = std::move(*body);
    out.signature = std::move(*signature);
    return out;
}

bool verify_record(const SignedRecord& sr, const Bytes& signing_public_key) {
    // The record must also name the key it claims to be from: the sender field is the fingerprint.
    if (CryptoEngine::fingerprint(signing_public_key) != bytes_to_hex(sr.record.sender)) return false;
    return CryptoEngine::verify(signing_input(sr.body), sr.signature, signing_public_key);
}

Bytes conversation_payload(const ConversationInfo& info) {
    if (!valid_info(info)) throw std::runtime_error("The group's details are not valid");
    Bytes p;
    write_u32(p, CONVERSATION_PAYLOAD_VERSION);
    write_blob(p, Bytes(info.title.begin(), info.title.end()));
    write_u32(p, static_cast<uint32_t>(info.mode));
    write_u64(p, info.timer_seconds);
    write_blob(p, info.previous_id);
    write_u32(p, static_cast<uint32_t>(info.members.size()));
    for (const auto& m : info.members) write_blob(p, m);
    return p;
}

std::optional<ConversationInfo> parse_conversation_payload(const Bytes& payload) {
    if (payload.size() > MAX_CONVERSATION_PAYLOAD) return std::nullopt;
    size_t off = 0;
    auto version = read_u32(payload.data(), payload.size(), off);
    auto title = read_blob(payload.data(), payload.size(), off, MAX_TITLE_BYTES);
    auto mode = read_u32(payload.data(), payload.size(), off);
    auto timer = read_u64(payload.data(), payload.size(), off);
    auto previous = read_blob(payload.data(), payload.size(), off, ID_BYTES);
    auto count = read_u32(payload.data(), payload.size(), off);
    if (!version || *version != CONVERSATION_PAYLOAD_VERSION || !title || !mode || !timer || !previous || !count) return std::nullopt;
    if (*count < 2 || *count > MAX_GROUP_MEMBERS) return std::nullopt;

    ConversationInfo info;
    info.title.assign(title->begin(), title->end());
    info.mode = static_cast<ConversationMode>(*mode);
    info.timer_seconds = *timer;
    info.previous_id = std::move(*previous);
    for (uint32_t i = 0; i < *count; i++) {
        auto member = read_blob(payload.data(), payload.size(), off, HASH_BYTES);
        if (!member) return std::nullopt;
        info.members.push_back(std::move(*member));
    }
    if (off != payload.size() || !valid_info(info)) return std::nullopt;
    return info;
}

std::optional<ConversationInfo> conversation_from_record(const SignedRecord& sr) {
    const Record& r = sr.record;
    if (r.type != RecordType::Conversation) return std::nullopt;
    auto info = parse_conversation_payload(r.payload);
    if (!info) return std::nullopt;
    // The creator is a member, and the record is bound to exactly these people.
    if (std::find(info->members.begin(), info->members.end(), r.sender) == info->members.end()) return std::nullopt;
    if (r.recipients_hash != recipients_hash_for(info->members)) return std::nullopt;
    return info;
}

Bytes forward_payload(const Bytes& target, const Bytes& sealed_envelope) {
    if (target.size() != HASH_BYTES || sealed_envelope.empty() || sealed_envelope.size() > MAX_FORWARD_ENVELOPE_BYTES)
        throw std::runtime_error("The forwarded envelope is not valid");
    Bytes p;
    write_blob(p, target);
    write_blob(p, sealed_envelope);
    return p;
}

std::optional<ForwardInfo> parse_forward_payload(const Bytes& payload) {
    size_t off = 0;
    auto target = read_blob(payload.data(), payload.size(), off, HASH_BYTES);
    auto envelope = read_blob(payload.data(), payload.size(), off, MAX_FORWARD_ENVELOPE_BYTES);
    if (!target || !envelope || off != payload.size()) return std::nullopt;
    if (target->size() != HASH_BYTES || envelope->empty()) return std::nullopt;
    return ForwardInfo{std::move(*target), std::move(*envelope)};
}

namespace {
bool visible_ascii(const std::string& s) {
    for (unsigned char c : s)
        if (c < 0x21 || c > 0x7E) return false;
    return true;
}
}  // namespace

Bytes archive_grant_payload(const ArchiveGrantInfo& info) {
    if (info.relay_address.empty() || info.relay_address.size() > MAX_RELAY_ADDRESS_BYTES || !visible_ascii(info.relay_address) ||
        info.relay_id.size() != HASH_BYTES || info.archive_key.size() != 32 || info.join_token.size() != 32)
        throw std::runtime_error("The archive grant is not valid");
    Bytes p;
    write_blob(p, Bytes(info.relay_address.begin(), info.relay_address.end()));
    write_blob(p, info.relay_id);
    write_blob(p, info.archive_key);
    write_blob(p, info.join_token);
    return p;
}

std::optional<ArchiveGrantInfo> parse_archive_grant_payload(const Bytes& payload) {
    if (payload.size() > MAX_ARCHIVE_GRANT_PAYLOAD) return std::nullopt;
    size_t off = 0;
    auto address = read_blob(payload.data(), payload.size(), off, MAX_RELAY_ADDRESS_BYTES);
    auto relay_id = read_blob(payload.data(), payload.size(), off, HASH_BYTES);
    auto key = read_blob(payload.data(), payload.size(), off, 32);
    auto token = read_blob(payload.data(), payload.size(), off, 32);
    if (!address || !relay_id || !key || !token || off != payload.size()) return std::nullopt;
    ArchiveGrantInfo info;
    info.relay_address.assign(address->begin(), address->end());
    info.relay_id = std::move(*relay_id);
    info.archive_key = std::move(*key);
    info.join_token = std::move(*token);
    if (info.relay_address.empty() || !visible_ascii(info.relay_address) || info.relay_id.size() != HASH_BYTES || info.archive_key.size() != 32 ||
        info.join_token.size() != 32)
        return std::nullopt;
    return info;
}

Bytes receipt_payload(ReceiptKind kind, const std::vector<Bytes>& message_ids) {
    if (message_ids.size() > MAX_RECEIPT_IDS) throw std::runtime_error("Too many messages in one receipt");
    Bytes p;
    p.push_back(static_cast<uint8_t>(kind));
    write_u32(p, static_cast<uint32_t>(message_ids.size()));
    for (const auto& id : message_ids) write_blob(p, id);
    return p;
}

std::optional<ReceiptInfo> parse_receipt_payload(const Bytes& payload) {
    if (payload.empty()) return std::nullopt;
    ReceiptInfo info;
    if (payload[0] != static_cast<uint8_t>(ReceiptKind::Delivered) && payload[0] != static_cast<uint8_t>(ReceiptKind::Read))
        return std::nullopt;
    info.kind = static_cast<ReceiptKind>(payload[0]);
    size_t off = 1;
    auto count = read_u32(payload.data(), payload.size(), off);
    if (!count || *count > MAX_RECEIPT_IDS) return std::nullopt;
    for (uint32_t i = 0; i < *count; i++) {
        auto id = read_blob(payload.data(), payload.size(), off, ID_BYTES);
        if (!id || id->size() != ID_BYTES) return std::nullopt;
        info.message_ids.push_back(std::move(*id));
    }
    if (off != payload.size()) return std::nullopt;
    return info;
}

}  // namespace chat
