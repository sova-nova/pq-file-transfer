#include "message_record.h"

#include "crypto_engine.h"
#include "protocol.h"

#include <algorithm>
#include <stdexcept>

namespace chat {

namespace {

constexpr uint32_t RECORD_MAGIC = 0x50514D52;  // "PQMR"
constexpr uint32_t RECORD_VERSION = 1;
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
    if (!empty_or(r.own_prev, HASH_BYTES) || !empty_or(r.seen, HASH_BYTES)) return false;
    switch (r.type) {
        case RecordType::Text: return r.payload.size() <= MAX_TEXT_BYTES;
        case RecordType::Receipt: return r.payload.size() <= 1 + 4 + MAX_RECEIPT_IDS * (4 + ID_BYTES);
        case RecordType::TokenGrant: return r.payload.size() == 32;
    }
    return false;
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
    write_blob(body, r.seen);

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
    if (!magic || *magic != RECORD_MAGIC || !version || *version != RECORD_VERSION) return std::nullopt;

    Record r;
    auto conv = read_blob(bd.data(), bd.size(), b, ID_BYTES);
    auto msg = read_blob(bd.data(), bd.size(), b, ID_BYTES);
    auto sender = read_blob(bd.data(), bd.size(), b, HASH_BYTES);
    auto rh = read_blob(bd.data(), bd.size(), b, HASH_BYTES);
    auto sent = read_u64(bd.data(), bd.size(), b);
    auto type = read_u32(bd.data(), bd.size(), b);
    auto payload = read_blob(bd.data(), bd.size(), b, MAX_TEXT_BYTES + 1);
    auto prev = read_blob(bd.data(), bd.size(), b, HASH_BYTES);
    auto seen = read_blob(bd.data(), bd.size(), b, HASH_BYTES);
    if (!conv || !msg || !sender || !rh || !sent || !type || !payload || !prev || !seen || b != bd.size()) return std::nullopt;
    if (*type < 1 || *type > 3) return std::nullopt;

    r.conversation_id = std::move(*conv);
    r.message_id = std::move(*msg);
    r.sender = std::move(*sender);
    r.recipients_hash = std::move(*rh);
    r.sent_at = *sent;
    r.type = static_cast<RecordType>(*type);
    r.payload = std::move(*payload);
    r.own_prev = std::move(*prev);
    r.seen = std::move(*seen);
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
