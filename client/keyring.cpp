#include "keyring.h"

#include <stdexcept>

#include "crypto_engine.h"
#include "protocol.h"

namespace keyring {

namespace {

const char KEYRING_MAGIC_LABEL[] = "pq-suite v3 keyring";
const char KEYRING_AAD_LABEL[] = "pq-suite v3 archive keyring seal";

constexpr size_t MAX_ARCHIVES = 4096;
constexpr size_t MAX_ENTRIES = 100000;
constexpr size_t MAX_TEXT = 4096;
constexpr size_t MAX_BUNDLE = 16 * 1024;
constexpr size_t MAX_KEY_BLOB = 8192;

void put_text(Bytes& b, const std::string& s) {
    if (s.size() > MAX_TEXT) throw std::runtime_error("A keyring entry is too long");
    write_blob(b, Bytes(s.begin(), s.end()));
}

}  // namespace

Bytes serialize(const Contents& c) {
    Bytes b;
    write_string(b, KEYRING_MAGIC_LABEL);
    write_u32(b, VERSION);
    write_u32(b, static_cast<uint32_t>(c.archives.size()));
    for (const auto& a : c.archives) {
        write_blob(b, a.conversation_id);
        put_text(b, a.relay_address);
        write_blob(b, a.relay_id);
        write_u32(b, static_cast<uint32_t>(a.role));
        write_u32(b, static_cast<uint32_t>(a.state));
        write_blob(b, a.archive_key);
        write_blob(b, a.chat_public_key);
        write_blob(b, a.chat_private_key);
        write_blob(b, a.join_token);
    }
    write_u32(b, static_cast<uint32_t>(c.verified.size()));
    for (const auto& fp : c.verified) put_text(b, fp);
    write_u32(b, static_cast<uint32_t>(c.member_tokens.size()));
    for (const auto& t : c.member_tokens) {
        write_blob(b, t.conversation_id);
        put_text(b, t.member_fp);
        write_blob(b, t.token);
    }
    write_u32(b, static_cast<uint32_t>(c.introduced.size()));
    for (const auto& i : c.introduced) {
        put_text(b, i.fp);
        write_blob(b, i.bundle);
        write_u64(b, static_cast<uint64_t>(i.issued_at));
        put_text(b, i.introduced_by);
        write_u64(b, static_cast<uint64_t>(i.first_seen));
    }
    write_u32(b, static_cast<uint32_t>(c.issued_tokens.size()));
    for (const auto& t : c.issued_tokens) {
        write_blob(b, t.hash);
        put_text(b, t.label);
        write_u64(b, static_cast<uint64_t>(t.created_at));
        put_text(b, t.bound_fp);
        write_u32(b, t.revoked ? 1 : 0);
    }
    write_u32(b, static_cast<uint32_t>(c.receipts.size()));
    for (const auto& r : c.receipts) {
        write_blob(b, r.conversation_id);
        write_u32(b, (r.delivery ? 1 : 0) | (r.read ? 2 : 0));
    }
    return b;
}

namespace {

// A tiny reader that fails cleanly on anything short, over-long or out of range.
struct Reader {
    const Bytes& d;
    size_t off = 0;
    bool ok = true;
    explicit Reader(const Bytes& data) : d(data) {}

    uint32_t u32() { auto v = read_u32(d.data(), d.size(), off); if (!v) { ok = false; return 0; } return *v; }
    uint64_t u64() { auto v = read_u64(d.data(), d.size(), off); if (!v) { ok = false; return 0; } return *v; }
    Bytes blob(size_t max, size_t exact = 0, bool allow_empty = false) {
        auto v = read_blob(d.data(), d.size(), off, max);
        if (!v) { ok = false; return {}; }
        if (exact && !(v->size() == exact || (allow_empty && v->empty()))) { ok = false; return {}; }
        return std::move(*v);
    }
    std::string text(size_t max = MAX_TEXT) {
        auto v = blob(max);
        return std::string(v.begin(), v.end());
    }
    // A count that can't be larger than the data left could hold (each entry is at least 4 bytes).
    uint32_t count(size_t max) {
        uint32_t n = u32();
        if (n > max || static_cast<size_t>(n) * 4 > d.size() - std::min(off, d.size())) ok = false;
        return ok ? n : 0;
    }
};

}  // namespace

std::optional<Contents> parse(const Bytes& data) {
    Reader r(data);
    auto label = read_string(data.data(), data.size(), r.off, 64);
    if (!label || *label != KEYRING_MAGIC_LABEL) return std::nullopt;
    if (r.u32() != VERSION || !r.ok) return std::nullopt;
    Contents c;
    uint32_t n = r.count(MAX_ARCHIVES);
    for (uint32_t i = 0; i < n && r.ok; i++) {
        ArchiveItem a;
        a.conversation_id = r.blob(32, 16);
        a.relay_address = r.text(255);
        a.relay_id = r.blob(32, 32);
        const uint32_t role = r.u32(), state = r.u32();
        a.role = static_cast<int>(role);
        a.state = static_cast<int>(state);
        a.archive_key = r.blob(32, 32);
        a.chat_public_key = r.blob(MAX_KEY_BLOB);
        a.chat_private_key = r.blob(MAX_KEY_BLOB);
        a.join_token = r.blob(32, 32, true);
        if (a.relay_address.empty() || a.chat_public_key.empty() || a.chat_private_key.empty() || (role != 1 && role != 2) || state > 2) r.ok = false;
        c.archives.push_back(std::move(a));
    }
    n = r.count(MAX_ENTRIES);
    for (uint32_t i = 0; i < n && r.ok; i++) c.verified.push_back(r.text(64));
    n = r.count(MAX_ENTRIES);
    for (uint32_t i = 0; i < n && r.ok; i++) {
        MemberToken t;
        t.conversation_id = r.blob(32, 16);
        t.member_fp = r.text(64);
        t.token = r.blob(32, 32);
        c.member_tokens.push_back(std::move(t));
    }
    n = r.count(MAX_ENTRIES);
    for (uint32_t i = 0; i < n && r.ok; i++) {
        Introduced x;
        x.fp = r.text(64);
        x.bundle = r.blob(MAX_BUNDLE);
        x.issued_at = static_cast<int64_t>(r.u64());
        x.introduced_by = r.text(64);
        x.first_seen = static_cast<int64_t>(r.u64());
        if (x.bundle.empty()) r.ok = false;
        c.introduced.push_back(std::move(x));
    }
    n = r.count(MAX_ENTRIES);
    for (uint32_t i = 0; i < n && r.ok; i++) {
        IssuedToken t;
        t.hash = r.blob(32, 32);
        t.label = r.text();
        t.created_at = static_cast<int64_t>(r.u64());
        t.bound_fp = r.text(64);
        const uint32_t revoked = r.u32();
        if (revoked > 1) r.ok = false;
        t.revoked = revoked == 1;
        c.issued_tokens.push_back(std::move(t));
    }
    n = r.count(MAX_ENTRIES);
    for (uint32_t i = 0; i < n && r.ok; i++) {
        Receipts x;
        x.conversation_id = r.blob(32, 16);
        const uint32_t flags = r.u32();
        if (flags > 3) r.ok = false;
        x.delivery = flags & 1;
        x.read = flags & 2;
        c.receipts.push_back(std::move(x));
    }
    if (!r.ok || r.off != data.size()) return std::nullopt;
    return c;
}

Bytes seal(const Bytes& key, const Bytes& mailbox_id, const Bytes& plaintext) {
    Bytes nonce = CryptoEngine::random_bytes(12);
    Bytes aad;
    write_string(aad, KEYRING_AAD_LABEL);
    write_blob(aad, mailbox_id);
    Bytes ct = CryptoEngine::encrypt(key, nonce, plaintext, aad);
    nonce.insert(nonce.end(), ct.begin(), ct.end());
    return nonce;
}

std::optional<Bytes> open(const Bytes& key, const Bytes& mailbox_id, const Bytes& sealed) {
    if (key.size() != 32 || sealed.size() < 12 + 16) return std::nullopt;
    Bytes nonce(sealed.begin(), sealed.begin() + 12), ct(sealed.begin() + 12, sealed.end());
    Bytes aad;
    write_string(aad, KEYRING_AAD_LABEL);
    write_blob(aad, mailbox_id);
    try {
        return CryptoEngine::decrypt(key, nonce, ct, aad);
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

}  // namespace keyring
