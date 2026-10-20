#include "archive.h"

#include <stdexcept>

#include "crypto_engine.h"
#include "protocol.h"

namespace archive {

namespace {

const char ENTRY_AAD_LABEL[] = "pq-suite v3 archive entry content";

Bytes entry_aad(const Bytes& archive_id, uint64_t number) {
    Bytes b;
    write_string(b, ENTRY_AAD_LABEL);
    write_blob(b, archive_id);
    write_u64(b, number);
    return b;
}

}  // namespace

Bytes genesis_hash(const Bytes& archive_id) { return CryptoEngine::sha256(relay::archive_genesis_input(archive_id)); }

Bytes entry_hash(const Bytes& archive_id, uint64_t number, const Bytes& previous_hash, const Bytes& blob) {
    return CryptoEngine::sha256(relay::archive_entry_hash_input(archive_id, number, previous_hash, blob));
}

Bytes seal_entry(const Bytes& archive_key, const Bytes& archive_id, uint64_t number, const Bytes& record) {
    if (archive_key.size() != KEY_BYTES) throw std::runtime_error("The archive key has the wrong size");
    if (record.empty() || record.size() > MAX_RECORD_BYTES) throw std::runtime_error("That record does not fit in an archive entry");
    Bytes nonce = CryptoEngine::random_bytes(NONCE_BYTES);
    Bytes ciphertext = CryptoEngine::encrypt(archive_key, nonce, record, entry_aad(archive_id, number));
    Bytes out = nonce;
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());
    return out;
}

std::optional<Bytes> open_entry(const Bytes& archive_key, const Bytes& archive_id, uint64_t number, const Bytes& blob) {
    if (archive_key.size() != KEY_BYTES || blob.size() < NONCE_BYTES + TAG_BYTES + 1) return std::nullopt;
    Bytes nonce(blob.begin(), blob.begin() + NONCE_BYTES), ciphertext(blob.begin() + NONCE_BYTES, blob.end());
    try {
        return CryptoEngine::decrypt(archive_key, nonce, ciphertext, entry_aad(archive_id, number));
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::optional<Head> verify_chain(const Bytes& archive_id, const Head& from, const std::vector<relay::ArchiveEntry>& entries) {
    Head head = from;
    for (const auto& e : entries) {
        if (e.number != head.number + 1) return std::nullopt;  // a gap, a repeat or an entry out of order
        if (e.hash != entry_hash(archive_id, e.number, head.hash, e.ciphertext)) return std::nullopt;
        head.number = e.number;
        head.hash = e.hash;
    }
    return head;
}

}  // namespace archive
