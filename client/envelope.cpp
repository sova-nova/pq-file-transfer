#include "envelope.h"

#include "crypto_engine.h"
#include "protocol.h"
#include "relay_protocol.h"

#include <algorithm>
#include <stdexcept>

namespace chat {

namespace {

constexpr uint32_t ENVELOPE_VERSION = 1;
constexpr uint32_t INNER_VERSION = 2;      // what is written
constexpr uint32_t MIN_INNER_VERSION = 1;  // the oldest still read
const char ENVELOPE_AAD_LABEL[] = "pq-suite v3 envelope";
const char ENVELOPE_KEY_INFO[] = "pq-suite v3 envelope key";
const size_t BUCKETS[] = {1024, 4096, 16384, 65536};

Bytes header_bytes(const Bytes& kem_ciphertext, const Bytes& nonce) {
    Bytes h;
    write_u32(h, ENVELOPE_VERSION);
    write_blob(h, kem_ciphertext);
    write_blob(h, nonce);
    return h;
}

Bytes aad_for(const Bytes& header) {
    Bytes a;
    write_string(a, ENVELOPE_AAD_LABEL);
    write_bytes(a, header.data(), header.size());
    return a;
}

Bytes derive_key(const Bytes& shared_secret, const Bytes& header) {
    return CryptoEngine::hkdf_sha256(shared_secret, CryptoEngine::sha256(header), ENVELOPE_KEY_INFO, 32);
}

}  // namespace

Bytes encode_inner(const Inner& inner) {
    if (inner.sender_bundle.size() > MAX_BUNDLE_BYTES) throw std::runtime_error("The sender bundle is too large");
    if (inner.introduced.size() > MAX_INTRODUCED_PER_ENVELOPE) throw std::runtime_error("Too many introduced bundles in one envelope");
    for (const auto& bundle : inner.introduced)
        if (bundle.size() > MAX_BUNDLE_BYTES) throw std::runtime_error("An introduced bundle is too large");
    if (inner.records.size() > MAX_RECORDS_PER_ENVELOPE) throw std::runtime_error("Too many records in one envelope");
    Bytes b;
    write_u32(b, INNER_VERSION);
    write_blob(b, inner.sender_bundle);
    write_u32(b, static_cast<uint32_t>(inner.introduced.size()));
    for (const auto& bundle : inner.introduced) write_blob(b, bundle);
    write_u32(b, static_cast<uint32_t>(inner.records.size()));
    for (const auto& r : inner.records) write_blob(b, r);
    return b;
}

std::optional<Inner> decode_inner(const Bytes& b) {
    size_t off = 0;
    auto version = read_u32(b.data(), b.size(), off);
    if (!version || *version < MIN_INNER_VERSION || *version > INNER_VERSION) return std::nullopt;
    auto bundle = read_blob(b.data(), b.size(), off, MAX_BUNDLE_BYTES);
    if (!bundle) return std::nullopt;
    Inner inner;
    inner.sender_bundle = std::move(*bundle);
    if (*version >= 2) {
        auto introduced = read_u32(b.data(), b.size(), off);
        if (!introduced || *introduced > MAX_INTRODUCED_PER_ENVELOPE) return std::nullopt;
        for (uint32_t i = 0; i < *introduced; i++) {
            auto other = read_blob(b.data(), b.size(), off, MAX_BUNDLE_BYTES);
            if (!other) return std::nullopt;
            inner.introduced.push_back(std::move(*other));
        }
    }
    auto count = read_u32(b.data(), b.size(), off);
    if (!count || *count > MAX_RECORDS_PER_ENVELOPE) return std::nullopt;
    for (uint32_t i = 0; i < *count; i++) {
        auto record = read_blob(b.data(), b.size(), off, 64 * 1024);
        if (!record) return std::nullopt;
        inner.records.push_back(std::move(*record));
    }
    if (off != b.size()) return std::nullopt;
    return inner;
}

Bytes seal_envelope(const Inner& inner, const Bytes& recipient_public_key) {
    Bytes encoded = encode_inner(inner);
    const size_t needed = 4 + encoded.size();
    size_t bucket = 0;
    for (size_t size : BUCKETS)
        if (needed <= size) { bucket = size; break; }
    if (bucket == 0) throw std::runtime_error("That message is too large to send");

    Bytes plaintext;
    plaintext.reserve(bucket);
    write_u32(plaintext, static_cast<uint32_t>(encoded.size()));
    write_bytes(plaintext, encoded.data(), encoded.size());
    plaintext.resize(bucket, 0);

    auto encap = CryptoEngine::encapsulate(recipient_public_key);
    Bytes nonce = CryptoEngine::random_bytes(12);
    Bytes header = header_bytes(encap.ciphertext, nonce);
    Bytes key = derive_key(encap.shared_secret, header);
    CryptoEngine::secure_wipe(encap.shared_secret);
    Bytes ciphertext = CryptoEngine::encrypt(key, nonce, plaintext, aad_for(header));
    CryptoEngine::secure_wipe(key);

    Bytes envelope = header;
    write_blob(envelope, ciphertext);
    if (envelope.size() > relay::MAX_ENVELOPE_BYTES) throw std::runtime_error("That message is too large to send");
    return envelope;
}

std::optional<Inner> open_envelope(const Bytes& envelope, const Bytes& my_private_key) {
    size_t off = 0;
    auto version = read_u32(envelope.data(), envelope.size(), off);
    auto kem_ct = read_blob(envelope.data(), envelope.size(), off, 4096);
    auto nonce = read_blob(envelope.data(), envelope.size(), off, 12);
    if (!version || *version != ENVELOPE_VERSION || !kem_ct || !nonce || nonce->size() != 12 ||
        kem_ct->size() != CryptoEngine::kem_ciphertext_size())
        return std::nullopt;
    const Bytes header(envelope.begin(), envelope.begin() + static_cast<std::ptrdiff_t>(off));
    auto ciphertext = read_blob(envelope.data(), envelope.size(), off, relay::MAX_ENVELOPE_BYTES);
    if (!ciphertext || off != envelope.size()) return std::nullopt;

    Bytes shared;
    try {
        shared = CryptoEngine::decapsulate(*kem_ct, my_private_key);
    } catch (const std::exception&) {
        return std::nullopt;
    }
    Bytes key = derive_key(shared, header);
    CryptoEngine::secure_wipe(shared);
    std::optional<Bytes> plaintext;
    try {
        plaintext = CryptoEngine::decrypt(key, *nonce, *ciphertext, aad_for(header));
    } catch (const std::exception&) {
        plaintext.reset();
    }
    CryptoEngine::secure_wipe(key);
    if (!plaintext) return std::nullopt;

    const Bytes& p = *plaintext;
    if (std::find(std::begin(BUCKETS), std::end(BUCKETS), p.size()) == std::end(BUCKETS)) return std::nullopt;
    size_t po = 0;
    auto length = read_u32(p.data(), p.size(), po);
    if (!length || *length > p.size() - po) return std::nullopt;
    for (size_t i = po + *length; i < p.size(); i++)
        if (p[i] != 0) return std::nullopt;  // padding is all zeros
    return decode_inner(Bytes(p.begin() + static_cast<std::ptrdiff_t>(po), p.begin() + static_cast<std::ptrdiff_t>(po + *length)));
}

}  // namespace chat
