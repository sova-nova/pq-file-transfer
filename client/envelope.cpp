#include "envelope.h"

#include "crypto_engine.h"
#include "protocol.h"
#include "relay_protocol.h"

#include <algorithm>
#include <stdexcept>

namespace chat {

namespace {

constexpr uint32_t ENVELOPE_VERSION = 1;     // long-term key only
constexpr uint32_t ENVELOPE_VERSION_2 = 2;   // with a one-time prekey and X25519
constexpr uint32_t INNER_VERSION = 3;      // the newest understood; encode_inner writes 2 unless there are attachment grants
constexpr uint32_t MIN_INNER_VERSION = 1;  // the oldest still read
const char ENVELOPE_AAD_LABEL[] = "pq-suite v3 envelope";
const char ENVELOPE_KEY_INFO[] = "pq-suite v3 envelope key";
const char ENVELOPE_KEY_INFO_2[] = "pq-suite v3 envelope key v2";
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

// Version 2: the prekey's ID, its ML-KEM ciphertext, and the sender's one-time X25519 public key are all in the header, which is
// authenticated and also feeds the key, so none of them can be changed.
Bytes header_bytes_2(const Bytes& kem_ciphertext, const Bytes& prekey_id, const Bytes& prekey_ciphertext, const Bytes& ephemeral_public, const Bytes& nonce) {
    Bytes h;
    write_u32(h, ENVELOPE_VERSION_2);
    write_blob(h, kem_ciphertext);
    write_blob(h, prekey_id);
    write_blob(h, prekey_ciphertext);
    write_blob(h, ephemeral_public);
    write_blob(h, nonce);
    return h;
}

Bytes derive_key_2(const Bytes& long_term, const Bytes& prekey_secret, const Bytes& x25519_secret, const Bytes& header) {
    Bytes ikm = long_term;
    ikm.insert(ikm.end(), prekey_secret.begin(), prekey_secret.end());
    ikm.insert(ikm.end(), x25519_secret.begin(), x25519_secret.end());
    Bytes key = CryptoEngine::hkdf_sha256(ikm, CryptoEngine::sha256(header), ENVELOPE_KEY_INFO_2, 32);
    CryptoEngine::secure_wipe(ikm);
    return key;
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
    if (inner.grants.size() > MAX_GRANTS_PER_ENVELOPE) throw std::runtime_error("Too many attachment grants in one envelope");
    for (size_t i = 0; i < inner.grants.size(); i++) {
        const auto& g = inner.grants[i];
        if (g.file_id.size() != 16 || g.key.size() != 32 || g.token.size() != 32) throw std::runtime_error("An attachment grant is not valid");
        for (size_t j = 0; j < i; j++)
            if (inner.grants[j].file_id == g.file_id) throw std::runtime_error("Two attachment grants name the same file");
    }
    Bytes b;
    write_u32(b, inner.grants.empty() ? 2u : 3u);
    write_blob(b, inner.sender_bundle);
    write_u32(b, static_cast<uint32_t>(inner.introduced.size()));
    for (const auto& bundle : inner.introduced) write_blob(b, bundle);
    if (!inner.grants.empty()) {
        write_u32(b, static_cast<uint32_t>(inner.grants.size()));
        for (const auto& g : inner.grants) {
            write_blob(b, g.file_id);
            write_blob(b, g.key);
            write_blob(b, g.token);
        }
    }
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
    if (*version >= 3) {
        auto grants = read_u32(b.data(), b.size(), off);
        if (!grants || *grants < 1 || *grants > MAX_GRANTS_PER_ENVELOPE) return std::nullopt;  // version 3 means there are some
        for (uint32_t i = 0; i < *grants; i++) {
            auto id = read_blob(b.data(), b.size(), off, 16);
            auto key = read_blob(b.data(), b.size(), off, 32);
            auto token = read_blob(b.data(), b.size(), off, 32);
            if (!id || !key || !token || id->size() != 16 || key->size() != 32 || token->size() != 32) return std::nullopt;
            for (const auto& other : inner.grants)
                if (other.file_id == *id) return std::nullopt;
            inner.grants.push_back({std::move(*id), std::move(*key), std::move(*token)});
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

Bytes seal_envelope(const Inner& inner, const Bytes& recipient_public_key, const prekey::Prekey* prekey) {
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
    Bytes header, key;
    if (prekey) {
        if (prekey->id.size() != prekey::ID_BYTES || prekey->kem_public.size() != CryptoEngine::kem_public_key_size() || prekey->x25519_public.size() != prekey::X25519_BYTES)
            throw std::runtime_error("That prekey is not valid");
        auto one_time = CryptoEngine::encapsulate(prekey->kem_public);
        auto ephemeral = CryptoEngine::generate_x25519();
        Bytes x = CryptoEngine::x25519_shared(ephemeral.private_key, prekey->x25519_public);
        header = header_bytes_2(encap.ciphertext, prekey->id, one_time.ciphertext, ephemeral.public_key, nonce);
        key = derive_key_2(encap.shared_secret, one_time.shared_secret, x, header);
        CryptoEngine::secure_wipe(one_time.shared_secret);
        CryptoEngine::secure_wipe(x);
        CryptoEngine::secure_wipe(ephemeral.private_key);  // the sender can't open it again either: that is the point
    } else {
        header = header_bytes(encap.ciphertext, nonce);
        key = derive_key(encap.shared_secret, header);
    }
    CryptoEngine::secure_wipe(encap.shared_secret);
    Bytes ciphertext = CryptoEngine::encrypt(key, nonce, plaintext, aad_for(header));
    CryptoEngine::secure_wipe(key);

    Bytes envelope = header;
    write_blob(envelope, ciphertext);
    if (envelope.size() > relay::MAX_ENVELOPE_BYTES) throw std::runtime_error("That message is too large to send");
    return envelope;
}

std::optional<Bytes> envelope_prekey_id(const Bytes& envelope) {
    size_t off = 0;
    auto version = read_u32(envelope.data(), envelope.size(), off);
    if (!version || *version != ENVELOPE_VERSION_2) return std::nullopt;
    auto kem_ct = read_blob(envelope.data(), envelope.size(), off, 4096);
    auto id = read_blob(envelope.data(), envelope.size(), off, prekey::ID_BYTES);
    if (!kem_ct || !id || id->size() != prekey::ID_BYTES) return std::nullopt;
    return id;
}

std::optional<Inner> open_envelope(const Bytes& envelope, const Bytes& my_private_key, const PrekeyLookup& lookup, Bytes* used_prekey_id) {
    size_t off = 0;
    auto version = read_u32(envelope.data(), envelope.size(), off);
    if (!version || (*version != ENVELOPE_VERSION && *version != ENVELOPE_VERSION_2)) return std::nullopt;
    auto kem_ct = read_blob(envelope.data(), envelope.size(), off, 4096);
    if (!kem_ct || kem_ct->size() != CryptoEngine::kem_ciphertext_size()) return std::nullopt;
    std::optional<Bytes> prekey_id, prekey_ct, ephemeral;
    if (*version == ENVELOPE_VERSION_2) {
        prekey_id = read_blob(envelope.data(), envelope.size(), off, prekey::ID_BYTES);
        prekey_ct = read_blob(envelope.data(), envelope.size(), off, 4096);
        ephemeral = read_blob(envelope.data(), envelope.size(), off, prekey::X25519_BYTES);
        if (!prekey_id || prekey_id->size() != prekey::ID_BYTES || !prekey_ct || prekey_ct->size() != CryptoEngine::kem_ciphertext_size() || !ephemeral ||
            ephemeral->size() != prekey::X25519_BYTES)
            return std::nullopt;
    }
    auto nonce = read_blob(envelope.data(), envelope.size(), off, 12);
    if (!nonce || nonce->size() != 12) return std::nullopt;
    const Bytes header(envelope.begin(), envelope.begin() + static_cast<std::ptrdiff_t>(off));
    auto ciphertext = read_blob(envelope.data(), envelope.size(), off, relay::MAX_ENVELOPE_BYTES);
    if (!ciphertext || off != envelope.size()) return std::nullopt;

    Bytes key;
    try {
        Bytes shared = CryptoEngine::decapsulate(*kem_ct, my_private_key);
        if (*version == ENVELOPE_VERSION_2) {
            // The one-time half: without the prekey's private key (deleted after use) there is no way in.
            auto secret = lookup ? lookup(*prekey_id) : std::nullopt;
            if (!secret) {
                CryptoEngine::secure_wipe(shared);
                return std::nullopt;
            }
            Bytes one_time = CryptoEngine::decapsulate(*prekey_ct, secret->kem_private);
            Bytes x = CryptoEngine::x25519_shared(secret->x25519_private, *ephemeral);
            key = derive_key_2(shared, one_time, x, header);
            CryptoEngine::secure_wipe(one_time);
            CryptoEngine::secure_wipe(x);
        } else {
            key = derive_key(shared, header);
        }
        CryptoEngine::secure_wipe(shared);
    } catch (const std::exception&) {
        return std::nullopt;
    }
    std::optional<Bytes> plaintext;
    try {
        plaintext = CryptoEngine::decrypt(key, *nonce, *ciphertext, aad_for(header));
    } catch (const std::exception&) {
        plaintext.reset();
    }
    CryptoEngine::secure_wipe(key);
    if (!plaintext) return std::nullopt;
    if (used_prekey_id && prekey_id) *used_prekey_id = *prekey_id;

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
