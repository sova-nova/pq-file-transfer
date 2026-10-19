#include "identity_bundle.h"

#include "crypto_engine.h"
#include "protocol.h"

#include <algorithm>
#include <stdexcept>

namespace {

constexpr uint32_t BUNDLE_MAGIC = 0x50514942;  // "PQIB"
constexpr uint32_t BUNDLE_VERSION = 1;
const char SIGNATURE_LABEL[] = "pq-suite v3 identity bundle";
constexpr size_t MAX_BODY_BYTES = 16 * 1024;
constexpr uint32_t MAX_FIELDS = 32;

std::vector<uint8_t> signing_input(const std::vector<uint8_t>& body) {
    std::vector<uint8_t> in;
    write_string(in, SIGNATURE_LABEL);
    write_bytes(in, body.data(), body.size());
    return in;
}

void write_field(std::vector<uint8_t>& body, uint32_t type, const std::vector<uint8_t>& value) {
    write_u32(body, type);
    write_blob(body, value);
}

void write_text_field(std::vector<uint8_t>& body, uint32_t type, const std::string& value) {
    write_field(body, type, std::vector<uint8_t>(value.begin(), value.end()));
}

}  // namespace

std::string IdentityBundle::fingerprint() const { return CryptoEngine::fingerprint(signing_key); }

std::vector<uint8_t> create_identity_bundle(const std::vector<uint8_t>& signing_public,
                                            const std::vector<uint8_t>& encryption_public,
                                            const std::string& display_name,
                                            const std::string& relay_hint,
                                            uint64_t issued_at,
                                            const std::vector<uint8_t>& signing_private) {
    if (signing_public.size() != CryptoEngine::sig_public_key_size() ||
        encryption_public.size() != CryptoEngine::kem_public_key_size())
        throw std::runtime_error("The identity keys have the wrong size");
    if (display_name.size() > IdentityBundle::MAX_DISPLAY_NAME_BYTES)
        throw std::runtime_error("The display name is too long");
    if (relay_hint.size() > IdentityBundle::MAX_RELAY_HINT_BYTES)
        throw std::runtime_error("The relay address is too long");

    uint32_t count = 2 + (display_name.empty() ? 0 : 1) + (relay_hint.empty() ? 0 : 1);
    std::vector<uint8_t> body;
    write_u32(body, BUNDLE_MAGIC);
    write_u32(body, BUNDLE_VERSION);
    write_u64(body, issued_at);
    write_u32(body, count);
    write_field(body, IdentityBundle::FIELD_SIGNING_KEY, signing_public);
    write_field(body, IdentityBundle::FIELD_ENCRYPTION_KEY, encryption_public);
    if (!display_name.empty()) write_text_field(body, IdentityBundle::FIELD_DISPLAY_NAME, display_name);
    if (!relay_hint.empty()) write_text_field(body, IdentityBundle::FIELD_RELAY_HINT, relay_hint);

    auto signature = CryptoEngine::sign(signing_input(body), signing_private);

    std::vector<uint8_t> raw;
    write_blob(raw, body);
    write_blob(raw, signature);
    return raw;
}

std::optional<IdentityBundle> parse_identity_bundle(const std::vector<uint8_t>& raw, std::string* error) {
    auto fail = [&](const char* msg) -> std::optional<IdentityBundle> {
        if (error) *error = msg;
        return std::nullopt;
    };

    size_t off = 0;
    auto body = read_blob(raw.data(), raw.size(), off, MAX_BODY_BYTES);
    auto signature = read_blob(raw.data(), raw.size(), off, 8192);
    if (!body || !signature || off != raw.size()) return fail("The identity bundle is malformed");

    size_t b = 0;
    auto magic = read_u32(body->data(), body->size(), b);
    auto version = read_u32(body->data(), body->size(), b);
    auto issued = read_u64(body->data(), body->size(), b);
    auto count = read_u32(body->data(), body->size(), b);
    if (!magic || *magic != BUNDLE_MAGIC) return fail("That is not an identity bundle");
    if (!version || *version != BUNDLE_VERSION) return fail("The identity bundle is from an incompatible version");
    if (!issued || !count || *count > MAX_FIELDS) return fail("The identity bundle is malformed");

    IdentityBundle bundle;
    bundle.issued_at = *issued;
    bool have_signing = false, have_encryption = false, have_name = false, have_hint = false;

    for (uint32_t i = 0; i < *count; i++) {
        auto type = read_u32(body->data(), body->size(), b);
        auto value = type ? read_blob(body->data(), body->size(), b, MAX_BODY_BYTES) : std::nullopt;
        if (!type || !value) return fail("The identity bundle is malformed");

        // A known field must not appear twice, or two readers could pick different ones.
        switch (*type) {
            case IdentityBundle::FIELD_SIGNING_KEY:
                if (have_signing) return fail("The identity bundle is malformed");
                have_signing = true;
                bundle.signing_key = std::move(*value);
                break;
            case IdentityBundle::FIELD_ENCRYPTION_KEY:
                if (have_encryption) return fail("The identity bundle is malformed");
                have_encryption = true;
                bundle.encryption_key = std::move(*value);
                break;
            case IdentityBundle::FIELD_DISPLAY_NAME:
                if (have_name || value->size() > IdentityBundle::MAX_DISPLAY_NAME_BYTES)
                    return fail("The identity bundle is malformed");
                have_name = true;
                bundle.display_name.assign(value->begin(), value->end());
                break;
            case IdentityBundle::FIELD_RELAY_HINT:
                if (have_hint || value->size() > IdentityBundle::MAX_RELAY_HINT_BYTES)
                    return fail("The identity bundle is malformed");
                have_hint = true;
                bundle.relay_hint.assign(value->begin(), value->end());
                break;
            default:
                break;  // a field from a newer version: ignored, but covered by the signature
        }
    }
    if (b != body->size()) return fail("The identity bundle is malformed");
    if (!have_signing || !have_encryption) return fail("The identity bundle is missing a key");
    if (bundle.signing_key.size() != CryptoEngine::sig_public_key_size() ||
        bundle.encryption_key.size() != CryptoEngine::kem_public_key_size())
        return fail("The keys in this bundle are not ML-DSA-65 / ML-KEM-768 public keys");

    if (!CryptoEngine::verify(signing_input(*body), *signature, bundle.signing_key))
        return fail("The signature on this identity bundle is not valid. It may have been altered.");

    bundle.raw = raw;
    return bundle;
}
