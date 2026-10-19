#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// A signed identity bundle: the public half of an identity, signed by its own signing key.
//
// It binds the encryption key (ML-KEM) to the signing key (ML-DSA). The fingerprint people
// compare is the SHA-256 of the signing key, so without this binding someone who alters a
// contact card in transit could keep the signing key, swap in their own encryption key, and
// still pass the fingerprint check. With it, any change to the encryption key breaks the
// signature.
//
// Wire format (all integers big-endian, blobs are u32 length + bytes):
//   bundle = blob(body) || blob(signature)
//   body   = u32 magic "PQIB" | u32 version | u64 issued_at | u32 field_count
//            | field_count x ( u32 type | blob(value) )
//   signature = ML-DSA-65 over  string("pq-suite v3 identity bundle") || body
//
// Fields are typed so later versions can add more (hybrid key, mailbox address, ...) without
// changing the format. A reader ignores types it doesn't know, and they are still covered by
// the signature because it is made over the exact body bytes.
//
// `issued_at` (unix seconds) doubles as the sequence number: a newer bundle from the same
// signing key replaces an older one.
struct IdentityBundle {
    // Field types. 4-6 are reserved for the X25519 key, relay ID and mailbox ID.
    static constexpr uint32_t FIELD_SIGNING_KEY = 1;
    static constexpr uint32_t FIELD_ENCRYPTION_KEY = 2;
    static constexpr uint32_t FIELD_DISPLAY_NAME = 3;
    static constexpr uint32_t FIELD_RELAY_HINT = 16;  // "host:port" suggestion, as in v1 cards

    static constexpr size_t MAX_DISPLAY_NAME_BYTES = 64;
    static constexpr size_t MAX_RELAY_HINT_BYTES = 255;

    uint64_t issued_at = 0;
    std::vector<uint8_t> signing_key;     // ML-DSA-65 public key
    std::vector<uint8_t> encryption_key;  // ML-KEM-768 public key
    std::string display_name;             // a suggestion only; untrusted text
    std::string relay_hint;               // a suggestion only; "" if none
    std::vector<uint8_t> raw;             // the exact bytes that were signed and sent

    // SHA-256 of the signing key, as lowercase hex (the same fingerprint as before).
    std::string fingerprint() const;
};

// Builds and signs a bundle. Throws std::runtime_error on bad input sizes or signing failure.
std::vector<uint8_t> create_identity_bundle(const std::vector<uint8_t>& signing_public,
                                            const std::vector<uint8_t>& encryption_public,
                                            const std::string& display_name,
                                            const std::string& relay_hint,
                                            uint64_t issued_at,
                                            const std::vector<uint8_t>& signing_private);

// Parses AND verifies a bundle: the signature must be valid under the signing key inside it,
// and both keys must have the right sizes. Returns std::nullopt otherwise, with a short
// reason in `error` if given.
std::optional<IdentityBundle> parse_identity_bundle(const std::vector<uint8_t>& raw,
                                                    std::string* error = nullptr);
