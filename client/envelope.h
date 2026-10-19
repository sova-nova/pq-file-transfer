#pragma once

#include <cstdint>
#include <optional>
#include <vector>

// The sealed envelope: what the relay stores and forwards. It is encrypted to exactly one
// recipient, and the sender's identity and signature are inside, so the relay learns neither.
//
//   envelope = header || blob(ciphertext)
//   header   = u32 version | blob kem_ciphertext | blob nonce
//   key      = HKDF-SHA256(ML-KEM shared secret, salt = SHA-256(header), info = "pq-suite v3 envelope key")
//   ciphertext = AES-256-GCM(key, nonce, padded plaintext, aad = "pq-suite v3 envelope" || header)
//   padded plaintext = u32 length || inner || zeros, padded up to 1, 4, 16 or 64 KiB
//   inner    = u32 version | blob sender_bundle (optional) | u32 count | blob signed_record x count
//
// Every envelope uses a fresh ML-KEM encapsulation, so its key is used exactly once. (Version 1
// has no forward secrecy and no X25519 hybrid; both arrive in a later milestone as version 2.)
namespace chat {

using Bytes = std::vector<uint8_t>;

constexpr size_t MAX_RECORDS_PER_ENVELOPE = 16;
constexpr size_t MAX_BUNDLE_BYTES = 16 * 1024;

struct Inner {
    Bytes sender_bundle;        // the sender's identity bundle, included on first contact; may be empty
    std::vector<Bytes> records; // signed records (message_record.h)
};

// Throws std::runtime_error if the contents don't fit in the largest size bucket.
Bytes seal_envelope(const Inner& inner, const Bytes& recipient_encryption_public_key);

// std::nullopt for anything that doesn't open: wrong recipient, damage, tampering. These are
// deliberately indistinguishable.
std::optional<Inner> open_envelope(const Bytes& envelope, const Bytes& my_encryption_private_key);

}  // namespace chat
