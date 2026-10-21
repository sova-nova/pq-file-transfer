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
//   inner    = u32 version | blob sender_bundle (optional) | introduced | u32 count | blob signed_record x count
//   introduced (version 2) = u32 count | blob identity_bundle x count      (version 1 has none)
//
// `introduced` carries other people's self-signed identity bundles, which is how the creator of
// a group tells each member the others' keys. A bundle is about 6.5 KB, so an envelope holds
// only about 8 of them next to a creation record; the sender splits longer lists across envelopes.
// Inner version 2 is written; version 1 (the first one-to-one chats) is still read.
//
// Every envelope uses a fresh ML-KEM encapsulation, so its key is used exactly once. (Version 1
// has no forward secrecy and no X25519 hybrid; both arrive in a later milestone as version 2.)
namespace chat {

using Bytes = std::vector<uint8_t>;

constexpr size_t MAX_RECORDS_PER_ENVELOPE = 16;
constexpr size_t MAX_BUNDLE_BYTES = 16 * 1024;
constexpr size_t MAX_INTRODUCED_PER_ENVELOPE = 15;  // the other members of a 16-person group

// What one recipient needs to fetch and open one attachment: the file's ID, the key it is encrypted under, and
// that recipient's own one-time download token. Sealed in the recipient's own envelope and nowhere else: the
// message record the whole chat sees (and the archive keeps) holds none of it.
constexpr size_t MAX_GRANTS_PER_ENVELOPE = 4;
struct AttachmentGrant {
    Bytes file_id;  // 16 bytes
    Bytes key;      // 32 bytes
    Bytes token;    // 32 bytes
};

struct Inner {
    Bytes sender_bundle;         // the sender's identity bundle, included on first contact; may be empty
    std::vector<Bytes> records;  // signed records (message_record.h)
    // Other people's identity bundles (self-signed; check them before use). Declared last, with an
    // initializer, so code that builds an Inner as {sender_bundle, records} keeps its meaning.
    std::vector<Bytes> introduced{};
    // File keys and tokens for the attachments among `records` (up to MAX_GRANTS_PER_ENVELOPE). Written only when
    // there are some, as inner version 3: an envelope without any is exactly what it always was.
    std::vector<AttachmentGrant> grants{};
};

// The unpadded inner content, exposed so the format can be tested directly.
// encode_inner throws std::runtime_error if a limit is exceeded; decode_inner returns
// std::nullopt for anything malformed, including trailing bytes.
Bytes encode_inner(const Inner& inner);
std::optional<Inner> decode_inner(const Bytes& encoded);

// Throws std::runtime_error if the contents don't fit in the largest size bucket.
Bytes seal_envelope(const Inner& inner, const Bytes& recipient_encryption_public_key);

// std::nullopt for anything that doesn't open: wrong recipient, damage, tampering. These are
// deliberately indistinguishable.
std::optional<Inner> open_envelope(const Bytes& envelope, const Bytes& my_encryption_private_key);

}  // namespace chat
