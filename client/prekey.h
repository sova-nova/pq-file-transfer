#pragma once

#include <cstdint>
#include <optional>
#include <vector>

// One-time prekeys (M6): what gives envelopes forward secrecy. A recipient makes many of these ahead of time, keeps the
// private halves, and gives the relay the public halves, each signed by their identity key. A sender takes one, uses it
// for one envelope, and the recipient deletes its private half once that envelope is safely stored: after that, even
// someone who later steals every long-term key can't open the envelope, because the part that was needed is gone.
// Each prekey holds an ML-KEM key and an X25519 key, so one-time security doesn't rest on either algorithm alone.
namespace prekey {

using Bytes = std::vector<uint8_t>;

constexpr size_t ID_BYTES = 16;
constexpr size_t X25519_BYTES = 32;
constexpr size_t MAX_SIGNATURE_BYTES = 8192;

// The public half: what the relay holds and a sender takes.
struct Prekey {
    Bytes id;             // ID_BYTES, random
    Bytes kem_public;     // ML-KEM-768 public key
    Bytes x25519_public;  // X25519_BYTES
    bool last_resort = false;  // the reusable one handed out when the one-time ones have run out (weaker: it is reused)
    uint64_t created_at = 0;
    Bytes signature;      // the owner's identity key over all of the above
};

// The private half, which never leaves the device it was made on and is not in any backup.
struct Secret {
    Bytes kem_private;
    Bytes x25519_private;
};

struct Generated {
    Prekey prekey;
    Secret secret;
};

// Makes a prekey and signs it with the owner's identity (signing) private key.
Generated generate(const Bytes& identity_private_key, bool last_resort, uint64_t now);
// True only if `prekey` is well formed and signed by the owner of `identity_public_key`: a relay can't make up or alter one.
bool verify(const Prekey& prekey, const Bytes& identity_public_key);

// Throws std::runtime_error if the prekey isn't well formed. decode returns nothing for anything that isn't, including
// extra or missing bytes.
Bytes encode(const Prekey& prekey);
std::optional<Prekey> decode(const Bytes& data);
Bytes encode_secret(const Secret& secret);
std::optional<Secret> decode_secret(const Bytes& data);

}  // namespace prekey
