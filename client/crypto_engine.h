#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// Stateless wrappers around liboqs (ML-KEM-768, ML-DSA-65) and OpenSSL
// (AES-256-GCM, HKDF-SHA256, SHA-256, CSPRNG). All functions validate input
// sizes and throw std::runtime_error on library failures.
class CryptoEngine {
public:
    static constexpr size_t AES_KEY_SIZE = 32;

    struct KEMKeyPair {
        std::vector<uint8_t> public_key;
        std::vector<uint8_t> private_key;
    };

    struct SigKeyPair {
        std::vector<uint8_t> public_key;
        std::vector<uint8_t> private_key;
    };

    struct EncapResult {
        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> shared_secret;
    };

    // Two independent keys for one transfer; wiped from memory on destruction.
    struct SessionKeys {
        std::vector<uint8_t> data_key;      // encrypts file chunks
        std::vector<uint8_t> metadata_key;  // encrypts the sealed metadata

        SessionKeys() = default;
        SessionKeys(SessionKeys&&) = default;
        SessionKeys& operator=(SessionKeys&&) = default;
        SessionKeys(const SessionKeys&) = delete;
        SessionKeys& operator=(const SessionKeys&) = delete;
        ~SessionKeys();
    };

    // Expected sizes, used to validate key files and network input.
    static size_t kem_public_key_size();
    static size_t kem_secret_key_size();
    static size_t kem_ciphertext_size();
    static size_t sig_public_key_size();
    static size_t sig_secret_key_size();

    static KEMKeyPair generate_kem_keypair();
    static SigKeyPair generate_sig_keypair();

    // X25519 (RFC 7748), used alongside ML-KEM so that nothing rests on one algorithm.
    struct X25519KeyPair {
        std::vector<uint8_t> public_key;
        std::vector<uint8_t> private_key;
    };
    static X25519KeyPair generate_x25519();
    // The shared secret between our private key and their public key. Throws if either has the wrong size or the result is
    // the all-zero value that a low-order public key forces.
    static std::vector<uint8_t> x25519_shared(const std::vector<uint8_t>& private_key, const std::vector<uint8_t>& peer_public_key);

    static EncapResult encapsulate(const std::vector<uint8_t>& public_key);
    static std::vector<uint8_t> decapsulate(const std::vector<uint8_t>& ciphertext,
                                            const std::vector<uint8_t>& private_key);

    // HKDF-SHA256(ikm = shared_secret, salt = salt) → data key || metadata key.
    static SessionKeys derive_session_keys(const std::vector<uint8_t>& shared_secret,
                                           const std::vector<uint8_t>& salt);

    // General HKDF-SHA256. `info` is a label separating different uses of the same input key.
    static std::vector<uint8_t> hkdf_sha256(const std::vector<uint8_t>& ikm,
                                            const std::vector<uint8_t>& salt,
                                            const std::string& info,
                                            size_t length);

    // AES-256-GCM. Output is ciphertext || 16-byte tag.
    static std::vector<uint8_t> encrypt(const std::vector<uint8_t>& key,
                                        const std::vector<uint8_t>& nonce,
                                        const std::vector<uint8_t>& plaintext,
                                        const std::vector<uint8_t>& aad);

    // Returns std::nullopt if authentication fails (wrong key or tampering).
    static std::optional<std::vector<uint8_t>> decrypt(const std::vector<uint8_t>& key,
                                                       const std::vector<uint8_t>& nonce,
                                                       const std::vector<uint8_t>& ciphertext,
                                                       const std::vector<uint8_t>& aad);

    static std::vector<uint8_t> sign(const std::vector<uint8_t>& message,
                                     const std::vector<uint8_t>& private_key);

    // Returns false for invalid signatures and for malformed inputs.
    static bool verify(const std::vector<uint8_t>& message,
                       const std::vector<uint8_t>& signature,
                       const std::vector<uint8_t>& public_key);

    static std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> random_bytes(size_t count);
    static void secure_wipe(std::vector<uint8_t>& data);

    // --- Passphrase protection of secret keys at rest ---
    //
    // Blob layout (all fixed-size header fields are authenticated as AES-GCM AAD):
    //   "PQKE" | version=1 | kdf=1 (scrypt) | log2(N) | r | p | salt[16] | nonce[12] | ciphertext || tag
    // The key is scrypt(passphrase, salt). `label` ("private_kem" / "private_dsa") is also
    // authenticated, so one protected key file can't be passed off as another.
    static constexpr uint8_t DEFAULT_SCRYPT_LOG2_N = 17;  // 128 MiB, ~0.3 s on a desktop
    static constexpr uint8_t MIN_SCRYPT_LOG2_N = 10;      // accepted when reading (tests use this)
    static constexpr uint8_t MAX_SCRYPT_LOG2_N = 18;      // refuse absurd memory demands from a file

    // True if `data` starts with the protected-key magic.
    static bool is_protected_blob(const std::vector<uint8_t>& data);

    // Throws std::runtime_error if the passphrase is empty or the KDF cost is out of range.
    static std::vector<uint8_t> protect_secret(const std::vector<uint8_t>& secret,
                                               const std::string& passphrase,
                                               const std::string& label,
                                               uint8_t scrypt_log2_n = DEFAULT_SCRYPT_LOG2_N);

    // Returns std::nullopt for a wrong passphrase, wrong label or any tampering (these are
    // indistinguishable by design). Throws std::runtime_error for blobs that are malformed
    // or use unsupported parameters.
    static std::optional<std::vector<uint8_t>> unprotect_secret(const std::vector<uint8_t>& blob,
                                                                const std::string& passphrase,
                                                                const std::string& label);

    // Identity fingerprint: SHA-256 of an ML-DSA public key, 64 lowercase hex chars.
    static std::string fingerprint(const std::vector<uint8_t>& pub_dsa);
    // "abcd ef01 ..." for display and reading aloud.
    static std::string format_fingerprint(const std::string& fingerprint);
};
