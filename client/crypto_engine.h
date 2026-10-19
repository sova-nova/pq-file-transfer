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

    static EncapResult encapsulate(const std::vector<uint8_t>& public_key);
    static std::vector<uint8_t> decapsulate(const std::vector<uint8_t>& ciphertext,
                                            const std::vector<uint8_t>& private_key);

    // HKDF-SHA256(ikm = shared_secret, salt = salt) → data key || metadata key.
    static SessionKeys derive_session_keys(const std::vector<uint8_t>& shared_secret,
                                           const std::vector<uint8_t>& salt);

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

    // Identity fingerprint: SHA-256 of an ML-DSA public key, 64 lowercase hex chars.
    static std::string fingerprint(const std::vector<uint8_t>& pub_dsa);
    // "abcd ef01 ..." for display and reading aloud.
    static std::string format_fingerprint(const std::string& fingerprint);
};
