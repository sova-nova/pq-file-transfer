#pragma once

#include <vector>
#include <cstdint>

class CryptoEngine {
public:
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

    CryptoEngine() = default;

    KEMKeyPair generate_kem_keypair();
    SigKeyPair generate_sig_keypair();

    EncapResult encapsulate(const std::vector<uint8_t>& public_key);
    std::vector<uint8_t> decapsulate(const std::vector<uint8_t>& ciphertext,
                                      const std::vector<uint8_t>& private_key);

    std::vector<uint8_t> generate_aes_key(const std::vector<uint8_t>& shared_secret);

    std::vector<uint8_t> encrypt_chunk(const std::vector<uint8_t>& aes_key,
                                        const std::vector<uint8_t>& plaintext,
                                        std::vector<uint8_t>& nonce);

    std::vector<uint8_t> decrypt_chunk(const std::vector<uint8_t>& aes_key,
                                        const std::vector<uint8_t>& ciphertext,
                                        const std::vector<uint8_t>& nonce);

    std::vector<uint8_t> sign(const std::vector<uint8_t>& payload,
                               const std::vector<uint8_t>& private_key);

    bool verify(const std::vector<uint8_t>& payload,
                const std::vector<uint8_t>& signature,
                const std::vector<uint8_t>& public_key);
};