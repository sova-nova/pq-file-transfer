#include "crypto_engine.h"
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <stdexcept>
#include <memory>
#include <cstring>

using KEMPtr = std::unique_ptr<OQS_KEM, decltype(&OQS_KEM_free)>;
using SigPtr = std::unique_ptr<OQS_SIG, decltype(&OQS_SIG_free)>;
using EvpCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

static KEMPtr make_kem() {
    OQS_KEM* kem = OQS_KEM_new("ML-KEM-768");
    if (!kem) throw std::runtime_error("Failed to create ML-KEM-768");
    return KEMPtr(kem, &OQS_KEM_free);
}

static SigPtr make_sig() {
    OQS_SIG* sig = OQS_SIG_new("ML-DSA-65");
    if (!sig) throw std::runtime_error("Failed to create ML-DSA-65");
    return SigPtr(sig, &OQS_SIG_free);
}

CryptoEngine::KEMKeyPair CryptoEngine::generate_kem_keypair() {
    auto kem = make_kem();
    std::vector<uint8_t> pub(kem->length_public_key);
    std::vector<uint8_t> priv(kem->length_secret_key);

    if (OQS_KEM_keypair(kem.get(), pub.data(), priv.data()) != OQS_SUCCESS) {
        throw std::runtime_error("ML-KEM-768 keypair generation failed");
    }

    return {std::move(pub), std::move(priv)};
}

CryptoEngine::SigKeyPair CryptoEngine::generate_sig_keypair() {
    auto sig = make_sig();
    std::vector<uint8_t> pub(sig->length_public_key);
    std::vector<uint8_t> priv(sig->length_secret_key);

    if (OQS_SIG_keypair(sig.get(), pub.data(), priv.data()) != OQS_SUCCESS) {
        throw std::runtime_error("ML-DSA-65 keypair generation failed");
    }

    return {std::move(pub), std::move(priv)};
}

CryptoEngine::EncapResult CryptoEngine::encapsulate(const std::vector<uint8_t>& public_key) {
    auto kem = make_kem();

    std::vector<uint8_t> ciphertext(kem->length_ciphertext);
    std::vector<uint8_t> shared_secret(kem->length_shared_secret);

    if (OQS_KEM_encaps(kem.get(), ciphertext.data(), shared_secret.data(),
                        public_key.data()) != OQS_SUCCESS) {
        throw std::runtime_error("ML-KEM-768 encapsulation failed");
    }

    return {std::move(ciphertext), std::move(shared_secret)};
}

std::vector<uint8_t> CryptoEngine::decapsulate(const std::vector<uint8_t>& ciphertext,
                                                const std::vector<uint8_t>& private_key) {
    auto kem = make_kem();

    std::vector<uint8_t> shared_secret(kem->length_shared_secret);

    if (OQS_KEM_decaps(kem.get(), shared_secret.data(),
                        ciphertext.data(), private_key.data()) != OQS_SUCCESS) {
        throw std::runtime_error("ML-KEM-768 decapsulation failed");
    }

    return shared_secret;
}

std::vector<uint8_t> CryptoEngine::generate_aes_key(const std::vector<uint8_t>& shared_secret) {
    // Manual HKDF-Extract-then-Expand using HMAC-SHA256
    std::vector<uint8_t> key(32);
    const char* info_str = "pq-messenger";
    const unsigned char* info = reinterpret_cast<const unsigned char*>(info_str);

    // Step 1: HKDF-Extract — PRK = HMAC-SHA256(salt=zero, shared_secret)
    unsigned char prk[32];
    unsigned int prk_len = 0;
    unsigned char zero_salt[32] = {0};

    HMAC(EVP_sha256(), zero_salt, 32,
         shared_secret.data(), shared_secret.size(),
         prk, &prk_len);

    // Step 2: HKDF-Expand — OKM = HMAC-SHA256(PRK, info || 0x01)
    std::vector<uint8_t> t(info, info + 12);
    t.push_back(0x01);

    unsigned int okm_len = 0;
    HMAC(EVP_sha256(), prk, 32,
         t.data(), t.size(),
         key.data(), &okm_len);

    return key;
}

std::vector<uint8_t> CryptoEngine::encrypt_chunk(
    const std::vector<uint8_t>& aes_key,
    const std::vector<uint8_t>& plaintext,
    std::vector<uint8_t>& nonce)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create AES context");

    auto ctx_guard = EvpCtxPtr(ctx, &EVP_CIPHER_CTX_free);

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("AES-GCM init failed");

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1)
        throw std::runtime_error("AES-GCM set IV len failed");

    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, aes_key.data(), nonce.data()) != 1)
        throw std::runtime_error("AES-GCM set key/iv failed");

    std::vector<uint8_t> ciphertext(plaintext.size());
    int len = 0;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                           plaintext.data(), static_cast<int>(plaintext.size())) != 1)
        throw std::runtime_error("AES-GCM encrypt failed");

    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1)
        throw std::runtime_error("AES-GCM finalize failed");

    ciphertext_len += len;

    // Get the 16-byte authentication tag
    std::vector<uint8_t> tag(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1)
        throw std::runtime_error("AES-GCM get tag failed");

    // Append tag to ciphertext
    ciphertext.resize(ciphertext_len + 16);
    std::memcpy(ciphertext.data() + ciphertext_len, tag.data(), 16);

    return ciphertext;
}

std::vector<uint8_t> CryptoEngine::decrypt_chunk(
    const std::vector<uint8_t>& aes_key,
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& nonce)
{
    if (ciphertext.size() < 16)
        throw std::runtime_error("Ciphertext too short for AES-GCM tag");

    size_t ct_len = ciphertext.size() - 16;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create AES context");

    auto ctx_guard = EvpCtxPtr(ctx, &EVP_CIPHER_CTX_free);

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("AES-GCM init failed");

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1)
        throw std::runtime_error("AES-GCM set IV len failed");

    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, aes_key.data(), nonce.data()) != 1)
        throw std::runtime_error("AES-GCM set key/iv failed");

    std::vector<uint8_t> plaintext(ct_len);
    int len = 0;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                           ciphertext.data(), static_cast<int>(ct_len)) != 1)
        throw std::runtime_error("AES-GCM decrypt update failed");

    int plaintext_len = len;

    // Set the expected tag
    std::vector<uint8_t> tag(16);
    std::memcpy(tag.data(), ciphertext.data() + ct_len, 16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data()) != 1)
        throw std::runtime_error("AES-GCM set tag failed");

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1)
        throw std::runtime_error("AES-GCM authentication failed — data may be tampered");

    plaintext_len += len;
    plaintext.resize(plaintext_len);

    return plaintext;
}

std::vector<uint8_t> CryptoEngine::sign(
    const std::vector<uint8_t>& payload,
    const std::vector<uint8_t>& private_key)
{
    auto sig = make_sig();

    std::vector<uint8_t> signature(sig->length_signature);
    size_t sig_len = sig->length_signature;

    if (OQS_SIG_sign(sig.get(), signature.data(), &sig_len,
                      payload.data(), payload.size(),
                      private_key.data()) != OQS_SUCCESS) {
        throw std::runtime_error("ML-DSA-65 signing failed");
    }

    signature.resize(sig_len);
    return signature;
}

bool CryptoEngine::verify(
    const std::vector<uint8_t>& payload,
    const std::vector<uint8_t>& signature,
    const std::vector<uint8_t>& public_key)
{
    auto sig = make_sig();

    return OQS_SIG_verify(sig.get(), payload.data(), payload.size(),
                           signature.data(), signature.size(),
                           public_key.data()) == OQS_SUCCESS;
}