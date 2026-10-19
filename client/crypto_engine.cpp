#include "crypto_engine.h"

#include <oqs/oqs.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include <climits>
#include <cstring>
#include <memory>
#include <stdexcept>

namespace {

using KEMPtr = std::unique_ptr<OQS_KEM, decltype(&OQS_KEM_free)>;
using SigPtr = std::unique_ptr<OQS_SIG, decltype(&OQS_SIG_free)>;
using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

// Domain-separated HKDF info string. Changing it changes every derived key.
const char HKDF_INFO[] = "pq-file-transfer v2 session keys";

// The algorithm objects only hold sizes and function pointers, so one shared
// instance each is safe to use from multiple threads.
const OQS_KEM* kem() {
    static KEMPtr instance = [] {
        OQS_KEM* k = OQS_KEM_new("ML-KEM-768");
        if (!k) throw std::runtime_error("ML-KEM-768 is not available in this liboqs build");
        return KEMPtr(k, &OQS_KEM_free);
    }();
    return instance.get();
}

const OQS_SIG* sig() {
    static SigPtr instance = [] {
        OQS_SIG* s = OQS_SIG_new("ML-DSA-65");
        if (!s) throw std::runtime_error("ML-DSA-65 is not available in this liboqs build");
        return SigPtr(s, &OQS_SIG_free);
    }();
    return instance.get();
}

void require_size(const std::vector<uint8_t>& v, size_t expected, const char* what) {
    if (v.size() != expected)
        throw std::runtime_error(std::string(what) + " has the wrong size");
}

CipherCtxPtr new_cipher_ctx() {
    CipherCtxPtr ctx(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
    if (!ctx) throw std::runtime_error("Failed to create AES context");
    return ctx;
}

void check_aead_inputs(const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce,
                       size_t data_len, size_t aad_len) {
    if (key.size() != CryptoEngine::AES_KEY_SIZE) throw std::runtime_error("AES key has the wrong size");
    if (nonce.size() != 12) throw std::runtime_error("AES-GCM nonce has the wrong size");
    if (data_len > INT_MAX || aad_len > INT_MAX) throw std::runtime_error("AES-GCM input too large");
}

}  // namespace

CryptoEngine::SessionKeys::~SessionKeys() {
    secure_wipe(data_key);
    secure_wipe(metadata_key);
}

size_t CryptoEngine::kem_public_key_size() { return kem()->length_public_key; }
size_t CryptoEngine::kem_secret_key_size() { return kem()->length_secret_key; }
size_t CryptoEngine::kem_ciphertext_size() { return kem()->length_ciphertext; }
size_t CryptoEngine::sig_public_key_size() { return sig()->length_public_key; }
size_t CryptoEngine::sig_secret_key_size() { return sig()->length_secret_key; }

CryptoEngine::KEMKeyPair CryptoEngine::generate_kem_keypair() {
    const OQS_KEM* k = kem();
    KEMKeyPair kp{std::vector<uint8_t>(k->length_public_key), std::vector<uint8_t>(k->length_secret_key)};
    if (OQS_KEM_keypair(k, kp.public_key.data(), kp.private_key.data()) != OQS_SUCCESS)
        throw std::runtime_error("ML-KEM-768 keypair generation failed");
    return kp;
}

CryptoEngine::SigKeyPair CryptoEngine::generate_sig_keypair() {
    const OQS_SIG* s = sig();
    SigKeyPair kp{std::vector<uint8_t>(s->length_public_key), std::vector<uint8_t>(s->length_secret_key)};
    if (OQS_SIG_keypair(s, kp.public_key.data(), kp.private_key.data()) != OQS_SUCCESS)
        throw std::runtime_error("ML-DSA-65 keypair generation failed");
    return kp;
}

CryptoEngine::EncapResult CryptoEngine::encapsulate(const std::vector<uint8_t>& public_key) {
    const OQS_KEM* k = kem();
    require_size(public_key, k->length_public_key, "Recipient's ML-KEM public key");

    EncapResult r{std::vector<uint8_t>(k->length_ciphertext), std::vector<uint8_t>(k->length_shared_secret)};
    if (OQS_KEM_encaps(k, r.ciphertext.data(), r.shared_secret.data(), public_key.data()) != OQS_SUCCESS)
        throw std::runtime_error("ML-KEM-768 encapsulation failed");
    return r;
}

std::vector<uint8_t> CryptoEngine::decapsulate(const std::vector<uint8_t>& ciphertext,
                                               const std::vector<uint8_t>& private_key) {
    const OQS_KEM* k = kem();
    require_size(ciphertext, k->length_ciphertext, "ML-KEM ciphertext");
    require_size(private_key, k->length_secret_key, "ML-KEM private key");

    std::vector<uint8_t> shared_secret(k->length_shared_secret);
    if (OQS_KEM_decaps(k, shared_secret.data(), ciphertext.data(), private_key.data()) != OQS_SUCCESS)
        throw std::runtime_error("ML-KEM-768 decapsulation failed");
    return shared_secret;
}

CryptoEngine::SessionKeys CryptoEngine::derive_session_keys(const std::vector<uint8_t>& shared_secret,
                                                            const std::vector<uint8_t>& salt) {
    if (shared_secret.empty() || salt.empty()) throw std::runtime_error("Invalid key derivation input");

    PkeyCtxPtr pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), &EVP_PKEY_CTX_free);
    if (!pctx ||
        EVP_PKEY_derive_init(pctx.get()) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx.get(), EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx.get(), salt.data(), static_cast<int>(salt.size())) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx.get(), shared_secret.data(), static_cast<int>(shared_secret.size())) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(pctx.get(), reinterpret_cast<const unsigned char*>(HKDF_INFO),
                                    static_cast<int>(sizeof(HKDF_INFO) - 1)) <= 0) {
        throw std::runtime_error("HKDF setup failed");
    }

    std::vector<uint8_t> okm(2 * AES_KEY_SIZE);
    size_t okm_len = okm.size();
    if (EVP_PKEY_derive(pctx.get(), okm.data(), &okm_len) <= 0 || okm_len != okm.size()) {
        secure_wipe(okm);
        throw std::runtime_error("HKDF derivation failed");
    }

    SessionKeys keys;
    keys.data_key.assign(okm.begin(), okm.begin() + AES_KEY_SIZE);
    keys.metadata_key.assign(okm.begin() + AES_KEY_SIZE, okm.end());
    secure_wipe(okm);
    return keys;
}

std::vector<uint8_t> CryptoEngine::hkdf_sha256(const std::vector<uint8_t>& ikm, const std::vector<uint8_t>& salt,
                                               const std::string& info, size_t length) {
    if (ikm.empty() || length == 0 || length > 255 * 32) throw std::runtime_error("Invalid key derivation input");
    static const uint8_t no_salt = 0;
    PkeyCtxPtr pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), &EVP_PKEY_CTX_free);
    if (!pctx ||
        EVP_PKEY_derive_init(pctx.get()) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx.get(), EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx.get(), salt.empty() ? &no_salt : salt.data(), static_cast<int>(salt.size())) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx.get(), ikm.data(), static_cast<int>(ikm.size())) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(pctx.get(), reinterpret_cast<const unsigned char*>(info.data()), static_cast<int>(info.size())) <= 0)
        throw std::runtime_error("HKDF setup failed");
    std::vector<uint8_t> out(length);
    size_t out_len = out.size();
    if (EVP_PKEY_derive(pctx.get(), out.data(), &out_len) <= 0 || out_len != out.size()) {
        secure_wipe(out);
        throw std::runtime_error("HKDF derivation failed");
    }
    return out;
}

std::vector<uint8_t> CryptoEngine::encrypt(const std::vector<uint8_t>& key,
                                           const std::vector<uint8_t>& nonce,
                                           const std::vector<uint8_t>& plaintext,
                                           const std::vector<uint8_t>& aad) {
    check_aead_inputs(key, nonce, plaintext.size(), aad.size());
    auto ctx = new_cipher_ctx();

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1)
        throw std::runtime_error("AES-GCM init failed");

    int len = 0;
    if (!aad.empty() &&
        EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1)
        throw std::runtime_error("AES-GCM AAD failed");

    std::vector<uint8_t> out(plaintext.size() + 16);
    int written = 0;
    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx.get(), out.data(), &len, plaintext.data(),
                              static_cast<int>(plaintext.size())) != 1)
            throw std::runtime_error("AES-GCM encrypt failed");
        written = len;
    }
    if (EVP_EncryptFinal_ex(ctx.get(), out.data() + written, &len) != 1)
        throw std::runtime_error("AES-GCM finalize failed");
    written += len;

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, out.data() + written) != 1)
        throw std::runtime_error("AES-GCM get tag failed");
    out.resize(static_cast<size_t>(written) + 16);
    return out;
}

std::optional<std::vector<uint8_t>> CryptoEngine::decrypt(const std::vector<uint8_t>& key,
                                                          const std::vector<uint8_t>& nonce,
                                                          const std::vector<uint8_t>& ciphertext,
                                                          const std::vector<uint8_t>& aad) {
    if (ciphertext.size() < 16) return std::nullopt;
    const size_t ct_len = ciphertext.size() - 16;
    check_aead_inputs(key, nonce, ct_len, aad.size());
    auto ctx = new_cipher_ctx();

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1)
        throw std::runtime_error("AES-GCM init failed");

    int len = 0;
    if (!aad.empty() &&
        EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1)
        throw std::runtime_error("AES-GCM AAD failed");

    std::vector<uint8_t> plaintext(ct_len + 16);  // slack for DecryptFinal's output pointer
    int written = 0;
    if (ct_len > 0) {
        if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, ciphertext.data(),
                              static_cast<int>(ct_len)) != 1)
            throw std::runtime_error("AES-GCM decrypt failed");
        written = len;
    }

    uint8_t tag[16];
    std::memcpy(tag, ciphertext.data() + ct_len, 16);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16, tag) != 1)
        throw std::runtime_error("AES-GCM set tag failed");

    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + written, &len) != 1) {
        secure_wipe(plaintext);  // never release unauthenticated plaintext
        return std::nullopt;
    }
    written += len;
    plaintext.resize(static_cast<size_t>(written));
    return plaintext;
}

std::vector<uint8_t> CryptoEngine::sign(const std::vector<uint8_t>& message,
                                        const std::vector<uint8_t>& private_key) {
    const OQS_SIG* s = sig();
    require_size(private_key, s->length_secret_key, "ML-DSA private key");

    std::vector<uint8_t> signature(s->length_signature);
    size_t sig_len = signature.size();
    if (OQS_SIG_sign(s, signature.data(), &sig_len, message.data(), message.size(),
                     private_key.data()) != OQS_SUCCESS)
        throw std::runtime_error("ML-DSA-65 signing failed");
    signature.resize(sig_len);
    return signature;
}

bool CryptoEngine::verify(const std::vector<uint8_t>& message,
                          const std::vector<uint8_t>& signature,
                          const std::vector<uint8_t>& public_key) {
    const OQS_SIG* s = sig();
    if (public_key.size() != s->length_public_key) return false;
    if (signature.empty() || signature.size() > s->length_signature) return false;
    return OQS_SIG_verify(s, message.data(), message.size(), signature.data(), signature.size(),
                          public_key.data()) == OQS_SUCCESS;
}

std::vector<uint8_t> CryptoEngine::sha256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> digest(32);
    unsigned int len = 0;
    if (EVP_Digest(data.data(), data.size(), digest.data(), &len, EVP_sha256(), nullptr) != 1 || len != 32)
        throw std::runtime_error("SHA-256 failed");
    return digest;
}

std::vector<uint8_t> CryptoEngine::random_bytes(size_t count) {
    std::vector<uint8_t> out(count);
    if (count > INT_MAX || (count > 0 && RAND_bytes(out.data(), static_cast<int>(count)) != 1))
        throw std::runtime_error("Secure random number generator failed");
    return out;
}

void CryptoEngine::secure_wipe(std::vector<uint8_t>& data) {
    if (!data.empty()) OPENSSL_cleanse(data.data(), data.size());
    data.clear();
}

// --- Passphrase protection of secret keys at rest ---

namespace {

constexpr char PROTECTED_MAGIC[4] = {'P', 'Q', 'K', 'E'};
constexpr uint8_t PROTECTED_VERSION = 1;
constexpr uint8_t KDF_SCRYPT = 1;
constexpr uint8_t SCRYPT_R = 8;
constexpr uint8_t SCRYPT_P = 1;
constexpr size_t PROTECTED_SALT_SIZE = 16;
constexpr size_t PROTECTED_NONCE_SIZE = 12;
constexpr size_t PROTECTED_HEADER_SIZE = 4 + 1 + 1 + 1 + 1 + 1 + PROTECTED_SALT_SIZE + PROTECTED_NONCE_SIZE;  // 37

std::vector<uint8_t> scrypt_key(const std::string& passphrase, const uint8_t* salt,
                                uint8_t log2_n, uint8_t r, uint8_t p) {
    const uint64_t n = 1ull << log2_n;
    // OpenSSL refuses to use more than `maxmem`; allow twice what scrypt really needs.
    const uint64_t maxmem = 256ull * n * r;
    std::vector<uint8_t> key(CryptoEngine::AES_KEY_SIZE);
    if (EVP_PBE_scrypt(passphrase.data(), passphrase.size(), salt, PROTECTED_SALT_SIZE, n, r, p, maxmem,
                       key.data(), key.size()) != 1)
        throw std::runtime_error("Key derivation (scrypt) failed");
    return key;
}

std::vector<uint8_t> protected_aad(const uint8_t* header, const std::string& label) {
    std::vector<uint8_t> aad(header, header + PROTECTED_HEADER_SIZE);
    aad.insert(aad.end(), label.begin(), label.end());
    return aad;
}

}  // namespace

bool CryptoEngine::is_protected_blob(const std::vector<uint8_t>& data) {
    return data.size() >= sizeof(PROTECTED_MAGIC) &&
           std::memcmp(data.data(), PROTECTED_MAGIC, sizeof(PROTECTED_MAGIC)) == 0;
}

std::vector<uint8_t> CryptoEngine::protect_secret(const std::vector<uint8_t>& secret,
                                                  const std::string& passphrase,
                                                  const std::string& label,
                                                  uint8_t scrypt_log2_n) {
    if (passphrase.empty()) throw std::runtime_error("The passphrase is empty");
    if (scrypt_log2_n < MIN_SCRYPT_LOG2_N || scrypt_log2_n > MAX_SCRYPT_LOG2_N)
        throw std::runtime_error("Key derivation cost is out of range");

    std::vector<uint8_t> blob(PROTECTED_MAGIC, PROTECTED_MAGIC + sizeof(PROTECTED_MAGIC));
    blob.push_back(PROTECTED_VERSION);
    blob.push_back(KDF_SCRYPT);
    blob.push_back(scrypt_log2_n);
    blob.push_back(SCRYPT_R);
    blob.push_back(SCRYPT_P);
    auto salt = random_bytes(PROTECTED_SALT_SIZE);
    auto nonce = random_bytes(PROTECTED_NONCE_SIZE);
    blob.insert(blob.end(), salt.begin(), salt.end());
    blob.insert(blob.end(), nonce.begin(), nonce.end());

    auto key = scrypt_key(passphrase, salt.data(), scrypt_log2_n, SCRYPT_R, SCRYPT_P);
    auto ciphertext = encrypt(key, nonce, secret, protected_aad(blob.data(), label));
    secure_wipe(key);
    blob.insert(blob.end(), ciphertext.begin(), ciphertext.end());
    return blob;
}

std::optional<std::vector<uint8_t>> CryptoEngine::unprotect_secret(const std::vector<uint8_t>& blob,
                                                                   const std::string& passphrase,
                                                                   const std::string& label) {
    if (!is_protected_blob(blob) || blob.size() < PROTECTED_HEADER_SIZE + 16)
        throw std::runtime_error("The protected key file is damaged");
    const uint8_t* h = blob.data();
    if (h[4] != PROTECTED_VERSION || h[5] != KDF_SCRYPT)
        throw std::runtime_error("The protected key file was made by an incompatible version");
    const uint8_t log2_n = h[6], r = h[7], p = h[8];
    if (log2_n < MIN_SCRYPT_LOG2_N || log2_n > MAX_SCRYPT_LOG2_N || r != SCRYPT_R || p != SCRYPT_P)
        throw std::runtime_error("The protected key file uses unsupported key derivation settings");
    if (passphrase.empty()) return std::nullopt;

    const uint8_t* salt = h + 9;
    const uint8_t* nonce_ptr = salt + PROTECTED_SALT_SIZE;
    std::vector<uint8_t> nonce(nonce_ptr, nonce_ptr + PROTECTED_NONCE_SIZE);
    std::vector<uint8_t> ciphertext(blob.begin() + PROTECTED_HEADER_SIZE, blob.end());

    auto key = scrypt_key(passphrase, salt, log2_n, r, p);
    auto plain = decrypt(key, nonce, ciphertext, protected_aad(h, label));
    secure_wipe(key);
    return plain;
}

std::string CryptoEngine::fingerprint(const std::vector<uint8_t>& pub_dsa) {
    static const char digits[] = "0123456789abcdef";
    auto digest = sha256(pub_dsa);
    std::string hex;
    for (uint8_t b : digest) {
        hex.push_back(digits[b >> 4]);
        hex.push_back(digits[b & 0x0F]);
    }
    return hex;
}

std::string CryptoEngine::format_fingerprint(const std::string& fp) {
    std::string out;
    for (size_t i = 0; i < fp.size(); i++) {
        if (i > 0 && i % 4 == 0) out.push_back(i % 32 == 0 ? '\n' : ' ');
        out.push_back(fp[i]);
    }
    return out;
}
