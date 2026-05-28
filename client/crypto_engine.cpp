#include "crypto_engine.h"
#include <oqs/oqs.h>
#include <stdexcept>
#include <memory>

using KEMPtr = std::unique_ptr<OQS_KEM, decltype(&OQS_KEM_free)>;
using SigPtr = std::unique_ptr<OQS_SIG, decltype(&OQS_SIG_free)>;

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

std::vector<uint8_t> CryptoEngine::generate_aes_key(const std::vector<uint8_t>&) {
    // TODO: Phase 7 — HKDF-SHA256
    return {};
}

std::vector<uint8_t> CryptoEngine::encrypt_chunk(const std::vector<uint8_t>&,
                                                  const std::vector<uint8_t>&,
                                                  std::vector<uint8_t>&) {
    // TODO: Phase 7 — AES-256-GCM
    return {};
}

std::vector<uint8_t> CryptoEngine::decrypt_chunk(const std::vector<uint8_t>&,
                                                  const std::vector<uint8_t>&,
                                                  const std::vector<uint8_t>&) {
    // TODO: Phase 7 — AES-256-GCM
    return {};
}

std::vector<uint8_t> CryptoEngine::sign(const std::vector<uint8_t>&,
                                         const std::vector<uint8_t>&) {
    // TODO: Phase 7 — ML-DSA-65
    return {};
}

bool CryptoEngine::verify(const std::vector<uint8_t>&,
                           const std::vector<uint8_t>&,
                           const std::vector<uint8_t>&) {
    // TODO: Phase 7 — ML-DSA-65
    return false;
}