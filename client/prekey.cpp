#include "prekey.h"

#include <stdexcept>

#include "crypto_engine.h"
#include "protocol.h"

namespace prekey {

namespace {

const char SIGN_LABEL[] = "pq-suite v3 prekey";

Bytes signing_input(const Prekey& p) {
    Bytes b;
    write_string(b, SIGN_LABEL);
    write_blob(b, p.id);
    write_blob(b, p.kem_public);
    write_blob(b, p.x25519_public);
    b.push_back(p.last_resort ? 1 : 0);
    write_u64(b, p.created_at);
    return b;
}

bool well_formed(const Prekey& p) {
    return p.id.size() == ID_BYTES && p.kem_public.size() == CryptoEngine::kem_public_key_size() && p.x25519_public.size() == X25519_BYTES &&
           !p.signature.empty() && p.signature.size() <= MAX_SIGNATURE_BYTES;
}

}  // namespace

Generated generate(const Bytes& identity_private_key, bool last_resort, uint64_t now) {
    Generated g;
    auto kem = CryptoEngine::generate_kem_keypair();
    auto x = CryptoEngine::generate_x25519();
    g.prekey.id = CryptoEngine::random_bytes(ID_BYTES);
    g.prekey.kem_public = kem.public_key;
    g.prekey.x25519_public = x.public_key;
    g.prekey.last_resort = last_resort;
    g.prekey.created_at = now;
    g.prekey.signature = CryptoEngine::sign(signing_input(g.prekey), identity_private_key);
    g.secret.kem_private = std::move(kem.private_key);
    g.secret.x25519_private = std::move(x.private_key);
    return g;
}

bool verify(const Prekey& prekey, const Bytes& identity_public_key) {
    if (!well_formed(prekey)) return false;
    try {
        return CryptoEngine::verify(signing_input(prekey), prekey.signature, identity_public_key);
    } catch (const std::exception&) {
        return false;
    }
}

Bytes encode(const Prekey& p) {
    if (!well_formed(p)) throw std::runtime_error("That prekey is not valid");
    Bytes b = signing_input(p);
    write_blob(b, p.signature);
    return b;
}

std::optional<Prekey> decode(const Bytes& data) {
    size_t off = 0;
    auto label = read_string(data.data(), data.size(), off, 64);
    auto id = read_blob(data.data(), data.size(), off, ID_BYTES);
    auto kem = read_blob(data.data(), data.size(), off, 4096);
    auto x = read_blob(data.data(), data.size(), off, X25519_BYTES);
    if (!label || *label != SIGN_LABEL || !id || !kem || !x || off >= data.size()) return std::nullopt;
    const uint8_t flag = data[off++];
    auto created = read_u64(data.data(), data.size(), off);
    auto sig = read_blob(data.data(), data.size(), off, MAX_SIGNATURE_BYTES);
    if (flag > 1 || !created || !sig || off != data.size()) return std::nullopt;
    Prekey p;
    p.id = std::move(*id);
    p.kem_public = std::move(*kem);
    p.x25519_public = std::move(*x);
    p.last_resort = flag == 1;
    p.created_at = *created;
    p.signature = std::move(*sig);
    if (!well_formed(p)) return std::nullopt;
    return p;
}

Bytes encode_secret(const Secret& s) {
    if (s.kem_private.size() != CryptoEngine::kem_secret_key_size() || s.x25519_private.size() != X25519_BYTES) throw std::runtime_error("That prekey secret is not valid");
    Bytes b;
    write_blob(b, s.kem_private);
    write_blob(b, s.x25519_private);
    return b;
}

std::optional<Secret> decode_secret(const Bytes& data) {
    size_t off = 0;
    auto kem = read_blob(data.data(), data.size(), off, 8192);
    auto x = read_blob(data.data(), data.size(), off, X25519_BYTES);
    if (!kem || !x || off != data.size() || kem->size() != CryptoEngine::kem_secret_key_size() || x->size() != X25519_BYTES) return std::nullopt;
    return Secret{std::move(*kem), std::move(*x)};
}

}  // namespace prekey
