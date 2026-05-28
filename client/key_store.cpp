#include "key_store.h"
#include <filesystem>
#include <cstdlib>

namespace fs = std::filesystem;

KeyStore::KeyStore() {
    const char* home = std::getenv("HOME");
    if (home) {
        base_path_ = (fs::path(home) / ".pq-file-transfer" / "keys").string();
    }
}

void KeyStore::initialize_keys() {
    // TODO: Phase 6
}

void KeyStore::delete_keys() {
    // TODO: Phase 6
}

std::vector<uint8_t> KeyStore::load_public_kem() {
    // TODO: Phase 6
    return {};
}

std::vector<uint8_t> KeyStore::load_private_kem() {
    // TODO: Phase 6
    return {};
}

std::vector<uint8_t> KeyStore::load_public_dsa() {
    // TODO: Phase 6
    return {};
}

std::vector<uint8_t> KeyStore::load_private_dsa() {
    // TODO: Phase 6
    return {};
}

void KeyStore::save_contact(const std::string& name,
                             const std::vector<uint8_t>& pub_kem,
                             const std::vector<uint8_t>& pub_dsa) {
    // TODO: Phase 8
}

KeyStore::Contact KeyStore::load_contact(const std::string& name) {
    // TODO: Phase 8
    return {name, {}, {}};
}