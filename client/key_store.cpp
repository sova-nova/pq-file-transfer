#include "key_store.h"
#include "crypto_engine.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <cstdlib>

namespace fs = std::filesystem;

KeyStore::KeyStore() {
    const char* home = std::getenv("HOME");
    if (home) {
        base_path_ = (fs::path(home) / ".pq-file-transfer" / "keys").string();
    }
}

void KeyStore::initialize_keys() {
    fs::create_directories(base_path_);

    bool all_exist =
        fs::exists(base_path_ + "/public_kem") &&
        fs::exists(base_path_ + "/private_kem") &&
        fs::exists(base_path_ + "/public_dsa") &&
        fs::exists(base_path_ + "/private_dsa");

    if (all_exist) {
        std::cout << "Keys already exist, loading existing keys." << std::endl;
        return;
    }

    std::cout << "Generating new keypairs..." << std::endl;

    CryptoEngine crypto;

    auto kem = crypto.generate_kem_keypair();
    auto sig = crypto.generate_sig_keypair();

    // Write KEM keys
    std::ofstream(base_path_ + "/public_kem", std::ios::binary)
        .write(reinterpret_cast<const char*>(kem.public_key.data()), kem.public_key.size());
    std::ofstream(base_path_ + "/private_kem", std::ios::binary)
        .write(reinterpret_cast<const char*>(kem.private_key.data()), kem.private_key.size());

    // Write DSA keys
    std::ofstream(base_path_ + "/public_dsa", std::ios::binary)
        .write(reinterpret_cast<const char*>(sig.public_key.data()), sig.public_key.size());
    std::ofstream(base_path_ + "/private_dsa", std::ios::binary)
        .write(reinterpret_cast<const char*>(sig.private_key.data()), sig.private_key.size());

    std::cout << "Keypairs generated and saved." << std::endl;
    std::cout << "  ML-KEM-768 public key: " << kem.public_key.size() << " bytes" << std::endl;
    std::cout << "  ML-DSA-65 public key:  " << sig.public_key.size() << " bytes" << std::endl;
}

void KeyStore::delete_keys() {
    fs::remove(base_path_ + "/public_kem");
    fs::remove(base_path_ + "/private_kem");
    fs::remove(base_path_ + "/public_dsa");
    fs::remove(base_path_ + "/private_dsa");
    std::cout << "Keys deleted." << std::endl;
}

std::vector<uint8_t> read_key_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return {};

    auto size = file.tellg();
    file.seekg(0);

    std::vector<uint8_t> data(size);
    file.read(reinterpret_cast<char*>(data.data()), size);
    return data;
}

std::vector<uint8_t> KeyStore::load_public_kem() {
    return read_key_file(base_path_ + "/public_kem");
}

std::vector<uint8_t> KeyStore::load_private_kem() {
    return read_key_file(base_path_ + "/private_kem");
}

std::vector<uint8_t> KeyStore::load_public_dsa() {
    return read_key_file(base_path_ + "/public_dsa");
}

std::vector<uint8_t> KeyStore::load_private_dsa() {
    return read_key_file(base_path_ + "/private_dsa");
}

void KeyStore::save_contact(const std::string&,
                             const std::vector<uint8_t>&,
                             const std::vector<uint8_t>&) {
    // TODO: Phase 8
}

KeyStore::Contact KeyStore::load_contact(const std::string& name) {
    // TODO: Phase 8
    return {name, {}, {}};
}