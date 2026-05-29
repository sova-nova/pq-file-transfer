#include "key_store.h"
#include "crypto_engine.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <cstdlib>
#include <optional>

namespace fs = std::filesystem;

KeyStore::KeyStore() {
#ifdef _WIN32
    const char* home = std::getenv("USERPROFILE");
    if (!home) home = std::getenv("APPDATA");
    if (home) {
        base_path_ = (fs::path(home) / "pq-file-transfer" / "keys").string();
        contacts_path_ = (fs::path(home) / "pq-file-transfer" / "contacts").string();
    }
#else
    const char* home = std::getenv("HOME");
    if (home) {
        base_path_ = (fs::path(home) / ".pq-file-transfer" / "keys").string();
        contacts_path_ = (fs::path(home) / ".pq-file-transfer" / "contacts").string();
    }
#endif
}

void KeyStore::initialize_keys() {
    fs::create_directories(base_path_);
    fs::create_directories(contacts_path_);

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

    std::ofstream(base_path_ + "/public_kem", std::ios::binary)
        .write(reinterpret_cast<const char*>(kem.public_key.data()), kem.public_key.size());
    std::ofstream(base_path_ + "/private_kem", std::ios::binary)
        .write(reinterpret_cast<const char*>(kem.private_key.data()), kem.private_key.size());

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

void KeyStore::save_contact(const std::string& name,
                             const std::vector<uint8_t>& pub_kem,
                             const std::vector<uint8_t>& pub_dsa) {
    fs::create_directories(contacts_path_);

    std::string dir = contacts_path_ + "/" + name;
    fs::create_directories(dir);

    std::ofstream(dir + "/pub_kem", std::ios::binary)
        .write(reinterpret_cast<const char*>(pub_kem.data()), pub_kem.size());
    std::ofstream(dir + "/pub_dsa", std::ios::binary)
        .write(reinterpret_cast<const char*>(pub_dsa.data()), pub_dsa.size());

    std::cout << "Contact saved: " << name << std::endl;
}

KeyStore::Contact KeyStore::load_contact(const std::string& name) {
    Contact contact;
    contact.name = name;
    contact.pub_kem = read_key_file(contacts_path_ + "/" + name + "/pub_kem");
    contact.pub_dsa = read_key_file(contacts_path_ + "/" + name + "/pub_dsa");
    return contact;
}

std::vector<std::string> KeyStore::list_contacts() {
    std::vector<std::string> names;
    fs::create_directories(contacts_path_);

    for (const auto& entry : fs::directory_iterator(contacts_path_)) {
        if (entry.is_directory()) {
            names.push_back(entry.path().filename().string());
        }
    }

    return names;
}

std::optional<KeyStore::Contact> KeyStore::find_contact_by_dsa_fingerprint(
    const std::vector<uint8_t>& pub_dsa)
{
    auto contacts = list_contacts();
    for (const auto& name : contacts) {
        auto contact = load_contact(name);
        if (contact.pub_dsa.size() >= 8 && pub_dsa.size() >= 8) {
            bool match = true;
            for (size_t i = 0; i < 8; i++) {
                if (contact.pub_dsa[i] != pub_dsa[i]) {
                    match = false;
                    break;
                }
            }
            if (match) return contact;
        }
    }
    return std::nullopt;
}

void KeyStore::delete_contact(const std::string& name) {
    fs::remove_all(contacts_path_ + "/" + name);
    std::cout << "Contact deleted: " << name << std::endl;
}