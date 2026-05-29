#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <optional>

class KeyStore {
public:
    KeyStore();

    void initialize_keys();
    void delete_keys();

    std::vector<uint8_t> load_public_kem();
    std::vector<uint8_t> load_private_kem();
    std::vector<uint8_t> load_public_dsa();
    std::vector<uint8_t> load_private_dsa();

    struct Contact {
        std::string name;
        std::vector<uint8_t> pub_kem;
        std::vector<uint8_t> pub_dsa;
    };

    void save_contact(const std::string& name,
                      const std::vector<uint8_t>& pub_kem,
                      const std::vector<uint8_t>& pub_dsa);

    Contact load_contact(const std::string& name);

    // New: list all contact names
    std::vector<std::string> list_contacts();

    // New: find a contact by matching the first 8 bytes of their DSA public key
    std::optional<Contact> find_contact_by_dsa_fingerprint(const std::vector<uint8_t>& pub_dsa);

    // New: delete a contact
    void delete_contact(const std::string& name);

private:
    std::string base_path_;
    std::string contacts_path_;
};