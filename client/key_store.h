#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

// Manages this user's keypairs and the public keys of their contacts.
//
// Layout (POSIX: ~/.pq-file-transfer, Windows: %USERPROFILE%\pq-file-transfer):
//   keys/{public_kem,private_kem,public_dsa,private_dsa}
//   contacts/<name>/{pub_kem,pub_dsa}
//   downloads/
class KeyStore {
public:
    struct Contact {
        std::string name;
        std::vector<uint8_t> pub_kem;
        std::vector<uint8_t> pub_dsa;
        std::string fingerprint;  // SHA-256 of pub_dsa, lowercase hex
    };

    // Throws std::runtime_error if no home directory can be determined.
    KeyStore();

    const std::filesystem::path& app_dir() const { return app_dir_; }
    std::filesystem::path downloads_dir() const { return app_dir_ / "downloads"; }

    // Loads existing keys, or generates them on first run. Throws if the key
    // directory is only partially populated, rather than silently replacing keys.
    void initialize_keys();

    // These return an empty vector if the file is missing or unreadable.
    std::vector<uint8_t> load_public_kem() const;
    std::vector<uint8_t> load_private_kem() const;
    std::vector<uint8_t> load_public_dsa() const;
    std::vector<uint8_t> load_private_dsa() const;

    std::string own_fingerprint() const;
    Contact self_contact() const;  // own public keys, for sending to yourself

    // Letters, digits, space, '-', '_', '.'; 1–64 chars; not "self".
    static bool is_valid_contact_name(const std::string& name);

    // Validates the name and key sizes; throws std::runtime_error with a
    // user-facing message on failure. Overwrites an existing contact.
    void save_contact(const std::string& name,
                      const std::vector<uint8_t>& pub_kem,
                      const std::vector<uint8_t>& pub_dsa);

    // Returns std::nullopt if the contact is missing or its keys are invalid.
    std::optional<Contact> load_contact(const std::string& name) const;
    bool contact_exists(const std::string& name) const;
    std::vector<std::string> list_contacts() const;  // sorted
    std::optional<Contact> find_contact_by_fingerprint(const std::string& fingerprint) const;
    void delete_contact(const std::string& name);

    // Writes this user's public keys into `dir` for sharing. Returns the paths.
    std::vector<std::filesystem::path> export_public_keys(const std::filesystem::path& dir) const;

private:
    std::filesystem::path app_dir_;
    std::filesystem::path keys_dir_;
    std::filesystem::path contacts_dir_;

    std::optional<std::filesystem::path> contact_dir(const std::string& name) const;
};
