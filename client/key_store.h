#pragma once

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "identity_bundle.h"

// Manages this user's keypairs and the public keys of their contacts.
//
// Layout (POSIX: ~/.pq-file-transfer, Windows: %USERPROFILE%\pq-file-transfer):
//   keys/{public_kem,private_kem,public_dsa,private_dsa}
//   contacts/<name>/{pub_kem,pub_dsa}
//   downloads/
//
// The two private key files are either raw key bytes, or protected by a passphrase
// (see CryptoEngine::protect_secret). While protected keys are locked, the load_private_*
// functions return an empty vector; unlock() decrypts them into memory for the session.
// All methods are safe to call from several threads.
class KeyStore {
public:
    struct Contact {
        std::string name;
        std::vector<uint8_t> pub_kem;
        std::vector<uint8_t> pub_dsa;
        std::string fingerprint;  // SHA-256 of pub_dsa, lowercase hex

        // True if pub_kem is bound to pub_dsa by a valid signed identity bundle. Contacts added
        // from an older (v1) card or from key files are false: their encryption key could have
        // been swapped in transit without the fingerprint check noticing.
        bool kem_verified = false;
        uint64_t bundle_issued_at = 0;  // when the bundle was made; 0 if there is none
    };

    // Throws std::runtime_error if no home directory can be determined.
    KeyStore();
    ~KeyStore();  // wipes any decrypted keys held in memory
    KeyStore(const KeyStore&) = delete;
    KeyStore& operator=(const KeyStore&) = delete;

    const std::filesystem::path& app_dir() const { return app_dir_; }
    std::filesystem::path downloads_dir() const { return app_dir_ / "downloads"; }

    // True if all four key files exist.
    bool keys_exist() const;

    // Loads existing keys, or generates them on first run. Throws if the key
    // directory is only partially populated, rather than silently replacing keys.
    // A non-empty `passphrase` is used only when generating: the private keys are then
    // written protected from the start and are never on disk in the clear. The new keys
    // are usable immediately (unlocked).
    void initialize_keys(const std::string& passphrase = std::string());

    // These return an empty vector if the file is missing or unreadable. The private ones
    // also return an empty vector while protected keys are locked.
    std::vector<uint8_t> load_public_kem() const;
    std::vector<uint8_t> load_private_kem() const;
    std::vector<uint8_t> load_public_dsa() const;
    std::vector<uint8_t> load_private_dsa() const;

    // --- Passphrase protection ---

    static constexpr size_t MIN_PASSPHRASE_BYTES = 8;
    static bool is_acceptable_passphrase(const std::string& passphrase);

    bool private_keys_protected() const;  // at least one private key file is encrypted
    bool private_keys_locked() const;     // protected, and not unlocked in this session

    // Decrypts the private keys into memory. Returns false for a wrong passphrase; throws
    // std::runtime_error if the files are damaged. Also finishes a protect operation that
    // was interrupted between the two files.
    bool unlock(const std::string& passphrase);
    void lock();  // forgets the decrypted keys

    // Checks a passphrase without changing any state.
    bool verify_passphrase(const std::string& passphrase) const;

    // Protects the private keys with a new passphrase (or replaces the old one). The keys
    // must be usable (unprotected or unlocked). Throws with a user-facing message otherwise.
    void set_passphrase(const std::string& passphrase);

    // Stores the private keys unprotected again. The keys must be unlocked.
    void remove_passphrase();

    // scrypt cost used when writing (log2 of N). Reading honours whatever the file says.
    void set_kdf_cost(uint8_t log2_n) { kdf_log2_n_ = log2_n; }

    std::string own_fingerprint() const;
    Contact self_contact() const;  // own public keys, for sending to yourself

    // Letters, digits, space, '-', '_', '.'; 1–64 chars; not "self".
    static bool is_valid_contact_name(const std::string& name);

    // Validates the name and key sizes; throws std::runtime_error with a
    // user-facing message on failure. Overwrites an existing contact. The contact is saved as
    // "encryption key not verified", and any bundle stored for a previous version is removed.
    void save_contact(const std::string& name,
                      const std::vector<uint8_t>& pub_kem,
                      const std::vector<uint8_t>& pub_dsa);

    // Saves a contact from a verified identity bundle (see parse_identity_bundle), with the
    // encryption key marked verified. Overwrites an existing contact of that name.
    void save_contact_bundle(const std::string& name, const IdentityBundle& bundle);

    // Signs a fresh bundle of this user's public keys. Needs the private signing key, so the
    // keys must be unlocked; throws with a user-facing message otherwise.
    std::vector<uint8_t> make_own_bundle(const std::string& display_name,
                                         const std::string& relay_hint = std::string()) const;

    // What to do with a bundle whose signing key may already belong to a contact.
    enum class BundleImportResult {
        UnknownIdentity,  // nobody saved has this signing key; the caller adds a new contact
        Updated,          // a newer bundle from a known identity replaced the old one
        Unchanged,        // already have this bundle, or a newer one with the same keys
        Stale             // older than what is saved and with a different encryption key: ignored
    };
    struct BundleImport {
        BundleImportResult result = BundleImportResult::UnknownIdentity;
        std::string contact_name;
        bool encryption_key_changed = false;  // the saved encryption key was replaced
        bool was_unverified = false;          // the contact had no bundle before
    };
    // A newer bundle signed by an already-saved signing key updates that contact without
    // asking: only the owner of the signing key can produce one.
    BundleImport import_bundle_for_known_identity(const IdentityBundle& bundle);

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

    std::vector<uint8_t> load_private(const std::filesystem::path& path,
                                      const std::vector<uint8_t>& cache) const;
    bool read_private_keys(const std::string& passphrase, std::vector<uint8_t>& kem,
                           std::vector<uint8_t>& dsa, bool& any_protected, bool& any_plain) const;
    void write_protected(const std::vector<uint8_t>& kem, const std::vector<uint8_t>& dsa,
                         const std::string& passphrase);
    void set_cache(const std::vector<uint8_t>& kem, const std::vector<uint8_t>& dsa);

    mutable std::mutex mutex_;                 // guards the two caches
    std::vector<uint8_t> cache_kem_;           // decrypted keys while unlocked
    std::vector<uint8_t> cache_dsa_;
    uint8_t kdf_log2_n_ = 17;                  // CryptoEngine::DEFAULT_SCRYPT_LOG2_N
};
