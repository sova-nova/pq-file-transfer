#include "key_store.h"
#include "crypto_engine.h"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace fs = std::filesystem;

namespace {

constexpr uintmax_t MAX_KEY_FILE_SIZE = 64 * 1024;

std::vector<uint8_t> read_file_bytes(const fs::path& path) {
    std::error_code ec;
    if (!fs::is_regular_file(path, ec)) return {};
    auto size = fs::file_size(path, ec);
    if (ec || size == 0 || size > MAX_KEY_FILE_SIZE) return {};

    std::ifstream f(path, std::ios::binary);
    std::vector<uint8_t> data(static_cast<size_t>(size));
    if (!f.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(size))) return {};
    return data;
}

// Best effort: real owner-only permissions on POSIX; on Windows this only
// toggles the read-only attribute, and the profile directory's ACL applies.
void restrict_permissions(const fs::path& path, bool is_dir) {
    std::error_code ec;
    auto perms = is_dir ? fs::perms::owner_all : (fs::perms::owner_read | fs::perms::owner_write);
    fs::permissions(path, perms, fs::perm_options::replace, ec);
}

// Writes via a temporary file and rename, so a crash never leaves a truncated key.
void write_file_atomic(const fs::path& path, const std::vector<uint8_t>& data, bool secret) {
    fs::path tmp = path;
    tmp += ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) throw std::runtime_error("Cannot write " + path.u8string());
        if (secret) restrict_permissions(tmp, false);  // before any secret bytes land
        f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        f.close();
        if (f.fail()) {
            std::error_code ec;
            fs::remove(tmp, ec);
            throw std::runtime_error("Cannot write " + path.u8string());
        }
    }
    std::error_code ec;
    fs::rename(tmp, path, ec);
    if (ec) {
        fs::remove(tmp, ec);
        throw std::runtime_error("Cannot write " + path.u8string());
    }
}

std::string ascii_lower(std::string s) {
    for (auto& c : s)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return s;
}

}  // namespace

KeyStore::KeyStore() {
#ifdef _WIN32
    // Wide-char lookup so non-ASCII user names work.
    const wchar_t* home = _wgetenv(L"USERPROFILE");
    if (!home || !*home) home = _wgetenv(L"APPDATA");
    if (!home || !*home) throw std::runtime_error("Cannot determine the user profile directory");
    app_dir_ = fs::path(home) / "pq-file-transfer";
#else
    const char* home = std::getenv("HOME");
    if (!home || !*home) throw std::runtime_error("Cannot determine the home directory ($HOME is not set)");
    app_dir_ = fs::path(home) / ".pq-file-transfer";
#endif
    keys_dir_ = app_dir_ / "keys";
    contacts_dir_ = app_dir_ / "contacts";
}

void KeyStore::initialize_keys() {
    std::error_code ec;
    fs::create_directories(keys_dir_, ec);
    if (!ec) fs::create_directories(contacts_dir_, ec);
    if (ec) throw std::runtime_error("Cannot create " + app_dir_.u8string() + ": " + ec.message());
    restrict_permissions(app_dir_, true);
    restrict_permissions(keys_dir_, true);

    const fs::path files[] = {keys_dir_ / "public_kem", keys_dir_ / "private_kem",
                              keys_dir_ / "public_dsa", keys_dir_ / "private_dsa"};
    int present = 0;
    for (const auto& f : files)
        if (fs::exists(f, ec)) present++;

    if (present == 4) {
        // Validate now so a corrupt key fails at startup, not mid-transfer.
        if (load_public_kem().size() != CryptoEngine::kem_public_key_size() ||
            load_private_kem().size() != CryptoEngine::kem_secret_key_size() ||
            load_public_dsa().size() != CryptoEngine::sig_public_key_size() ||
            load_private_dsa().size() != CryptoEngine::sig_secret_key_size()) {
            throw std::runtime_error("Key files in " + keys_dir_.u8string() +
                                     " are corrupt or from an incompatible version");
        }
        // Tighten permissions on keys written by older versions.
        restrict_permissions(files[1], false);
        restrict_permissions(files[3], false);
        return;
    }

    if (present != 0) {
        throw std::runtime_error(
            "Some key files are missing from " + keys_dir_.u8string() +
            ". Not generating new keys over a partial set: restore the missing files from a "
            "backup, or delete that folder to start fresh (your contacts will then need your "
            "new public keys).");
    }

    std::cout << "Generating new keypairs..." << std::endl;
    auto kem = CryptoEngine::generate_kem_keypair();
    auto sig = CryptoEngine::generate_sig_keypair();

    write_file_atomic(files[1], kem.private_key, true);
    write_file_atomic(files[3], sig.private_key, true);
    write_file_atomic(files[0], kem.public_key, false);
    write_file_atomic(files[2], sig.public_key, false);

    CryptoEngine::secure_wipe(kem.private_key);
    CryptoEngine::secure_wipe(sig.private_key);
    std::cout << "Keypairs generated and saved to " << keys_dir_.u8string() << std::endl;
}

std::vector<uint8_t> KeyStore::load_public_kem() const { return read_file_bytes(keys_dir_ / "public_kem"); }
std::vector<uint8_t> KeyStore::load_private_kem() const { return read_file_bytes(keys_dir_ / "private_kem"); }
std::vector<uint8_t> KeyStore::load_public_dsa() const { return read_file_bytes(keys_dir_ / "public_dsa"); }
std::vector<uint8_t> KeyStore::load_private_dsa() const { return read_file_bytes(keys_dir_ / "private_dsa"); }

std::string KeyStore::own_fingerprint() const {
    return CryptoEngine::fingerprint(load_public_dsa());
}

KeyStore::Contact KeyStore::self_contact() const {
    Contact c;
    c.name = "yourself";
    c.pub_kem = load_public_kem();
    c.pub_dsa = load_public_dsa();
    c.fingerprint = CryptoEngine::fingerprint(c.pub_dsa);
    return c;
}

bool KeyStore::is_valid_contact_name(const std::string& name) {
    if (name.empty() || name.size() > 64) return false;
    for (char c : name) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                  c == ' ' || c == '-' || c == '_' || c == '.';
        if (!ok) return false;
    }
    // Leading dots hide folders; trailing dots/spaces are stripped by Windows.
    if (name.front() == '.' || name.front() == ' ' || name.back() == '.' || name.back() == ' ') return false;

    std::string lower = ascii_lower(name);
    if (lower == "self") return false;

    // Reserved device names on Windows.
    std::string base = lower.substr(0, lower.find('.'));
    static const char* reserved[] = {"con", "prn", "aux", "nul",
                                     "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
                                     "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9"};
    for (const char* r : reserved)
        if (base == r) return false;
    return true;
}

// Maps a contact name to its directory, rejecting anything that could escape
// the contacts folder. Names already on disk may predate the validation rules,
// so this only checks for path components, not the full character set.
std::optional<fs::path> KeyStore::contact_dir(const std::string& name) const {
    if (name.empty() || name == "." || name == ".." ||
        name.find_first_of("/\\:") != std::string::npos || name.find('\0') != std::string::npos)
        return std::nullopt;
    try {
        return contacts_dir_ / fs::u8path(name);
    } catch (const std::exception&) {
        return std::nullopt;  // invalid UTF-8
    }
}

void KeyStore::save_contact(const std::string& name,
                            const std::vector<uint8_t>& pub_kem,
                            const std::vector<uint8_t>& pub_dsa) {
    if (!is_valid_contact_name(name))
        throw std::runtime_error("Invalid contact name. Use 1-64 letters, digits, spaces, '-', '_' or '.'");
    if (pub_kem.size() != CryptoEngine::kem_public_key_size() ||
        pub_dsa.size() != CryptoEngine::sig_public_key_size())
        throw std::runtime_error("These files are not ML-KEM-768 / ML-DSA-65 public keys");

    fs::path dir = *contact_dir(name);
    std::error_code ec;
    fs::create_directories(dir, ec);
    if (ec) throw std::runtime_error("Cannot create contact folder: " + ec.message());

    write_file_atomic(dir / "pub_kem", pub_kem, false);
    write_file_atomic(dir / "pub_dsa", pub_dsa, false);
}

std::optional<KeyStore::Contact> KeyStore::load_contact(const std::string& name) const {
    auto dir = contact_dir(name);
    if (!dir) return std::nullopt;

    Contact c;
    c.name = name;
    c.pub_kem = read_file_bytes(*dir / "pub_kem");
    c.pub_dsa = read_file_bytes(*dir / "pub_dsa");
    if (c.pub_kem.size() != CryptoEngine::kem_public_key_size() ||
        c.pub_dsa.size() != CryptoEngine::sig_public_key_size())
        return std::nullopt;
    c.fingerprint = CryptoEngine::fingerprint(c.pub_dsa);
    return c;
}

bool KeyStore::contact_exists(const std::string& name) const {
    auto dir = contact_dir(name);
    std::error_code ec;
    return dir && fs::is_directory(*dir, ec);
}

std::vector<std::string> KeyStore::list_contacts() const {
    std::vector<std::string> names;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(contacts_dir_, ec)) {
        std::error_code entry_ec;
        if (entry.is_directory(entry_ec)) names.push_back(entry.path().filename().u8string());
    }
    std::sort(names.begin(), names.end());
    return names;
}

std::optional<KeyStore::Contact> KeyStore::find_contact_by_fingerprint(const std::string& fingerprint) const {
    for (const auto& name : list_contacts()) {
        auto contact = load_contact(name);
        if (contact && contact->fingerprint == fingerprint) return contact;
    }
    return std::nullopt;
}

void KeyStore::delete_contact(const std::string& name) {
    auto dir = contact_dir(name);
    if (!dir) return;
    std::error_code ec;
    fs::remove_all(*dir, ec);
    if (ec) throw std::runtime_error("Cannot delete contact: " + ec.message());
}

std::vector<fs::path> KeyStore::export_public_keys(const fs::path& dir) const {
    auto kem = load_public_kem();
    auto dsa = load_public_dsa();
    if (kem.empty() || dsa.empty()) throw std::runtime_error("Your public keys could not be read");

    fs::path kem_path = dir / "pq_public_kem.key";
    fs::path dsa_path = dir / "pq_public_dsa.key";
    write_file_atomic(kem_path, kem, false);
    write_file_atomic(dsa_path, dsa, false);
    return {kem_path, dsa_path};
}
