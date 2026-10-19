#include "key_store.h"
#include "crypto_engine.h"
#include "protocol.h"
#include "scope_exit.h"

#include <algorithm>
#include <ctime>
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

KeyStore::~KeyStore() { lock(); }

bool KeyStore::keys_exist() const {
    std::error_code ec;
    for (const char* name : {"public_kem", "private_kem", "public_dsa", "private_dsa"})
        if (!fs::exists(keys_dir_ / name, ec)) return false;
    return true;
}

void KeyStore::initialize_keys(const std::string& passphrase) {
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
        // Validate now so a corrupt key fails at startup, not mid-transfer. Protected private
        // keys can't be size-checked until they are unlocked, which unlock() does.
        auto private_ok = [&](const fs::path& path, size_t expected) {
            auto raw = read_file_bytes(path);
            return !raw.empty() && (CryptoEngine::is_protected_blob(raw) || raw.size() == expected);
        };
        if (load_public_kem().size() != CryptoEngine::kem_public_key_size() ||
            load_public_dsa().size() != CryptoEngine::sig_public_key_size() ||
            !private_ok(files[1], CryptoEngine::kem_secret_key_size()) ||
            !private_ok(files[3], CryptoEngine::sig_secret_key_size())) {
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

    if (!passphrase.empty() && !is_acceptable_passphrase(passphrase))
        throw std::runtime_error("The passphrase is too short (use at least " +
                                 std::to_string(MIN_PASSPHRASE_BYTES) + " characters)");

    std::cout << "Generating new keypairs..." << std::endl;
    auto kem = CryptoEngine::generate_kem_keypair();
    auto sig = CryptoEngine::generate_sig_keypair();

    write_file_atomic(files[0], kem.public_key, false);
    write_file_atomic(files[2], sig.public_key, false);
    if (passphrase.empty()) {
        write_file_atomic(files[1], kem.private_key, true);
        write_file_atomic(files[3], sig.private_key, true);
    } else {
        write_protected(kem.private_key, sig.private_key, passphrase);
        set_cache(kem.private_key, sig.private_key);  // a fresh install starts unlocked
    }

    CryptoEngine::secure_wipe(kem.private_key);
    CryptoEngine::secure_wipe(sig.private_key);
    std::cout << "Keypairs generated and saved to " << keys_dir_.u8string() << std::endl;
}

std::vector<uint8_t> KeyStore::load_public_kem() const { return read_file_bytes(keys_dir_ / "public_kem"); }
std::vector<uint8_t> KeyStore::load_private_kem() const { return load_private(keys_dir_ / "private_kem", cache_kem_); }
std::vector<uint8_t> KeyStore::load_public_dsa() const { return read_file_bytes(keys_dir_ / "public_dsa"); }
std::vector<uint8_t> KeyStore::load_private_dsa() const { return load_private(keys_dir_ / "private_dsa", cache_dsa_); }

// --- Passphrase protection ---

namespace {
const char KEM_LABEL[] = "private_kem";
const char DSA_LABEL[] = "private_dsa";
}  // namespace

bool KeyStore::is_acceptable_passphrase(const std::string& passphrase) {
    return passphrase.size() >= MIN_PASSPHRASE_BYTES;
}

// Raw bytes for an unprotected key; the in-memory copy for a protected one (empty while locked).
std::vector<uint8_t> KeyStore::load_private(const fs::path& path, const std::vector<uint8_t>& cache) const {
    auto raw = read_file_bytes(path);
    if (raw.empty() || !CryptoEngine::is_protected_blob(raw)) return raw;
    std::lock_guard<std::mutex> lock(mutex_);
    return cache;
}

bool KeyStore::private_keys_protected() const {
    return CryptoEngine::is_protected_blob(read_file_bytes(keys_dir_ / "private_kem")) ||
           CryptoEngine::is_protected_blob(read_file_bytes(keys_dir_ / "private_dsa"));
}

bool KeyStore::private_keys_locked() const {
    bool kem_protected = CryptoEngine::is_protected_blob(read_file_bytes(keys_dir_ / "private_kem"));
    bool dsa_protected = CryptoEngine::is_protected_blob(read_file_bytes(keys_dir_ / "private_dsa"));
    std::lock_guard<std::mutex> lock(mutex_);
    return (kem_protected && cache_kem_.empty()) || (dsa_protected && cache_dsa_.empty());
}

void KeyStore::set_cache(const std::vector<uint8_t>& kem, const std::vector<uint8_t>& dsa) {
    std::lock_guard<std::mutex> lock(mutex_);
    CryptoEngine::secure_wipe(cache_kem_);
    CryptoEngine::secure_wipe(cache_dsa_);
    cache_kem_ = kem;
    cache_dsa_ = dsa;
}

void KeyStore::lock() {
    std::lock_guard<std::mutex> lock(mutex_);
    CryptoEngine::secure_wipe(cache_kem_);
    CryptoEngine::secure_wipe(cache_dsa_);
}

// Reads both private keys, decrypting the protected ones. Returns false on a wrong passphrase.
bool KeyStore::read_private_keys(const std::string& passphrase, std::vector<uint8_t>& kem,
                                 std::vector<uint8_t>& dsa, bool& any_protected, bool& any_plain) const {
    struct Item { fs::path path; const char* label; std::vector<uint8_t>* out; size_t expected; };
    Item items[] = {{keys_dir_ / "private_kem", KEM_LABEL, &kem, CryptoEngine::kem_secret_key_size()},
                    {keys_dir_ / "private_dsa", DSA_LABEL, &dsa, CryptoEngine::sig_secret_key_size()}};
    any_protected = any_plain = false;
    for (auto& item : items) {
        auto raw = read_file_bytes(item.path);
        if (raw.empty()) throw std::runtime_error("Cannot read " + item.path.u8string());
        if (CryptoEngine::is_protected_blob(raw)) {
            any_protected = true;
            auto plain = CryptoEngine::unprotect_secret(raw, passphrase, item.label);
            if (!plain) return false;
            *item.out = std::move(*plain);
        } else {
            any_plain = true;
            *item.out = std::move(raw);
        }
        if (item.out->size() != item.expected)
            throw std::runtime_error(item.path.u8string() + " is corrupt or from an incompatible version");
    }
    return true;
}

void KeyStore::write_protected(const std::vector<uint8_t>& kem, const std::vector<uint8_t>& dsa,
                               const std::string& passphrase) {
    auto kem_blob = CryptoEngine::protect_secret(kem, passphrase, KEM_LABEL, kdf_log2_n_);
    auto dsa_blob = CryptoEngine::protect_secret(dsa, passphrase, DSA_LABEL, kdf_log2_n_);
    write_file_atomic(keys_dir_ / "private_kem", kem_blob, true);
    write_file_atomic(keys_dir_ / "private_dsa", dsa_blob, true);
}

bool KeyStore::unlock(const std::string& passphrase) {
    if (passphrase.empty()) return false;
    std::vector<uint8_t> kem, dsa;
    auto wipe = make_scope_exit([&] {
        CryptoEngine::secure_wipe(kem);
        CryptoEngine::secure_wipe(dsa);
    });
    bool any_protected = false, any_plain = false;
    if (!read_private_keys(passphrase, kem, dsa, any_protected, any_plain)) return false;

    set_cache(kem, dsa);
    // One file protected and one not means an earlier protect step was interrupted: finish it.
    if (any_protected && any_plain) write_protected(kem, dsa, passphrase);
    return true;
}

bool KeyStore::verify_passphrase(const std::string& passphrase) const {
    if (passphrase.empty()) return false;
    std::vector<uint8_t> kem, dsa;
    auto wipe = make_scope_exit([&] {
        CryptoEngine::secure_wipe(kem);
        CryptoEngine::secure_wipe(dsa);
    });
    bool any_protected = false, any_plain = false;
    return read_private_keys(passphrase, kem, dsa, any_protected, any_plain) && any_protected;
}

void KeyStore::set_passphrase(const std::string& passphrase) {
    if (!is_acceptable_passphrase(passphrase))
        throw std::runtime_error("The passphrase is too short (use at least " +
                                 std::to_string(MIN_PASSPHRASE_BYTES) + " characters)");
    auto kem = load_private_kem();
    auto dsa = load_private_dsa();
    auto wipe = make_scope_exit([&] {
        CryptoEngine::secure_wipe(kem);
        CryptoEngine::secure_wipe(dsa);
    });
    if (kem.size() != CryptoEngine::kem_secret_key_size() || dsa.size() != CryptoEngine::sig_secret_key_size())
        throw std::runtime_error("Your keys are locked. Unlock them first");

    write_protected(kem, dsa, passphrase);
    set_cache(kem, dsa);  // the session stays unlocked
}

void KeyStore::remove_passphrase() {
    auto kem = load_private_kem();
    auto dsa = load_private_dsa();
    auto wipe = make_scope_exit([&] {
        CryptoEngine::secure_wipe(kem);
        CryptoEngine::secure_wipe(dsa);
    });
    if (kem.size() != CryptoEngine::kem_secret_key_size() || dsa.size() != CryptoEngine::sig_secret_key_size())
        throw std::runtime_error("Your keys are locked. Unlock them first");

    write_file_atomic(keys_dir_ / "private_kem", kem, true);
    write_file_atomic(keys_dir_ / "private_dsa", dsa, true);
    lock();  // unprotected keys are read straight from disk; nothing to cache
}

std::string KeyStore::own_fingerprint() const {
    return CryptoEngine::fingerprint(load_public_dsa());
}

KeyStore::Contact KeyStore::self_contact() const {
    Contact c;
    c.name = "yourself";
    c.pub_kem = load_public_kem();
    c.pub_dsa = load_public_dsa();
    c.fingerprint = CryptoEngine::fingerprint(c.pub_dsa);
    c.kem_verified = true;  // our own keys
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

    // Remove any bundle first: after this the keys are unverified, and a crash in between must
    // leave "unverified", never a stale bundle that no longer matches.
    fs::remove(dir / "bundle", ec);
    write_file_atomic(dir / "pub_kem", pub_kem, false);
    write_file_atomic(dir / "pub_dsa", pub_dsa, false);
}

void KeyStore::save_contact_bundle(const std::string& name, const IdentityBundle& bundle) {
    if (!is_valid_contact_name(name))
        throw std::runtime_error("Invalid contact name. Use 1-64 letters, digits, spaces, '-', '_' or '.'");
    if (bundle.raw.empty() || bundle.signing_key.size() != CryptoEngine::sig_public_key_size() ||
        bundle.encryption_key.size() != CryptoEngine::kem_public_key_size())
        throw std::runtime_error("This is not a valid identity bundle");

    fs::path dir = *contact_dir(name);
    std::error_code ec;
    fs::create_directories(dir, ec);
    if (ec) throw std::runtime_error("Cannot create contact folder: " + ec.message());

    // Keys first, bundle last: if we crash in between, the old bundle no longer matches the new
    // keys, so the contact reads as unverified rather than wrongly verified.
    write_file_atomic(dir / "pub_kem", bundle.encryption_key, false);
    write_file_atomic(dir / "pub_dsa", bundle.signing_key, false);
    write_file_atomic(dir / "bundle", bundle.raw, false);
}

std::vector<uint8_t> KeyStore::make_own_bundle(const std::string& display_name, const std::string& relay_hint) const {
    BundleAddress address;
    address.relay_hint = relay_hint;
    return make_own_bundle(display_name, address);
}

std::vector<uint8_t> KeyStore::make_own_bundle(const std::string& display_name, const BundleAddress& address) const {
    auto signing_private = load_private_dsa();
    auto wipe = make_scope_exit([&] { CryptoEngine::secure_wipe(signing_private); });
    if (signing_private.size() != CryptoEngine::sig_secret_key_size())
        throw std::runtime_error("Your keys are locked. Unlock them first");

    auto signing_public = load_public_dsa();
    auto encryption_public = load_public_kem();
    return create_identity_bundle(signing_public, encryption_public, display_name, address,
                                  static_cast<uint64_t>(std::time(nullptr)), signing_private);
}

KeyStore::BundleImport KeyStore::import_bundle_for_known_identity(const IdentityBundle& bundle,
                                                                  const std::vector<uint8_t>& send_token) {
    BundleImport result;
    auto existing = find_contact_by_fingerprint(bundle.fingerprint());
    if (!existing) return result;  // UnknownIdentity

    result.contact_name = existing->name;
    result.was_unverified = !existing->kem_verified;

    if (existing->kem_verified && bundle.issued_at <= existing->bundle_issued_at) {
        // Not newer than what we have. Harmless if it carries the same encryption key; if it
        // carries a different one it is an old key being replayed, so it is ignored.
        result.result = bundle.encryption_key == existing->pub_kem ? BundleImportResult::Unchanged
                                                                   : BundleImportResult::Stale;
        // A card made at the same moment as the one we have (two cards copied in one second) can still
        // bring a different send token. A strictly older card never does: its token may be long revoked.
        if (result.result == BundleImportResult::Unchanged && bundle.issued_at == existing->bundle_issued_at &&
            send_token.size() == 32 && send_token != existing->send_token) {
            save_contact_token(existing->name, send_token);
            result.result = BundleImportResult::Updated;
        }
        return result;
    }

    result.encryption_key_changed = bundle.encryption_key != existing->pub_kem;
    save_contact_bundle(existing->name, bundle);
    if (send_token.size() == 32) save_contact_token(existing->name, send_token);
    result.result = BundleImportResult::Updated;
    return result;
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

    // Verified only if a bundle exists, its signature is valid, and it names exactly these keys.
    auto raw_bundle = read_file_bytes(*dir / "bundle");
    if (!raw_bundle.empty()) {
        auto bundle = parse_identity_bundle(raw_bundle);
        if (bundle && bundle->signing_key == c.pub_dsa && bundle->encryption_key == c.pub_kem) {
            c.kem_verified = true;
            c.bundle_issued_at = bundle->issued_at;
            if (bundle->has_mailbox()) {
                c.relay_address = bundle->relay_hint;
                c.relay_id = bundle->relay_id;
                c.mailbox_id = bundle->mailbox_id;
            }
        }
    }
    auto token = read_file_bytes(*dir / "send_token");
    if (token.size() == 32) c.send_token = std::move(token);
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

void KeyStore::save_contact_token(const std::string& name, const std::vector<uint8_t>& send_token) {
    if (send_token.size() != 32) throw std::runtime_error("A send token is 32 bytes");
    auto dir = contact_dir(name);
    std::error_code ec;
    if (!dir || !fs::is_directory(*dir, ec)) throw std::runtime_error("No such contact");
    write_file_atomic(*dir / "send_token", send_token, true);  // a bearer credential: owner-only
}

// --- Local secrets ---

std::vector<uint8_t> KeyStore::derive_local_key(const std::string& label) const {
    auto kem_private = load_private_kem();
    auto wipe = make_scope_exit([&] { CryptoEngine::secure_wipe(kem_private); });
    if (kem_private.size() != CryptoEngine::kem_secret_key_size()) return {};
    static const std::string salt_text = "pq-suite v3 local keys";
    return CryptoEngine::hkdf_sha256(kem_private, std::vector<uint8_t>(salt_text.begin(), salt_text.end()), label, 32);
}

namespace {
const char ACCESS_WRAP_LABEL[] = "access key wrap";
const char ACCESS_WRAP_AAD[] = "pq-suite v3 mailbox access key";
}  // namespace

bool KeyStore::has_access_key() const {
    std::error_code ec;
    return fs::exists(keys_dir_ / "public_access", ec) && fs::exists(keys_dir_ / "private_access.enc", ec);
}

void KeyStore::create_access_key() {
    if (has_access_key()) throw std::runtime_error("This mailbox already has an access key");
    auto wrap_key = derive_local_key(ACCESS_WRAP_LABEL);
    if (wrap_key.empty()) throw std::runtime_error("Your keys are locked. Unlock them first");
    auto wipe = make_scope_exit([&] { CryptoEngine::secure_wipe(wrap_key); });

    auto pair = CryptoEngine::generate_sig_keypair();
    auto nonce = CryptoEngine::random_bytes(12);
    auto sealed = CryptoEngine::encrypt(wrap_key, nonce, pair.private_key,
                                        std::vector<uint8_t>(ACCESS_WRAP_AAD, ACCESS_WRAP_AAD + sizeof(ACCESS_WRAP_AAD) - 1));
    std::vector<uint8_t> blob = nonce;
    blob.insert(blob.end(), sealed.begin(), sealed.end());
    CryptoEngine::secure_wipe(pair.private_key);

    // Private half first: if we stop in between there is no public file, so no half-made key counts.
    write_file_atomic(keys_dir_ / "private_access.enc", blob, true);
    write_file_atomic(keys_dir_ / "public_access", pair.public_key, false);
}

std::vector<uint8_t> KeyStore::load_access_public() const { return read_file_bytes(keys_dir_ / "public_access"); }

std::vector<uint8_t> KeyStore::load_access_private() const {
    auto blob = read_file_bytes(keys_dir_ / "private_access.enc");
    if (blob.size() <= 12 + 16) return {};
    auto wrap_key = derive_local_key(ACCESS_WRAP_LABEL);
    if (wrap_key.empty()) return {};
    auto wipe = make_scope_exit([&] { CryptoEngine::secure_wipe(wrap_key); });
    std::vector<uint8_t> nonce(blob.begin(), blob.begin() + 12), sealed(blob.begin() + 12, blob.end());
    auto plain = CryptoEngine::decrypt(wrap_key, nonce, sealed,
                                       std::vector<uint8_t>(ACCESS_WRAP_AAD, ACCESS_WRAP_AAD + sizeof(ACCESS_WRAP_AAD) - 1));
    if (!plain || plain->size() != CryptoEngine::sig_secret_key_size()) return {};
    return std::move(*plain);
}

std::optional<KeyStore::MailboxConfig> KeyStore::load_mailbox_config() const {
    auto raw = read_file_bytes(app_dir_ / "mailbox.cfg");
    if (raw.empty()) return std::nullopt;
    size_t off = 0;
    MailboxConfig c;
    auto host = read_string(raw.data(), raw.size(), off, 255);
    auto port = read_u32(raw.data(), raw.size(), off);
    auto relay_id = read_blob(raw.data(), raw.size(), off, 32);
    auto mailbox_id = read_blob(raw.data(), raw.size(), off, 16);
    if (!host || !port || *port == 0 || *port > 65535 || !relay_id || relay_id->size() != 32 || !mailbox_id ||
        mailbox_id->size() != 16 || off != raw.size())
        return std::nullopt;
    c.host = std::move(*host);
    c.port = static_cast<uint16_t>(*port);
    c.relay_id = std::move(*relay_id);
    c.mailbox_id = std::move(*mailbox_id);
    return c;
}

void KeyStore::save_mailbox_config(const MailboxConfig& config) {
    std::vector<uint8_t> raw;
    write_string(raw, config.host);
    write_u32(raw, config.port);
    write_blob(raw, config.relay_id);
    write_blob(raw, config.mailbox_id);
    write_file_atomic(app_dir_ / "mailbox.cfg", raw, false);
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
