#include "prekey_vault.h"

#include <sqlite3.h>
#include <stdexcept>

#include "crypto_engine.h"
#include "protocol.h"

namespace {

const char AAD_LABEL[] = "pq-suite v3 prekey vault";

struct Statement {
    sqlite3_stmt* s = nullptr;
    Statement(sqlite3* db, const char* sql) {
        if (sqlite3_prepare_v2(db, sql, -1, &s, nullptr) != SQLITE_OK) throw std::runtime_error(std::string("Prekey store: ") + sqlite3_errmsg(db));
    }
    ~Statement() { sqlite3_finalize(s); }
    Statement& blob(int i, const std::vector<uint8_t>& b) { sqlite3_bind_blob(s, i, b.data(), static_cast<int>(b.size()), SQLITE_TRANSIENT); return *this; }
    Statement& i64(int i, int64_t v) { sqlite3_bind_int64(s, i, v); return *this; }
    bool step() {
        int rc = sqlite3_step(s);
        if (rc == SQLITE_ROW) return true;
        if (rc == SQLITE_DONE) return false;
        throw std::runtime_error("Prekey store: a query failed");
    }
    std::vector<uint8_t> column_blob(int i) {
        const auto* p = static_cast<const uint8_t*>(sqlite3_column_blob(s, i));
        return p ? std::vector<uint8_t>(p, p + sqlite3_column_bytes(s, i)) : std::vector<uint8_t>();
    }
    int64_t column_i64(int i) { return sqlite3_column_int64(s, i); }
};

}  // namespace

PrekeyVault::PrekeyVault(const std::filesystem::path& path, const Bytes& key) : key_(key) {
    if (key_.size() != 32) throw std::runtime_error("Prekey store: the key is not valid");
    open_or_recreate(path);
}

PrekeyVault::~PrekeyVault() {
    if (db_) sqlite3_close(db_);
    CryptoEngine::secure_wipe(key_);
}

void PrekeyVault::exec(const char* sql) {
    char* err = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        std::string message = err ? err : "unknown error";
        sqlite3_free(err);
        throw std::runtime_error("Prekey store: " + message);
    }
}

void PrekeyVault::open_or_recreate(const std::filesystem::path& path) {
    for (int attempt = 0; attempt < 2; attempt++) {
        if (sqlite3_open_v2(path.string().c_str(), &db_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK) {
            try {
                exec("PRAGMA secure_delete=ON; PRAGMA journal_mode=MEMORY; PRAGMA synchronous=FULL;"
                     "CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v BLOB NOT NULL);"
                     "CREATE TABLE IF NOT EXISTS prekeys(id BLOB PRIMARY KEY, sealed BLOB NOT NULL, public_blob BLOB, last_resort INTEGER NOT NULL,"
                     "  created_at INTEGER NOT NULL, uploaded INTEGER NOT NULL DEFAULT 0, retired_at INTEGER);"
                     "SELECT COUNT(*) FROM prekeys;");
                std::error_code ec;
                std::filesystem::permissions(path, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write, std::filesystem::perm_options::replace, ec);
                return;
            } catch (const std::exception&) {
            }
        }
        // Damaged (or not a database at all): start afresh. The app notices the pool is gone and replaces it on the relay.
        if (db_) sqlite3_close(db_);
        db_ = nullptr;
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }
    throw std::runtime_error("Prekey store: could not be opened");
}

PrekeyVault::Bytes PrekeyVault::seal(const Bytes& plain, const Bytes& id) {
    Bytes aad;
    write_string(aad, AAD_LABEL);
    write_blob(aad, id);
    Bytes nonce = CryptoEngine::random_bytes(12);
    Bytes out = nonce;
    Bytes ct = CryptoEngine::encrypt(key_, nonce, plain, aad);
    out.insert(out.end(), ct.begin(), ct.end());
    return out;
}

std::optional<PrekeyVault::Bytes> PrekeyVault::unseal(const Bytes& sealed, const Bytes& id) {
    if (sealed.size() < 12 + 16) return std::nullopt;
    Bytes aad;
    write_string(aad, AAD_LABEL);
    write_blob(aad, id);
    try {
        return CryptoEngine::decrypt(key_, Bytes(sealed.begin(), sealed.begin() + 12), Bytes(sealed.begin() + 12, sealed.end()), aad);
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

PrekeyVault::Bytes PrekeyVault::generation() {
    std::lock_guard<std::mutex> lock(mutex_);
    Statement s(db_, "SELECT v FROM meta WHERE k = 'generation'");
    return s.step() ? s.column_blob(0) : Bytes();
}

void PrekeyVault::secure_erase_where(const char* where, const std::vector<Bytes>& blobs, const std::vector<int64_t>& ints) {
    // Overwrite first, then delete: with secure_delete on, SQLite also zeroes the freed space.
    std::string update = std::string("UPDATE prekeys SET sealed = zeroblob(length(sealed)), public_blob = NULL WHERE ") + where;
    std::string remove = std::string("DELETE FROM prekeys WHERE ") + where;
    for (const std::string* sql : {&update, &remove}) {
        Statement s(db_, sql->c_str());
        int i = 1;
        for (const auto& b : blobs) s.blob(i++, b);
        for (int64_t v : ints) s.i64(i++, v);
        s.step();
    }
}

void PrekeyVault::start_generation(const Bytes& generation) {
    std::lock_guard<std::mutex> lock(mutex_);
    exec("BEGIN");
    secure_erase_where("1 = 1", {}, {});
    Statement(db_, "INSERT INTO meta(k, v) VALUES('generation', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").blob(1, generation).step();
    exec("COMMIT");
}

void PrekeyVault::add(const prekey::Generated& g, int64_t now) {
    std::lock_guard<std::mutex> lock(mutex_);
    Bytes secret = prekey::encode_secret(g.secret);
    Statement(db_, "INSERT OR REPLACE INTO prekeys(id, sealed, public_blob, last_resort, created_at, uploaded, retired_at) VALUES(?, ?, ?, ?, ?, 0, NULL)")
        .blob(1, g.prekey.id).blob(2, seal(secret, g.prekey.id)).blob(3, prekey::encode(g.prekey)).i64(4, g.prekey.last_resort ? 1 : 0).i64(5, now).step();
    CryptoEngine::secure_wipe(secret);
}

std::vector<prekey::Prekey> PrekeyVault::not_uploaded() {
    std::lock_guard<std::mutex> lock(mutex_);
    Statement s(db_, "SELECT public_blob FROM prekeys WHERE uploaded = 0 AND public_blob IS NOT NULL ORDER BY last_resort, created_at, rowid");
    std::vector<prekey::Prekey> out;
    while (s.step())
        if (auto p = prekey::decode(s.column_blob(0))) out.push_back(std::move(*p));
    return out;
}

void PrekeyVault::mark_uploaded(const Bytes& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    Statement(db_, "UPDATE prekeys SET uploaded = 1, public_blob = NULL WHERE id = ?").blob(1, id).step();
}

std::optional<prekey::Secret> PrekeyVault::find(const Bytes& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    Statement s(db_, "SELECT sealed FROM prekeys WHERE id = ?");
    s.blob(1, id);
    if (!s.step()) return std::nullopt;
    auto plain = unseal(s.column_blob(0), id);
    if (!plain) return std::nullopt;
    auto secret = prekey::decode_secret(*plain);
    CryptoEngine::secure_wipe(*plain);
    return secret;
}

bool PrekeyVault::erase(const Bytes& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    secure_erase_where("id = ?", {id}, {});
    return sqlite3_changes(db_) > 0;
}

bool PrekeyVault::erase_one_time(const Bytes& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    secure_erase_where("id = ? AND last_resort = 0", {id}, {});
    return sqlite3_changes(db_) > 0;
}

std::optional<int64_t> PrekeyVault::current_last_resort_created() {
    std::lock_guard<std::mutex> lock(mutex_);
    Statement s(db_, "SELECT COALESCE(MAX(created_at), -1) FROM prekeys WHERE last_resort = 1 AND retired_at IS NULL AND uploaded = 1");
    if (!s.step() || s.column_i64(0) < 0) return std::nullopt;
    return s.column_i64(0);
}

void PrekeyVault::retire_last_resort_except(const Bytes& keep_id, int64_t now) {
    std::lock_guard<std::mutex> lock(mutex_);
    Statement(db_, "UPDATE prekeys SET retired_at = ? WHERE last_resort = 1 AND retired_at IS NULL AND id != ?").i64(1, now).blob(2, keep_id).step();
}

size_t PrekeyVault::forget_old(int64_t retired_before, int64_t unused_before) {
    std::lock_guard<std::mutex> lock(mutex_);
    exec("BEGIN");
    secure_erase_where("(last_resort = 1 AND retired_at IS NOT NULL AND retired_at < ?) OR (last_resort = 0 AND uploaded = 1 AND created_at < ?)", {}, {retired_before, unused_before});
    const size_t gone = static_cast<size_t>(sqlite3_changes(db_));
    exec("COMMIT");
    return gone;
}

PrekeyVault::Counts PrekeyVault::counts() {
    std::lock_guard<std::mutex> lock(mutex_);
    Statement s(db_, "SELECT COALESCE(SUM(last_resort = 0), 0), COALESCE(SUM(last_resort = 1 AND retired_at IS NULL), 0), COALESCE(SUM(retired_at IS NOT NULL), 0), "
                     "COALESCE(SUM(uploaded = 0), 0) FROM prekeys");
    Counts c;
    if (s.step()) {
        c.one_time = static_cast<size_t>(s.column_i64(0));
        c.last_resort = static_cast<size_t>(s.column_i64(1));
        c.retired = static_cast<size_t>(s.column_i64(2));
        c.pending = static_cast<size_t>(s.column_i64(3));
    }
    return c;
}
