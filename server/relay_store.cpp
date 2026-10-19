#include "relay_store.h"

#include "sqlite_helpers.h"

#include <stdexcept>
#include <string>

namespace relay {

using sqlitex::exec;
using sqlitex::Stmt;
using sqlitex::Transaction;


RelayStore::RelayStore(const std::filesystem::path& db_path) {
    std::string path = db_path.u8string();  // SQLite wants UTF-8 (matters for non-ASCII paths on Windows)
    if (sqlite3_open_v2(path.c_str(), &db_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr) != SQLITE_OK) {
        std::string msg = db_ ? sqlite3_errmsg(db_) : "out of memory";
        sqlite3_close(db_);
        db_ = nullptr;
        throw std::runtime_error("Cannot open relay database " + path + ": " + msg);
    }
    sqlite3_busy_timeout(db_, 5000);
    exec(db_, "PRAGMA journal_mode=WAL");
    exec(db_, "PRAGMA synchronous=FULL");
    exec(db_, "PRAGMA foreign_keys=ON");
    exec(db_,
         "CREATE TABLE IF NOT EXISTS invites("
         "  hash BLOB PRIMARY KEY,"
         "  expires_at INTEGER NOT NULL);"
         "CREATE TABLE IF NOT EXISTS mailboxes("
         "  id BLOB PRIMARY KEY,"
         "  access_public_key BLOB NOT NULL,"
         "  created_at INTEGER NOT NULL);"
         "CREATE TABLE IF NOT EXISTS tokens("
         "  mailbox_id BLOB NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,"
         "  hash BLOB NOT NULL,"
         "  created_at INTEGER NOT NULL,"
         "  PRIMARY KEY(mailbox_id, hash));"
         "CREATE TABLE IF NOT EXISTS envelopes("
         "  seq INTEGER PRIMARY KEY AUTOINCREMENT,"
         "  id BLOB NOT NULL UNIQUE,"
         "  mailbox_id BLOB NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,"
         "  size INTEGER NOT NULL,"
         "  envelope BLOB NOT NULL,"
         "  deposited_at INTEGER NOT NULL,"
         "  expires_at INTEGER NOT NULL,"
         "  token_hash BLOB);"
         "CREATE INDEX IF NOT EXISTS envelopes_by_mailbox ON envelopes(mailbox_id, seq);"
         "CREATE INDEX IF NOT EXISTS envelopes_by_expiry ON envelopes(expires_at)");

    // Schema versions: 1 = the first release (envelopes without token_hash), 2 = current.
    // A brand-new database is created at the current shape and starts at 0.
    int64_t version = 0;
    {
        Stmt v(db_, "PRAGMA user_version");
        if (v.step()) version = v.column_i64(0);
    }
    if (version == 1) exec(db_, "ALTER TABLE envelopes ADD COLUMN token_hash BLOB");
    if (version < 2) exec(db_, "PRAGMA user_version=2");
}

RelayStore::~RelayStore() { sqlite3_close(db_); }

void RelayStore::add_invite(const Bytes& invite_hash, int64_t expires_at) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "INSERT INTO invites(hash, expires_at) VALUES(?, ?)").blob(1, invite_hash).i64(2, expires_at).step();
}

RelayStore::RegisterResult RelayStore::register_mailbox(const Bytes& invite_hash, const Bytes& mailbox_id,
                                                        const Bytes& access_public_key, const Bytes& token_hash,
                                                        int64_t now, size_t max_mailboxes) {
    std::lock_guard<std::mutex> lock(mutex_);
    Transaction tx(db_);

    {
        Stmt invite(db_, "SELECT expires_at FROM invites WHERE hash = ?");
        invite.blob(1, invite_hash);
        if (!invite.step() || invite.column_i64(0) <= now) return RegisterResult::BadInvite;
    }
    {
        Stmt count(db_, "SELECT COUNT(*) FROM mailboxes");
        if (count.step() && static_cast<size_t>(count.column_i64(0)) >= max_mailboxes) return RegisterResult::LimitReached;
    }
    {
        Stmt exists(db_, "SELECT 1 FROM mailboxes WHERE id = ?");
        exists.blob(1, mailbox_id);
        if (exists.step()) return RegisterResult::MailboxExists;
    }

    Stmt(db_, "INSERT INTO mailboxes(id, access_public_key, created_at) VALUES(?, ?, ?)")
        .blob(1, mailbox_id).blob(2, access_public_key).i64(3, now).step();
    Stmt(db_, "INSERT INTO tokens(mailbox_id, hash, created_at) VALUES(?, ?, ?)")
        .blob(1, mailbox_id).blob(2, token_hash).i64(3, now).step();
    Stmt(db_, "DELETE FROM invites WHERE hash = ?").blob(1, invite_hash).step();
    tx.commit();
    return RegisterResult::Ok;
}

std::optional<Bytes> RelayStore::access_key(const Bytes& mailbox_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT access_public_key FROM mailboxes WHERE id = ?");
    s.blob(1, mailbox_id);
    if (!s.step()) return std::nullopt;
    return s.column_blob(0);
}

size_t RelayStore::mailbox_count() {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT COUNT(*) FROM mailboxes");
    return s.step() ? static_cast<size_t>(s.column_i64(0)) : 0;
}

bool RelayStore::token_valid(const Bytes& mailbox_id, const Bytes& token_hash) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT 1 FROM tokens WHERE mailbox_id = ? AND hash = ?");
    s.blob(1, mailbox_id).blob(2, token_hash);
    return s.step();
}

RelayStore::TokenResult RelayStore::add_token(const Bytes& mailbox_id, const Bytes& token_hash, int64_t now,
                                              size_t max_tokens) {
    std::lock_guard<std::mutex> lock(mutex_);
    Transaction tx(db_);
    {
        Stmt exists(db_, "SELECT 1 FROM mailboxes WHERE id = ?");
        exists.blob(1, mailbox_id);
        if (!exists.step()) return TokenResult::NoSuchMailbox;
    }
    {
        Stmt have(db_, "SELECT 1 FROM tokens WHERE mailbox_id = ? AND hash = ?");
        have.blob(1, mailbox_id).blob(2, token_hash);
        if (have.step()) return TokenResult::Ok;  // adding twice is harmless
    }
    {
        Stmt count(db_, "SELECT COUNT(*) FROM tokens WHERE mailbox_id = ?");
        count.blob(1, mailbox_id);
        if (count.step() && static_cast<size_t>(count.column_i64(0)) >= max_tokens) return TokenResult::LimitReached;
    }
    Stmt(db_, "INSERT INTO tokens(mailbox_id, hash, created_at) VALUES(?, ?, ?)")
        .blob(1, mailbox_id).blob(2, token_hash).i64(3, now).step();
    tx.commit();
    return TokenResult::Ok;
}

bool RelayStore::revoke_token(const Bytes& mailbox_id, const Bytes& token_hash) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "DELETE FROM tokens WHERE mailbox_id = ? AND hash = ?").blob(1, mailbox_id).blob(2, token_hash).step();
    return sqlite3_changes(db_) > 0;
}

RelayStore::DepositResult RelayStore::deposit(const Bytes& mailbox_id, const Bytes& envelope_id, const Bytes& envelope,
                                              const Bytes& token_hash, int64_t now, uint32_t ttl_seconds, size_t quota_bytes) {
    std::lock_guard<std::mutex> lock(mutex_);
    Transaction tx(db_);
    {
        Stmt used(db_, "SELECT COALESCE(SUM(size), 0) FROM envelopes WHERE mailbox_id = ? AND expires_at > ?");
        used.blob(1, mailbox_id).i64(2, now);
        size_t bytes = used.step() ? static_cast<size_t>(used.column_i64(0)) : 0;
        if (bytes + envelope.size() > quota_bytes) return DepositResult::MailboxFull;
    }
    Stmt(db_, "INSERT INTO envelopes(id, mailbox_id, size, envelope, deposited_at, expires_at, token_hash) VALUES(?, ?, ?, ?, ?, ?, ?)")
        .blob(1, envelope_id).blob(2, mailbox_id).i64(3, static_cast<int64_t>(envelope.size()))
        .blob(4, envelope).i64(5, now).i64(6, now + static_cast<int64_t>(ttl_seconds)).blob(7, token_hash).step();
    tx.commit();
    return DepositResult::Ok;
}

std::vector<RelayStore::Stored> RelayStore::fetch(const Bytes& mailbox_id, int64_t after_seq, int64_t now, size_t limit) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT seq, id, deposited_at, envelope, token_hash FROM envelopes "
                "WHERE mailbox_id = ? AND seq > ? AND expires_at > ? ORDER BY seq LIMIT ?");
    s.blob(1, mailbox_id).i64(2, after_seq).i64(3, now).i64(4, static_cast<int64_t>(limit));
    std::vector<Stored> out;
    while (s.step()) {
        Bytes token_hash = s.column_blob(4);
        if (token_hash.size() != 32) token_hash.assign(32, 0);  // stored before token hashes were recorded
        out.push_back({s.column_i64(0), s.column_blob(1), s.column_i64(2), std::move(token_hash), s.column_blob(3)});
    }
    return out;
}

size_t RelayStore::ack(const Bytes& mailbox_id, const std::vector<Bytes>& envelope_ids) {
    std::lock_guard<std::mutex> lock(mutex_);
    Transaction tx(db_);
    size_t deleted = 0;
    for (const auto& id : envelope_ids) {
        Stmt(db_, "DELETE FROM envelopes WHERE mailbox_id = ? AND id = ?").blob(1, mailbox_id).blob(2, id).step();
        deleted += static_cast<size_t>(sqlite3_changes(db_));
    }
    tx.commit();
    return deleted;
}

size_t RelayStore::envelope_count(const Bytes& mailbox_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT COUNT(*) FROM envelopes WHERE mailbox_id = ?");
    s.blob(1, mailbox_id);
    return s.step() ? static_cast<size_t>(s.column_i64(0)) : 0;
}

RelayStore::Swept RelayStore::sweep(int64_t now) {
    std::lock_guard<std::mutex> lock(mutex_);
    Swept swept;
    Stmt(db_, "DELETE FROM envelopes WHERE expires_at <= ?").i64(1, now).step();
    swept.envelopes = static_cast<size_t>(sqlite3_changes(db_));
    Stmt(db_, "DELETE FROM invites WHERE expires_at <= ?").i64(1, now).step();
    swept.invites = static_cast<size_t>(sqlite3_changes(db_));
    return swept;
}

}  // namespace relay
