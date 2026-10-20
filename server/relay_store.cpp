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
         "  expires_at INTEGER NOT NULL,"
         "  issued_by BLOB);"
         "CREATE TABLE IF NOT EXISTS mailboxes("
         "  id BLOB PRIMARY KEY,"
         "  access_public_key BLOB NOT NULL,"
         "  created_at INTEGER NOT NULL,"
         "  invited_by BLOB);"
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
         "CREATE INDEX IF NOT EXISTS envelopes_by_expiry ON envelopes(expires_at);"
         // Version 4: chat archives. Nothing here refers to a mailbox.
         "CREATE TABLE IF NOT EXISTS archives("
         "  id BLOB PRIMARY KEY,"
         "  member_count INTEGER NOT NULL,"
         "  created_at INTEGER NOT NULL,"
         "  closes_at INTEGER NOT NULL,"
         "  head_number INTEGER NOT NULL,"
         "  head_hash BLOB NOT NULL,"
         "  bytes INTEGER NOT NULL DEFAULT 0,"
         "  last_activity INTEGER NOT NULL);"
         "CREATE TABLE IF NOT EXISTS archive_join_tokens("
         "  archive_id BLOB NOT NULL REFERENCES archives(id) ON DELETE CASCADE,"
         "  token_hash BLOB NOT NULL,"
         "  PRIMARY KEY(archive_id, token_hash));"
         "CREATE TABLE IF NOT EXISTS archive_keys("
         "  archive_id BLOB NOT NULL REFERENCES archives(id) ON DELETE CASCADE,"
         "  key_hash BLOB NOT NULL,"
         "  public_key BLOB NOT NULL,"
         "  joined_at INTEGER NOT NULL,"
         "  PRIMARY KEY(archive_id, key_hash));"
         "CREATE TABLE IF NOT EXISTS archive_entries("
         "  archive_id BLOB NOT NULL REFERENCES archives(id) ON DELETE CASCADE,"
         "  number INTEGER NOT NULL,"
         "  hash BLOB NOT NULL,"
         "  ciphertext BLOB NOT NULL,"
         "  appended_at INTEGER NOT NULL,"
         "  PRIMARY KEY(archive_id, number))");

    // Schema versions: 1 = the first release (envelopes without token_hash), 2 = token hashes,
    // 3 = invites and mailboxes remember who vouched, 4 = current (chat archives; new tables only, so
    // nothing to alter). A brand-new database is created at the current shape and starts at 0.
    int64_t version = 0;
    {
        Stmt v(db_, "PRAGMA user_version");
        if (v.step()) version = v.column_i64(0);
    }
    if (version == 1) exec(db_, "ALTER TABLE envelopes ADD COLUMN token_hash BLOB");
    if (version == 1 || version == 2) {
        exec(db_, "ALTER TABLE invites ADD COLUMN issued_by BLOB");
        exec(db_, "ALTER TABLE mailboxes ADD COLUMN invited_by BLOB");
    }
    if (version < 4) exec(db_, "PRAGMA user_version=4");
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

    Bytes issued_by;  // who vouched for this invite; empty if the operator made it
    {
        Stmt invite(db_, "SELECT expires_at, issued_by FROM invites WHERE hash = ?");
        invite.blob(1, invite_hash);
        if (!invite.step() || invite.column_i64(0) <= now) return RegisterResult::BadInvite;
        issued_by = invite.column_blob(1);
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

    if (issued_by.empty())
        Stmt(db_, "INSERT INTO mailboxes(id, access_public_key, created_at) VALUES(?, ?, ?)")
            .blob(1, mailbox_id).blob(2, access_public_key).i64(3, now).step();
    else
        Stmt(db_, "INSERT INTO mailboxes(id, access_public_key, created_at, invited_by) VALUES(?, ?, ?, ?)")
            .blob(1, mailbox_id).blob(2, access_public_key).i64(3, now).blob(4, issued_by).step();
    Stmt(db_, "INSERT INTO tokens(mailbox_id, hash, created_at) VALUES(?, ?, ?)")
        .blob(1, mailbox_id).blob(2, token_hash).i64(3, now).step();
    Stmt(db_, "DELETE FROM invites WHERE hash = ?").blob(1, invite_hash).step();
    tx.commit();
    return RegisterResult::Ok;
}

RelayStore::IssueResult RelayStore::add_member_invite(const Bytes& issuer_mailbox, const Bytes& invite_hash, int64_t now,
                                                      int64_t expires_at, size_t max_outstanding, size_t max_total) {
    std::lock_guard<std::mutex> lock(mutex_);
    Transaction tx(db_);
    {
        Stmt exists(db_, "SELECT 1 FROM mailboxes WHERE id = ?");
        exists.blob(1, issuer_mailbox);
        if (!exists.step()) return IssueResult::NoSuchMailbox;
    }
    size_t outstanding = 0, used = 0;
    {
        Stmt s(db_, "SELECT COUNT(*) FROM invites WHERE issued_by = ? AND expires_at > ?");
        s.blob(1, issuer_mailbox).i64(2, now);
        if (s.step()) outstanding = static_cast<size_t>(s.column_i64(0));
    }
    {
        Stmt s(db_, "SELECT COUNT(*) FROM mailboxes WHERE invited_by = ?");
        s.blob(1, issuer_mailbox);
        if (s.step()) used = static_cast<size_t>(s.column_i64(0));
    }
    if (outstanding >= max_outstanding) return IssueResult::TooManyOutstanding;
    if (outstanding + used >= max_total) return IssueResult::TooManyIssued;
    Stmt(db_, "INSERT INTO invites(hash, expires_at, issued_by) VALUES(?, ?, ?)")
        .blob(1, invite_hash).i64(2, expires_at).blob(3, issuer_mailbox).step();
    tx.commit();
    return IssueResult::Ok;
}

std::vector<RelayStore::UnusedInvite> RelayStore::unused_invites(const Bytes& issuer_mailbox, int64_t now) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT hash, expires_at FROM invites WHERE issued_by = ? AND expires_at > ? ORDER BY expires_at, hash");
    s.blob(1, issuer_mailbox).i64(2, now);
    std::vector<UnusedInvite> out;
    while (s.step()) out.push_back({s.column_blob(0), s.column_i64(1)});
    return out;
}

std::vector<RelayStore::JoinedMember> RelayStore::joined_through(const Bytes& issuer_mailbox) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT id, created_at FROM mailboxes WHERE invited_by = ? ORDER BY created_at, id");
    s.blob(1, issuer_mailbox);
    std::vector<JoinedMember> out;
    while (s.step()) out.push_back({s.column_blob(0), s.column_i64(1)});
    return out;
}

bool RelayStore::cancel_member_invite(const Bytes& issuer_mailbox, const Bytes& invite_hash) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "DELETE FROM invites WHERE hash = ? AND issued_by = ?").blob(1, invite_hash).blob(2, issuer_mailbox).step();
    return sqlite3_changes(db_) > 0;
}

std::vector<RelayStore::Member> RelayStore::members() {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT m.id, m.created_at, m.invited_by, (SELECT COUNT(*) FROM envelopes e WHERE e.mailbox_id = m.id) "
                "FROM mailboxes m ORDER BY m.created_at, m.id");
    std::vector<Member> out;
    while (s.step()) {
        Member m;
        m.id = s.column_blob(0);
        m.created_at = s.column_i64(1);
        m.invited_by = s.column_blob(2);
        m.envelopes = static_cast<size_t>(s.column_i64(3));
        out.push_back(std::move(m));
    }
    return out;
}

bool RelayStore::delete_mailbox(const Bytes& mailbox_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    Transaction tx(db_);
    Stmt(db_, "DELETE FROM invites WHERE issued_by = ?").blob(1, mailbox_id).step();
    Stmt(db_, "DELETE FROM mailboxes WHERE id = ?").blob(1, mailbox_id).step();  // tokens and envelopes go with it
    const bool existed = sqlite3_changes(db_) > 0;
    tx.commit();
    return existed;
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

// --- Chat archives ---

RelayStore::CreateArchiveResult RelayStore::create_archive(const Bytes& archive_id, const std::vector<Bytes>& join_token_hashes,
                                                           const Bytes& genesis_hash, int64_t now, int64_t closes_at, size_t max_archives) {
    std::lock_guard<std::mutex> lock(mutex_);
    Transaction tx(db_);
    {
        Stmt exists(db_, "SELECT 1 FROM archives WHERE id = ?");
        exists.blob(1, archive_id);
        if (exists.step()) return CreateArchiveResult::Exists;
    }
    {
        Stmt count(db_, "SELECT COUNT(*) FROM archives");
        if (count.step() && static_cast<size_t>(count.column_i64(0)) >= max_archives) return CreateArchiveResult::LimitReached;
    }
    Stmt(db_, "INSERT INTO archives(id, member_count, created_at, closes_at, head_number, head_hash, bytes, last_activity) VALUES(?, ?, ?, ?, 0, ?, 0, ?)")
        .blob(1, archive_id).i64(2, static_cast<int64_t>(join_token_hashes.size())).i64(3, now).i64(4, closes_at).blob(5, genesis_hash).i64(6, now).step();
    for (const auto& h : join_token_hashes)
        Stmt(db_, "INSERT OR IGNORE INTO archive_join_tokens(archive_id, token_hash) VALUES(?, ?)").blob(1, archive_id).blob(2, h).step();
    tx.commit();
    return CreateArchiveResult::Ok;
}

RelayStore::JoinResult RelayStore::join_archive(const Bytes& archive_id, const Bytes& token_hash, const Bytes& key_hash,
                                                const Bytes& public_key, int64_t now) {
    std::lock_guard<std::mutex> lock(mutex_);
    Transaction tx(db_);
    int64_t member_count = 0, closes_at = 0;
    {
        Stmt a(db_, "SELECT member_count, closes_at FROM archives WHERE id = ?");
        a.blob(1, archive_id);
        if (!a.step()) return JoinResult::NoSuchArchive;
        member_count = a.column_i64(0);
        closes_at = a.column_i64(1);
    }
    {
        Stmt token(db_, "SELECT 1 FROM archive_join_tokens WHERE archive_id = ? AND token_hash = ?");
        token.blob(1, archive_id).blob(2, token_hash);
        if (!token.step()) return JoinResult::BadToken;
    }
    int64_t joined = 0;
    {
        Stmt n(db_, "SELECT COUNT(*) FROM archive_keys WHERE archive_id = ?");
        n.blob(1, archive_id);
        if (n.step()) joined = n.column_i64(0);
    }
    if (joined >= member_count || now >= closes_at) return JoinResult::Closed;
    {
        Stmt key(db_, "SELECT 1 FROM archive_keys WHERE archive_id = ? AND key_hash = ?");
        key.blob(1, archive_id).blob(2, key_hash);
        if (key.step()) return JoinResult::KeyExists;
    }
    Stmt(db_, "INSERT INTO archive_keys(archive_id, key_hash, public_key, joined_at) VALUES(?, ?, ?, ?)")
        .blob(1, archive_id).blob(2, key_hash).blob(3, public_key).i64(4, now).step();
    Stmt(db_, "DELETE FROM archive_join_tokens WHERE archive_id = ? AND token_hash = ?").blob(1, archive_id).blob(2, token_hash).step();
    tx.commit();
    return JoinResult::Ok;
}

std::optional<Bytes> RelayStore::archive_member_key(const Bytes& archive_id, const Bytes& key_hash) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT public_key FROM archive_keys WHERE archive_id = ? AND key_hash = ?");
    s.blob(1, archive_id).blob(2, key_hash);
    if (!s.step()) return std::nullopt;
    return s.column_blob(0);
}

std::optional<RelayStore::ArchiveInfo> RelayStore::archive_info(const Bytes& archive_id, int64_t now) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt a(db_, "SELECT member_count, closes_at, head_number, head_hash, bytes FROM archives WHERE id = ?");
    a.blob(1, archive_id);
    if (!a.step()) return std::nullopt;
    ArchiveInfo info;
    info.member_count = static_cast<size_t>(a.column_i64(0));
    const int64_t closes_at = a.column_i64(1);
    info.head.number = static_cast<uint64_t>(a.column_i64(2));
    info.head.hash = a.column_blob(3);
    info.bytes = static_cast<uint64_t>(a.column_i64(4));
    Stmt n(db_, "SELECT COUNT(*) FROM archive_keys WHERE archive_id = ?");
    n.blob(1, archive_id);
    if (n.step()) info.joined = static_cast<size_t>(n.column_i64(0));
    info.registration_open = info.joined < info.member_count && now < closes_at;
    return info;
}

size_t RelayStore::archive_count() {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT COUNT(*) FROM archives");
    return s.step() ? static_cast<size_t>(s.column_i64(0)) : 0;
}

RelayStore::AppendResult RelayStore::append_entry(const Bytes& archive_id, uint64_t expected_number, const Bytes& expected_hash,
                                                  const Bytes& new_hash, const Bytes& ciphertext, int64_t now, size_t quota_bytes,
                                                  ArchiveState* head) {
    std::lock_guard<std::mutex> lock(mutex_);
    Transaction tx(db_);
    ArchiveState current;
    uint64_t bytes = 0;
    {
        Stmt a(db_, "SELECT head_number, head_hash, bytes FROM archives WHERE id = ?");
        a.blob(1, archive_id);
        if (!a.step()) return AppendResult::NoSuchArchive;
        current.number = static_cast<uint64_t>(a.column_i64(0));
        current.hash = a.column_blob(1);
        bytes = static_cast<uint64_t>(a.column_i64(2));
    }
    if (head) *head = current;
    // Compare and swap: only if the sender extended the head that is still the head.
    if (current.number != expected_number || current.hash != expected_hash) return AppendResult::Stale;
    if (bytes + ciphertext.size() > quota_bytes) return AppendResult::ArchiveFull;

    const uint64_t number = current.number + 1;
    Stmt(db_, "INSERT INTO archive_entries(archive_id, number, hash, ciphertext, appended_at) VALUES(?, ?, ?, ?, ?)")
        .blob(1, archive_id).i64(2, static_cast<int64_t>(number)).blob(3, new_hash).blob(4, ciphertext).i64(5, now).step();
    Stmt(db_, "UPDATE archives SET head_number = ?, head_hash = ?, bytes = ?, last_activity = ? WHERE id = ?")
        .i64(1, static_cast<int64_t>(number)).blob(2, new_hash).i64(3, static_cast<int64_t>(bytes + ciphertext.size())).i64(4, now).blob(5, archive_id).step();
    tx.commit();
    if (head) {
        head->number = number;
        head->hash = new_hash;
    }
    return AppendResult::Ok;
}

std::vector<RelayStore::StoredEntry> RelayStore::fetch_entries(const Bytes& archive_id, uint64_t from_number, size_t limit) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT number, hash, ciphertext FROM archive_entries WHERE archive_id = ? AND number >= ? ORDER BY number LIMIT ?");
    s.blob(1, archive_id).i64(2, static_cast<int64_t>(from_number)).i64(3, static_cast<int64_t>(limit));
    std::vector<StoredEntry> out;
    while (s.step()) out.push_back({static_cast<uint64_t>(s.column_i64(0)), s.column_blob(1), s.column_blob(2)});
    return out;
}

RelayStore::Swept RelayStore::sweep(int64_t now) {
    std::lock_guard<std::mutex> lock(mutex_);
    Swept swept;
    Stmt(db_, "DELETE FROM envelopes WHERE expires_at <= ?").i64(1, now).step();
    swept.envelopes = static_cast<size_t>(sqlite3_changes(db_));
    Stmt(db_, "DELETE FROM invites WHERE expires_at <= ?").i64(1, now).step();
    swept.invites = static_cast<size_t>(sqlite3_changes(db_));
    // An archive nobody joined in time was abandoned (its tokens are dead): don't keep it.
    Stmt(db_, "DELETE FROM archives WHERE closes_at <= ? AND NOT EXISTS (SELECT 1 FROM archive_keys WHERE archive_id = archives.id)")
        .i64(1, now).step();
    swept.archives = static_cast<size_t>(sqlite3_changes(db_));
    return swept;
}

}  // namespace relay
