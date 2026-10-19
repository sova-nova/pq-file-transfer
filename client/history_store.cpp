#include "history_store.h"

#include "crypto_engine.h"
#include "protocol.h"
#include "sqlite_helpers.h"

#include <algorithm>
#include <stdexcept>

using sqlitex::exec;
using sqlitex::Stmt;
using sqlitex::Transaction;

namespace {

using Bytes = std::vector<uint8_t>;

Bytes aad_of(const char* label, const Bytes& a, const Bytes& b = {}) {
    Bytes out;
    write_string(out, label);
    write_blob(out, a);
    write_blob(out, b);
    return out;
}

Bytes pack(const std::vector<Bytes>& list) {
    Bytes out;
    write_u32(out, static_cast<uint32_t>(list.size()));
    for (const auto& item : list) write_blob(out, item);
    return out;
}

std::optional<std::vector<Bytes>> unpack(const Bytes& in) {
    size_t off = 0;
    auto count = read_u32(in.data(), in.size(), off);
    if (!count || *count > 4096) return std::nullopt;
    std::vector<Bytes> out;
    for (uint32_t i = 0; i < *count; i++) {
        auto item = read_blob(in.data(), in.size(), off, 1 << 20);
        if (!item) return std::nullopt;
        out.push_back(std::move(*item));
    }
    if (off != in.size()) return std::nullopt;
    return out;
}

}  // namespace

HistoryStore::HistoryStore(const std::filesystem::path& db_path, const Bytes& history_key) : key_(history_key) {
    if (key_.size() != 32) throw std::runtime_error("The history key must be 32 bytes");
    std::string path = db_path.u8string();
    if (sqlite3_open_v2(path.c_str(), &db_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr) != SQLITE_OK) {
        std::string msg = db_ ? sqlite3_errmsg(db_) : "out of memory";
        sqlite3_close(db_);
        db_ = nullptr;
        throw std::runtime_error("Cannot open the message history " + path + ": " + msg);
    }
    sqlite3_busy_timeout(db_, 5000);
    exec(db_, "PRAGMA journal_mode=WAL");
    exec(db_, "PRAGMA synchronous=FULL");
    exec(db_, "PRAGMA foreign_keys=ON");
    exec(db_,
         "CREATE TABLE IF NOT EXISTS conversations("
         "  id BLOB PRIMARY KEY, contact_fp TEXT NOT NULL UNIQUE,"
         "  created_at INTEGER NOT NULL, last_activity INTEGER NOT NULL,"
         "  send_delivery INTEGER NOT NULL DEFAULT 1, send_read INTEGER NOT NULL DEFAULT 1);"
         "CREATE TABLE IF NOT EXISTS messages("
         "  row INTEGER PRIMARY KEY AUTOINCREMENT,"
         "  conv_id BLOB NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,"
         "  msg_id BLOB NOT NULL, outgoing INTEGER NOT NULL,"
         "  sent_at INTEGER NOT NULL, received_at INTEGER NOT NULL,"
         "  status INTEGER NOT NULL, gap INTEGER NOT NULL DEFAULT 0,"
         "  entry_hash BLOB NOT NULL, sealed BLOB NOT NULL,"
         "  UNIQUE(conv_id, msg_id));"
         "CREATE INDEX IF NOT EXISTS messages_by_hash ON messages(conv_id, entry_hash);"
         "CREATE TABLE IF NOT EXISTS outbox("
         "  id INTEGER PRIMARY KEY AUTOINCREMENT, contact_fp TEXT NOT NULL, kind INTEGER NOT NULL,"
         "  msg_id BLOB NOT NULL, sealed BLOB NOT NULL, due_at INTEGER NOT NULL,"
         "  attempts INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);"
         "CREATE TABLE IF NOT EXISTS requests("
         "  id INTEGER PRIMARY KEY AUTOINCREMENT, sender_fp TEXT NOT NULL,"
         "  bundle BLOB NOT NULL, received_at INTEGER NOT NULL, sealed BLOB NOT NULL);"
         "CREATE TABLE IF NOT EXISTS issued_tokens("
         "  token_hash BLOB PRIMARY KEY, label TEXT NOT NULL, created_at INTEGER NOT NULL,"
         "  bound_fp TEXT NOT NULL DEFAULT '', revoked INTEGER NOT NULL DEFAULT 0);"
         "CREATE TABLE IF NOT EXISTS contact_state("
         "  contact_fp TEXT PRIMARY KEY, bundle_sent INTEGER NOT NULL DEFAULT 0);"
         "PRAGMA user_version=1");
}

HistoryStore::~HistoryStore() {
    CryptoEngine::secure_wipe(key_);
    sqlite3_close(db_);
}

HistoryStore::Bytes HistoryStore::seal(const Bytes& plaintext, const Bytes& aad) const {
    Bytes nonce = CryptoEngine::random_bytes(12);
    Bytes ct = CryptoEngine::encrypt(key_, nonce, plaintext, aad);
    Bytes out = nonce;
    out.insert(out.end(), ct.begin(), ct.end());
    return out;
}

std::optional<HistoryStore::Bytes> HistoryStore::unseal(const Bytes& sealed, const Bytes& aad) const {
    if (sealed.size() < 12 + 16) return std::nullopt;
    Bytes nonce(sealed.begin(), sealed.begin() + 12), ct(sealed.begin() + 12, sealed.end());
    try {
        return CryptoEngine::decrypt(key_, nonce, ct, aad);
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

// --- Conversations ---

static HistoryStore::Conversation read_conversation(Stmt& s) {
    HistoryStore::Conversation c;
    c.id = s.column_blob(0);
    c.contact_fp = s.column_text(1);
    c.created_at = s.column_i64(2);
    c.last_activity = s.column_i64(3);
    c.send_delivery_receipts = s.column_i64(4) != 0;
    c.send_read_receipts = s.column_i64(5) != 0;
    return c;
}

HistoryStore::Conversation HistoryStore::ensure_conversation(const Bytes& id, const std::string& contact_fp, int64_t now) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "INSERT OR IGNORE INTO conversations(id, contact_fp, created_at, last_activity) VALUES(?, ?, ?, ?)")
        .blob(1, id).text(2, contact_fp).i64(3, now).i64(4, now).step();
    Stmt s(db_, "SELECT id, contact_fp, created_at, last_activity, send_delivery, send_read FROM conversations WHERE contact_fp = ?");
    s.text(1, contact_fp);
    if (!s.step()) throw std::runtime_error("database: conversation missing after insert");
    return read_conversation(s);
}

std::optional<HistoryStore::Conversation> HistoryStore::conversation_for(const std::string& contact_fp) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT id, contact_fp, created_at, last_activity, send_delivery, send_read FROM conversations WHERE contact_fp = ?");
    s.text(1, contact_fp);
    if (!s.step()) return std::nullopt;
    return read_conversation(s);
}

std::vector<HistoryStore::Conversation> HistoryStore::conversations() {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT id, contact_fp, created_at, last_activity, send_delivery, send_read FROM conversations ORDER BY last_activity DESC");
    std::vector<Conversation> out;
    while (s.step()) out.push_back(read_conversation(s));
    return out;
}

void HistoryStore::set_receipt_settings(const Bytes& conversation_id, bool delivery, bool read) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "UPDATE conversations SET send_delivery = ?, send_read = ? WHERE id = ?")
        .i64(1, delivery ? 1 : 0).i64(2, read ? 1 : 0).blob(3, conversation_id).step();
}

// --- Messages ---

bool HistoryStore::add_message(const Message& m) {
    std::lock_guard<std::mutex> lock(mutex_);
    Transaction tx(db_);
    {
        Stmt dup(db_, "SELECT 1 FROM messages WHERE conv_id = ? AND msg_id = ?");
        dup.blob(1, m.conversation_id).blob(2, m.message_id);
        if (dup.step()) return false;
    }
    Bytes sealed = seal(m.record, aad_of("pq-suite v3 history message", m.conversation_id, m.message_id));
    Stmt(db_, "INSERT INTO messages(conv_id, msg_id, outgoing, sent_at, received_at, status, gap, entry_hash, sealed) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .blob(1, m.conversation_id).blob(2, m.message_id).i64(3, m.outgoing ? 1 : 0).i64(4, m.sent_at).i64(5, m.received_at)
        .i64(6, m.status).i64(7, m.gap ? 1 : 0).blob(8, m.entry_hash).blob(9, sealed).step();
    Stmt(db_, "UPDATE conversations SET last_activity = MAX(last_activity, ?) WHERE id = ?")
        .i64(1, std::max(m.sent_at, m.received_at)).blob(2, m.conversation_id).step();
    tx.commit();
    return true;
}

template <typename Unseal>
static bool read_message(Stmt& s, HistoryStore::Message& out, const Unseal& unseal) {
    out.row = s.column_i64(0);
    out.conversation_id = s.column_blob(1);
    out.message_id = s.column_blob(2);
    out.outgoing = s.column_i64(3) != 0;
    out.sent_at = s.column_i64(4);
    out.received_at = s.column_i64(5);
    out.status = static_cast<int>(s.column_i64(6));
    out.gap = s.column_i64(7) != 0;
    out.entry_hash = s.column_blob(8);
    auto plain = unseal(s.column_blob(9), aad_of("pq-suite v3 history message", out.conversation_id, out.message_id));
    if (!plain) return false;  // damaged, or sealed under a different key
    out.record = std::move(*plain);
    return true;
}

std::vector<HistoryStore::Message> HistoryStore::messages(const Bytes& conversation_id, size_t limit) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT row, conv_id, msg_id, outgoing, sent_at, received_at, status, gap, entry_hash, sealed "
                "FROM messages WHERE conv_id = ? ORDER BY row DESC LIMIT ?");
    s.blob(1, conversation_id).i64(2, static_cast<int64_t>(limit));
    auto opener = [this](const Bytes& sealed, const Bytes& aad) { return unseal(sealed, aad); };
    std::vector<Message> out;
    while (s.step()) {
        Message m;
        if (read_message(s, m, opener)) out.push_back(std::move(m));
    }
    std::reverse(out.begin(), out.end());
    return out;
}

std::optional<HistoryStore::Message> HistoryStore::find_message(const Bytes& conversation_id, const Bytes& message_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT row, conv_id, msg_id, outgoing, sent_at, received_at, status, gap, entry_hash, sealed "
                "FROM messages WHERE conv_id = ? AND msg_id = ?");
    s.blob(1, conversation_id).blob(2, message_id);
    if (!s.step()) return std::nullopt;
    Message m;
    auto opener = [this](const Bytes& sealed, const Bytes& aad) { return unseal(sealed, aad); };
    if (!read_message(s, m, opener)) return std::nullopt;
    return m;
}

bool HistoryStore::raise_status(const Bytes& conversation_id, const Bytes& message_id, int status) {
    std::lock_guard<std::mutex> lock(mutex_);
    // Only outgoing messages, and only upwards: a late "delivered" never undoes a "read".
    Stmt(db_, "UPDATE messages SET status = ? WHERE conv_id = ? AND msg_id = ? AND outgoing = 1 AND status < ?")
        .i64(1, status).blob(2, conversation_id).blob(3, message_id).i64(4, status).step();
    return sqlite3_changes(db_) > 0;
}

bool HistoryStore::has_entry(const Bytes& conversation_id, const Bytes& entry_hash) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT 1 FROM messages WHERE conv_id = ? AND entry_hash = ?");
    s.blob(1, conversation_id).blob(2, entry_hash);
    return s.step();
}

std::optional<HistoryStore::Bytes> HistoryStore::last_entry_hash(const Bytes& conversation_id, bool outgoing) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT entry_hash FROM messages WHERE conv_id = ? AND outgoing = ? ORDER BY row DESC LIMIT 1");
    s.blob(1, conversation_id).i64(2, outgoing ? 1 : 0);
    if (!s.step()) return std::nullopt;
    return s.column_blob(0);
}

size_t HistoryStore::unread_count(const Bytes& conversation_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT COUNT(*) FROM messages WHERE conv_id = ? AND outgoing = 0 AND status = 0");
    s.blob(1, conversation_id);
    return s.step() ? static_cast<size_t>(s.column_i64(0)) : 0;
}

std::vector<HistoryStore::Bytes> HistoryStore::mark_all_read(const Bytes& conversation_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    Transaction tx(db_);
    std::vector<Bytes> ids;
    {
        Stmt s(db_, "SELECT msg_id FROM messages WHERE conv_id = ? AND outgoing = 0 AND status = 0 ORDER BY row");
        s.blob(1, conversation_id);
        while (s.step()) ids.push_back(s.column_blob(0));
    }
    Stmt(db_, "UPDATE messages SET status = 1 WHERE conv_id = ? AND outgoing = 0 AND status = 0").blob(1, conversation_id).step();
    tx.commit();
    return ids;
}

// --- Outbox ---

int64_t HistoryStore::enqueue(const std::string& contact_fp, int kind, const Bytes& message_id,
                              const std::vector<Bytes>& records, int64_t due_at, int64_t now) {
    std::lock_guard<std::mutex> lock(mutex_);
    Bytes sealed = seal(pack(records), aad_of("pq-suite v3 history outbox", message_id, Bytes{static_cast<uint8_t>(kind)}));
    Stmt(db_, "INSERT INTO outbox(contact_fp, kind, msg_id, sealed, due_at, created_at) VALUES(?, ?, ?, ?, ?, ?)")
        .text(1, contact_fp).i64(2, kind).blob(3, message_id).blob(4, sealed).i64(5, due_at).i64(6, now).step();
    return sqlite3_last_insert_rowid(db_);
}

std::vector<HistoryStore::OutboxItem> HistoryStore::due_items(int64_t now, size_t limit) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT id, contact_fp, kind, msg_id, sealed, due_at, attempts FROM outbox WHERE due_at <= ? ORDER BY id LIMIT ?");
    s.i64(1, now).i64(2, static_cast<int64_t>(limit));
    std::vector<OutboxItem> out;
    while (s.step()) {
        OutboxItem item;
        item.id = s.column_i64(0);
        item.contact_fp = s.column_text(1);
        item.kind = static_cast<int>(s.column_i64(2));
        item.message_id = s.column_blob(3);
        item.due_at = s.column_i64(5);
        item.attempts = static_cast<int>(s.column_i64(6));
        auto plain = unseal(s.column_blob(4), aad_of("pq-suite v3 history outbox", item.message_id, Bytes{static_cast<uint8_t>(item.kind)}));
        auto records = plain ? unpack(*plain) : std::nullopt;
        if (!records) continue;
        item.records = std::move(*records);
        out.push_back(std::move(item));
    }
    return out;
}

void HistoryStore::update_outbox_records(int64_t id, const std::vector<Bytes>& records) {
    std::lock_guard<std::mutex> lock(mutex_);
    Bytes message_id;
    int kind = 0;
    {
        Stmt s(db_, "SELECT msg_id, kind FROM outbox WHERE id = ?");
        s.i64(1, id);
        if (!s.step()) return;
        message_id = s.column_blob(0);
        kind = static_cast<int>(s.column_i64(1));
    }
    Bytes sealed = seal(pack(records), aad_of("pq-suite v3 history outbox", message_id, Bytes{static_cast<uint8_t>(kind)}));
    Stmt(db_, "UPDATE outbox SET sealed = ? WHERE id = ?").blob(1, sealed).i64(2, id).step();
}

void HistoryStore::outbox_failed(int64_t id, int64_t next_due) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "UPDATE outbox SET attempts = attempts + 1, due_at = ? WHERE id = ?").i64(1, next_due).i64(2, id).step();
}

void HistoryStore::outbox_done(int64_t id) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "DELETE FROM outbox WHERE id = ?").i64(1, id).step();
}

size_t HistoryStore::outbox_size() {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT COUNT(*) FROM outbox");
    return s.step() ? static_cast<size_t>(s.column_i64(0)) : 0;
}

// --- Requests ---

void HistoryStore::add_request(const std::string& sender_fp, const Bytes& bundle, const std::vector<Bytes>& records, int64_t now) {
    std::lock_guard<std::mutex> lock(mutex_);
    Bytes sealed = seal(pack(records), aad_of("pq-suite v3 history request", Bytes(sender_fp.begin(), sender_fp.end())));
    Stmt(db_, "INSERT INTO requests(sender_fp, bundle, received_at, sealed) VALUES(?, ?, ?, ?)")
        .text(1, sender_fp).blob(2, bundle).i64(3, now).blob(4, sealed).step();
}

std::vector<HistoryStore::Request> HistoryStore::requests() {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT id, sender_fp, bundle, received_at, sealed FROM requests ORDER BY id");
    std::vector<Request> out;
    while (s.step()) {
        Request r;
        r.id = s.column_i64(0);
        r.sender_fp = s.column_text(1);
        r.bundle = s.column_blob(2);
        r.received_at = s.column_i64(3);
        auto plain = unseal(s.column_blob(4), aad_of("pq-suite v3 history request", Bytes(r.sender_fp.begin(), r.sender_fp.end())));
        auto records = plain ? unpack(*plain) : std::nullopt;
        if (!records) continue;
        r.records = std::move(*records);
        out.push_back(std::move(r));
    }
    return out;
}

size_t HistoryStore::request_count() {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT COUNT(*) FROM requests");
    return s.step() ? static_cast<size_t>(s.column_i64(0)) : 0;
}

void HistoryStore::delete_requests(const std::string& sender_fp) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "DELETE FROM requests WHERE sender_fp = ?").text(1, sender_fp).step();
}

// --- Issued tokens ---

void HistoryStore::add_issued_token(const Bytes& hash, const std::string& label, const std::string& bound_fp, int64_t now) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "INSERT OR REPLACE INTO issued_tokens(token_hash, label, created_at, bound_fp, revoked) VALUES(?, ?, ?, ?, 0)")
        .blob(1, hash).text(2, label).i64(3, now).text(4, bound_fp).step();
}

static HistoryStore::IssuedToken read_token(Stmt& s) {
    HistoryStore::IssuedToken t;
    t.hash = s.column_blob(0);
    t.label = s.column_text(1);
    t.created_at = s.column_i64(2);
    t.bound_fp = s.column_text(3);
    t.revoked = s.column_i64(4) != 0;
    return t;
}

std::optional<HistoryStore::IssuedToken> HistoryStore::find_issued_token(const Bytes& hash) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT token_hash, label, created_at, bound_fp, revoked FROM issued_tokens WHERE token_hash = ?");
    s.blob(1, hash);
    if (!s.step()) return std::nullopt;
    return read_token(s);
}

std::vector<HistoryStore::IssuedToken> HistoryStore::issued_tokens() {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT token_hash, label, created_at, bound_fp, revoked FROM issued_tokens ORDER BY created_at DESC, rowid DESC");
    std::vector<IssuedToken> out;
    while (s.step()) out.push_back(read_token(s));
    return out;
}

void HistoryStore::bind_issued_token(const Bytes& hash, const std::string& fp) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "UPDATE issued_tokens SET bound_fp = ? WHERE token_hash = ? AND bound_fp = ''").text(1, fp).blob(2, hash).step();
}

void HistoryStore::mark_token_revoked(const Bytes& hash) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "UPDATE issued_tokens SET revoked = 1 WHERE token_hash = ?").blob(1, hash).step();
}

// --- First-contact state ---

bool HistoryStore::bundle_sent(const std::string& contact_fp) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT bundle_sent FROM contact_state WHERE contact_fp = ?");
    s.text(1, contact_fp);
    return s.step() && s.column_i64(0) != 0;
}

void HistoryStore::set_bundle_sent(const std::string& contact_fp) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "INSERT INTO contact_state(contact_fp, bundle_sent) VALUES(?, 1) ON CONFLICT(contact_fp) DO UPDATE SET bundle_sent = 1")
        .text(1, contact_fp).step();
}
