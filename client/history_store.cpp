#include "history_store.h"

#include "crypto_engine.h"
#include "protocol.h"
#include "sqlite_helpers.h"

#include <algorithm>
#include <cstring>
#include <functional>
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

namespace {

constexpr int64_t SCHEMA_VERSION = 9;

// The conversations table at version 2. The unique index lets each contact have one direct
// conversation, while any number of groups can share members.
#define PQ_CONVERSATIONS_COLUMNS                                                          \
    "(id BLOB PRIMARY KEY, kind INTEGER NOT NULL DEFAULT 1, contact_fp TEXT NOT NULL DEFAULT '',"  \
    " title TEXT NOT NULL DEFAULT '', creator_fp TEXT NOT NULL DEFAULT '', mode INTEGER NOT NULL DEFAULT 1,"  \
    " timer_seconds INTEGER NOT NULL DEFAULT 0, previous_id BLOB NOT NULL DEFAULT x'',"    \
    " state INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, last_activity INTEGER NOT NULL,"  \
    " send_delivery INTEGER NOT NULL DEFAULT 1, send_read INTEGER NOT NULL DEFAULT 1)"
const char CONVERSATIONS_V2_TEMPLATE_PREFIX[] = "CREATE TABLE ";
const char CONVERSATIONS_V2_TEMPLATE_BODY[] = PQ_CONVERSATIONS_COLUMNS;
const char CONVERSATIONS_V2[] =
    "CREATE TABLE conversations" PQ_CONVERSATIONS_COLUMNS ";"
    "CREATE UNIQUE INDEX conversations_direct ON conversations(contact_fp) WHERE kind = 1;";
const char CONVERSATIONS_INDEXES[] =
    "CREATE UNIQUE INDEX IF NOT EXISTS conversations_direct ON conversations(contact_fp) WHERE kind = 1;";

// Everything except the conversations table. All idempotent, so a brand-new database and a
// migrated one end up the same.
const char SCHEMA_REST[] =
    "CREATE TABLE IF NOT EXISTS conversation_members("
    "  conv_id BLOB NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,"
    "  member_fp TEXT NOT NULL, idx INTEGER NOT NULL DEFAULT 0,"
    "  PRIMARY KEY(conv_id, member_fp));"
    "CREATE TABLE IF NOT EXISTS messages("
    "  row INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  conv_id BLOB NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,"
    "  msg_id BLOB NOT NULL, outgoing INTEGER NOT NULL,"
    "  sent_at INTEGER NOT NULL, received_at INTEGER NOT NULL,"
    "  status INTEGER NOT NULL, gap INTEGER NOT NULL DEFAULT 0,"
    "  entry_hash BLOB NOT NULL, sealed BLOB NOT NULL,"
    "  UNIQUE(conv_id, msg_id));"
    "CREATE INDEX IF NOT EXISTS messages_by_hash ON messages(conv_id, entry_hash);"
    "CREATE TABLE IF NOT EXISTS deliveries("
    "  conv_id BLOB NOT NULL, msg_id BLOB NOT NULL, member_fp TEXT NOT NULL,"
    "  status INTEGER NOT NULL,"
    "  PRIMARY KEY(conv_id, msg_id, member_fp),"
    "  FOREIGN KEY(conv_id, msg_id) REFERENCES messages(conv_id, msg_id) ON DELETE CASCADE);"
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
    // Added in version 3:
    "CREATE TABLE IF NOT EXISTS group_invites("
    "  conv_id BLOB PRIMARY KEY, creator_fp TEXT NOT NULL, received_at INTEGER NOT NULL, sealed BLOB NOT NULL);"
    "CREATE TABLE IF NOT EXISTS introduced_members("
    "  fp TEXT PRIMARY KEY, bundle BLOB NOT NULL, issued_at INTEGER NOT NULL,"
    "  introduced_by TEXT NOT NULL, first_seen INTEGER NOT NULL);"
    // Added in version 4:
    "CREATE TABLE IF NOT EXISTS member_tokens("
    "  conv_id BLOB NOT NULL, fp TEXT NOT NULL, sealed BLOB NOT NULL, received_at INTEGER NOT NULL,"
    "  PRIMARY KEY(conv_id, fp));"
    // Added in version 5:
    "CREATE TABLE IF NOT EXISTS verified_people("
    "  fp TEXT PRIMARY KEY, verified_at INTEGER NOT NULL);"
    // Added in version 6:
    "CREATE TABLE IF NOT EXISTS archives("
    "  conv_id BLOB PRIMARY KEY, relay_address TEXT NOT NULL, relay_id BLOB NOT NULL,"
    "  role INTEGER NOT NULL, state INTEGER NOT NULL,"
    "  archive_key BLOB NOT NULL, chat_public BLOB NOT NULL, chat_private BLOB NOT NULL, join_token BLOB NOT NULL,"
    "  head_number INTEGER NOT NULL DEFAULT 0, head_hash BLOB NOT NULL DEFAULT x'',"
    "  created_at INTEGER NOT NULL, note TEXT NOT NULL DEFAULT '',"
    "  checkpoint_at INTEGER NOT NULL DEFAULT 0, activity INTEGER NOT NULL DEFAULT 0,"
    "  checkpoint_seen INTEGER NOT NULL DEFAULT 0, warning TEXT NOT NULL DEFAULT '');"
    // Added in version 9: attachments.
    "CREATE TABLE IF NOT EXISTS attachments("
    "  file_id BLOB PRIMARY KEY, conv_id BLOB NOT NULL, message_id BLOB NOT NULL, outgoing INTEGER NOT NULL,"
    "  name TEXT NOT NULL, size INTEGER NOT NULL, sha256 BLOB NOT NULL, expires_at INTEGER NOT NULL,"
    "  relay_address TEXT NOT NULL, relay_id BLOB NOT NULL, state INTEGER NOT NULL, secrets BLOB NOT NULL,"
    "  path TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '', recipients INTEGER NOT NULL DEFAULT 0,"
    "  redeemed INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);"
    // Added in version 8: deleting by agreement.
    "CREATE TABLE IF NOT EXISTS deletions("
    "  op_id BLOB PRIMARY KEY, conv_id BLOB NOT NULL, scope INTEGER NOT NULL, expires_at INTEGER NOT NULL,"
    "  requester_fp TEXT NOT NULL, entries BLOB NOT NULL, state INTEGER NOT NULL, created_at INTEGER NOT NULL);"
    "CREATE TABLE IF NOT EXISTS deletion_accepts("
    "  op_id BLOB NOT NULL, key_hash BLOB NOT NULL, signature BLOB NOT NULL, member_fp TEXT NOT NULL,"
    "  PRIMARY KEY(op_id, key_hash));"
    "CREATE TABLE IF NOT EXISTS archive_messages("
    "  conv_id BLOB NOT NULL, msg_id BLOB NOT NULL, number INTEGER NOT NULL,"
    "  PRIMARY KEY(conv_id, msg_id));"
    "CREATE TABLE IF NOT EXISTS archive_redacted("
    "  conv_id BLOB NOT NULL, number INTEGER NOT NULL,"
    "  PRIMARY KEY(conv_id, number));"
    // Added in version 7: the chain hashes this device has checked.
    "CREATE TABLE IF NOT EXISTS archive_chain("
    "  conv_id BLOB NOT NULL, number INTEGER NOT NULL, hash BLOB NOT NULL,"
    "  PRIMARY KEY(conv_id, number));";

const char CONVERSATION_COLUMNS[] =
    "id, contact_fp, created_at, last_activity, send_delivery, send_read, kind, state, title, creator_fp, mode, timer_seconds, previous_id";

bool is_member_fp(const std::string& fp) {
    if (fp.size() != 64) return false;
    for (char c : fp)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
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
    try {
    int64_t version = 0;
    {
        Stmt v(db_, "PRAGMA user_version");
        if (v.step()) version = v.column_i64(0);
    }
    bool has_conversations = false;
    {
        Stmt t(db_, "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'conversations'");
        has_conversations = t.step();
    }

    if (version > SCHEMA_VERSION)
        throw std::runtime_error("This message history was made by a newer version of the app (" + path +
                                 "). Update the app; it can't be opened by this one.");
    if (has_conversations && version < 2) {
        migrate_v1_to_v2(db_path);  // rewrites a table, so it keeps a copy of the old file first
    } else if (has_conversations && version < SCHEMA_VERSION) {
        // Versions 3 to 7 only add tables (group invitations, introduced members, member tokens,
        // verified people, chat archives) and, in 7, four columns on the archive table: nothing to
        // rewrite, so nothing to back up.
        Transaction tx(db_);
        if (version == 6) {
            exec(db_, "ALTER TABLE archives ADD COLUMN checkpoint_at INTEGER NOT NULL DEFAULT 0");
            exec(db_, "ALTER TABLE archives ADD COLUMN activity INTEGER NOT NULL DEFAULT 0");
            exec(db_, "ALTER TABLE archives ADD COLUMN checkpoint_seen INTEGER NOT NULL DEFAULT 0");
            exec(db_, "ALTER TABLE archives ADD COLUMN warning TEXT NOT NULL DEFAULT ''");
        }
        exec(db_, SCHEMA_REST);
        exec(db_, "PRAGMA user_version=9");
        tx.commit();
    } else if (!has_conversations) {
        Transaction tx(db_);
        exec(db_, CONVERSATIONS_V2);
        exec(db_, SCHEMA_REST);
        exec(db_, "PRAGMA user_version=9");
        tx.commit();
    }
    } catch (...) {
        // A constructor that throws never runs the destructor, so don't leak the connection.
        sqlite3_close(db_);
        db_ = nullptr;
        throw;
    }
}

// Version 1 had one conversation per contact. Version 2 adds groups: a conversation gets a
// kind, state, title, creator, mode, timer and link to a previous conversation; members move to
// their own table; and delivery is tracked per member. Everything that was there is kept.
void HistoryStore::migrate_v1_to_v2(const std::filesystem::path& db_path) {
    // The whole history lives in this one file, so keep the old one until the new shape has
    // proven itself. (Not overwritten if an earlier, interrupted attempt already made one.)
    exec(db_, "PRAGMA wal_checkpoint(TRUNCATE)");
    std::filesystem::path backup = db_path;
    backup += ".before-v2";
    std::error_code ec;
    if (!std::filesystem::exists(backup, ec)) {
        std::filesystem::copy_file(db_path, backup, ec);
        if (ec) throw std::runtime_error("Cannot back up the message history before upgrading it (" + ec.message() + ")");
    }

    // Rebuilding a table that others refer to must happen with foreign keys off (SQLite's documented procedure).
    exec(db_, "PRAGMA foreign_keys=OFF");
    try {
        {
            Transaction tx(db_);
            exec(db_, (std::string(CONVERSATIONS_V2_TEMPLATE_PREFIX) + "conversations_new" + CONVERSATIONS_V2_TEMPLATE_BODY).c_str());
            exec(db_,
                 "INSERT INTO conversations_new(id, kind, contact_fp, created_at, last_activity, send_delivery, send_read) "
                 "SELECT id, 1, contact_fp, created_at, last_activity, send_delivery, send_read FROM conversations");
            exec(db_, "DROP TABLE conversations");
            exec(db_, "ALTER TABLE conversations_new RENAME TO conversations");
            exec(db_, CONVERSATIONS_INDEXES);
            exec(db_, SCHEMA_REST);
            // Every existing conversation is a direct one: its member is the contact.
            exec(db_, "INSERT INTO conversation_members(conv_id, member_fp, idx) SELECT id, contact_fp, 0 FROM conversations WHERE kind = 1");
            exec(db_, "PRAGMA user_version=9");  // SCHEMA_REST already holds the newer tables
            tx.commit();
        }
        Stmt check(db_, "PRAGMA foreign_key_check");
        if (check.step()) throw std::runtime_error("The message history failed its integrity check after upgrading; the old copy is " + backup.u8string());
    } catch (...) {
        sqlite3_exec(db_, "PRAGMA foreign_keys=ON", nullptr, nullptr, nullptr);
        throw;
    }
    exec(db_, "PRAGMA foreign_keys=ON");
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

static std::vector<std::string> load_members(sqlite3* db, const std::vector<uint8_t>& conversation_id) {
    Stmt s(db, "SELECT member_fp FROM conversation_members WHERE conv_id = ? ORDER BY idx, member_fp");
    s.blob(1, conversation_id);
    std::vector<std::string> out;
    while (s.step()) out.push_back(s.column_text(0));
    return out;
}

static HistoryStore::Conversation read_conversation(sqlite3* db, Stmt& s) {
    HistoryStore::Conversation c;
    c.id = s.column_blob(0);
    c.contact_fp = s.column_text(1);
    c.created_at = s.column_i64(2);
    c.last_activity = s.column_i64(3);
    c.send_delivery_receipts = s.column_i64(4) != 0;
    c.send_read_receipts = s.column_i64(5) != 0;
    c.kind = static_cast<int>(s.column_i64(6));
    c.state = static_cast<int>(s.column_i64(7));
    c.title = s.column_text(8);
    c.creator_fp = s.column_text(9);
    c.mode = static_cast<int>(s.column_i64(10));
    c.timer_seconds = s.column_i64(11);
    c.previous_id = s.column_blob(12);
    c.members = load_members(db, c.id);
    return c;
}

HistoryStore::Conversation HistoryStore::ensure_conversation(const Bytes& id, const std::string& contact_fp, int64_t now) {
    std::lock_guard<std::mutex> lock(mutex_);
    Transaction tx(db_);
    Stmt(db_, "INSERT OR IGNORE INTO conversations(id, kind, contact_fp, created_at, last_activity) VALUES(?, 1, ?, ?, ?)")
        .blob(1, id).text(2, contact_fp).i64(3, now).i64(4, now).step();
    Bytes found_id;
    {
        Stmt s(db_, "SELECT id FROM conversations WHERE kind = 1 AND contact_fp = ?");
        s.text(1, contact_fp);
        if (!s.step()) throw std::runtime_error("database: conversation missing after insert");
        found_id = s.column_blob(0);
    }
    Stmt(db_, "INSERT OR IGNORE INTO conversation_members(conv_id, member_fp, idx) VALUES(?, ?, 0)")
        .blob(1, found_id).text(2, contact_fp).step();
    tx.commit();
    Stmt s(db_, (std::string("SELECT ") + CONVERSATION_COLUMNS + " FROM conversations WHERE id = ?").c_str());
    s.blob(1, found_id);
    if (!s.step()) throw std::runtime_error("database: conversation missing after insert");
    return read_conversation(db_, s);
}

std::optional<HistoryStore::Conversation> HistoryStore::conversation_for(const std::string& contact_fp) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, (std::string("SELECT ") + CONVERSATION_COLUMNS + " FROM conversations WHERE kind = 1 AND contact_fp = ?").c_str());
    s.text(1, contact_fp);
    if (!s.step()) return std::nullopt;
    return read_conversation(db_, s);
}

std::optional<HistoryStore::Conversation> HistoryStore::conversation(const Bytes& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, (std::string("SELECT ") + CONVERSATION_COLUMNS + " FROM conversations WHERE id = ?").c_str());
    s.blob(1, id);
    if (!s.step()) return std::nullopt;
    return read_conversation(db_, s);
}

HistoryStore::Conversation HistoryStore::create_group(const Bytes& id, const std::string& title, const std::string& creator_fp,
                                                      int mode, int64_t timer_seconds, const Bytes& previous_id,
                                                      const std::vector<std::string>& members, int state, int64_t now) {
    if (id.empty()) throw std::runtime_error("A group needs a conversation ID");
    if (mode != Saved) throw std::runtime_error("Only Saved chats are supported so far");
    if (state != Active && state != SettingUp) throw std::runtime_error("Unknown conversation state");
    if (title.size() > MAX_TITLE_BYTES) throw std::runtime_error("The group name is too long");
    if (!creator_fp.empty() && !is_member_fp(creator_fp)) throw std::runtime_error("The group creator is not a valid fingerprint");
    if (members.empty() || members.size() > MAX_OTHER_MEMBERS) throw std::runtime_error("A group needs between 2 and 16 people");
    for (size_t i = 0; i < members.size(); i++) {
        if (!is_member_fp(members[i])) throw std::runtime_error("A group member is not a valid fingerprint");
        for (size_t j = 0; j < i; j++)
            if (members[i] == members[j]) throw std::runtime_error("A group member is listed twice");
    }

    std::lock_guard<std::mutex> lock(mutex_);
    {
        Stmt existing(db_, (std::string("SELECT ") + CONVERSATION_COLUMNS + " FROM conversations WHERE id = ?").c_str());
        existing.blob(1, id);
        if (existing.step()) return read_conversation(db_, existing);  // a replay: nothing changes
    }
    Transaction tx(db_);
    Stmt(db_, "INSERT INTO conversations(id, kind, contact_fp, title, creator_fp, mode, timer_seconds, previous_id, state, created_at, last_activity) "
              "VALUES(?, 2, '', ?, ?, ?, ?, ?, ?, ?, ?)")
        .blob(1, id).text(2, title).text(3, creator_fp).i64(4, mode).i64(5, timer_seconds).blob(6, previous_id)
        .i64(7, state).i64(8, now).i64(9, now).step();
    for (size_t i = 0; i < members.size(); i++)
        Stmt(db_, "INSERT INTO conversation_members(conv_id, member_fp, idx) VALUES(?, ?, ?)")
            .blob(1, id).text(2, members[i]).i64(3, static_cast<int64_t>(i)).step();
    tx.commit();
    Stmt s(db_, (std::string("SELECT ") + CONVERSATION_COLUMNS + " FROM conversations WHERE id = ?").c_str());
    s.blob(1, id);
    if (!s.step()) throw std::runtime_error("database: group missing after insert");
    return read_conversation(db_, s);
}

void HistoryStore::set_conversation_state(const Bytes& id, int state) {
    if (state != Active && state != SettingUp) throw std::runtime_error("Unknown conversation state");
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "UPDATE conversations SET state = ? WHERE id = ?").i64(1, state).blob(2, id).step();
}

std::vector<HistoryStore::Conversation> HistoryStore::conversations() {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, (std::string("SELECT ") + CONVERSATION_COLUMNS + " FROM conversations ORDER BY last_activity DESC").c_str());
    std::vector<Conversation> out;
    while (s.step()) out.push_back(read_conversation(db_, s));
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
    Bytes sealed = s.column_blob(9);
    if (sealed.empty()) {  // erased by agreement: only its place and hash are kept
        out.deleted = true;
        out.record.clear();
        return true;
    }
    auto plain = unseal(sealed, aad_of("pq-suite v3 history message", out.conversation_id, out.message_id));
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

bool HistoryStore::raise_delivery(const Bytes& conversation_id, const Bytes& message_id, const std::string& member_fp, int status) {
    std::lock_guard<std::mutex> lock(mutex_);
    Transaction tx(db_);
    {
        Stmt ours(db_, "SELECT 1 FROM messages WHERE conv_id = ? AND msg_id = ? AND outgoing = 1");
        ours.blob(1, conversation_id).blob(2, message_id);
        if (!ours.step()) return false;
    }
    {
        Stmt member(db_, "SELECT 1 FROM conversation_members WHERE conv_id = ? AND member_fp = ?");
        member.blob(1, conversation_id).text(2, member_fp);
        if (!member.step()) return false;
    }
    Stmt(db_, "INSERT INTO deliveries(conv_id, msg_id, member_fp, status) VALUES(?, ?, ?, ?) "
              "ON CONFLICT(conv_id, msg_id, member_fp) DO UPDATE SET status = excluded.status WHERE excluded.status > deliveries.status")
        .blob(1, conversation_id).blob(2, message_id).text(3, member_fp).i64(4, status).step();
    bool changed = sqlite3_changes(db_) > 0;

    int64_t lowest = 0;
    {
        Stmt agg(db_, "SELECT MIN(COALESCE(d.status, 0)) FROM conversation_members m "
                      "LEFT JOIN deliveries d ON d.conv_id = m.conv_id AND d.msg_id = ? AND d.member_fp = m.member_fp "
                      "WHERE m.conv_id = ?");
        agg.blob(1, message_id).blob(2, conversation_id);
        if (agg.step()) lowest = agg.column_i64(0);
    }
    Stmt(db_, "UPDATE messages SET status = ? WHERE conv_id = ? AND msg_id = ? AND outgoing = 1 AND status < ?")
        .i64(1, lowest).blob(2, conversation_id).blob(3, message_id).i64(4, lowest).step();
    changed |= sqlite3_changes(db_) > 0;
    tx.commit();
    return changed;
}

std::vector<HistoryStore::Delivery> HistoryStore::deliveries(const Bytes& conversation_id, const Bytes& message_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT m.member_fp, COALESCE(d.status, 0) FROM conversation_members m "
                "LEFT JOIN deliveries d ON d.conv_id = m.conv_id AND d.msg_id = ? AND d.member_fp = m.member_fp "
                "WHERE m.conv_id = ? ORDER BY m.idx, m.member_fp");
    s.blob(1, message_id).blob(2, conversation_id);
    std::vector<Delivery> out;
    while (s.step()) {
        Delivery d;
        d.member_fp = s.column_text(0);
        d.status = static_cast<int>(s.column_i64(1));
        out.push_back(std::move(d));
    }
    return out;
}

std::optional<HistoryStore::Bytes> HistoryStore::conversation_of_outgoing(const Bytes& message_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT conv_id FROM messages WHERE msg_id = ? AND outgoing = 1 LIMIT 1");
    s.blob(1, message_id);
    if (!s.step()) return std::nullopt;
    return s.column_blob(0);
}

// --- Pending group invitations ---

static const char GROUP_INVITE_AAD[] = "pq-suite v3 history group invite";

std::optional<HistoryStore::GroupInvite> HistoryStore::open_invite(const Bytes& conv_id, const std::string& creator_fp, int64_t received_at, const Bytes& sealed) const {
    auto plain = unseal(sealed, aad_of(GROUP_INVITE_AAD, conv_id));
    auto records = plain ? unpack(*plain) : std::nullopt;
    if (!records || records->empty()) return std::nullopt;  // damaged, or sealed under a different key
    GroupInvite invite;
    invite.conversation_id = conv_id;
    invite.creator_fp = creator_fp;
    invite.received_at = received_at;
    invite.records = std::move(*records);
    return invite;
}

bool HistoryStore::add_group_invite(const Bytes& conversation_id, const std::string& creator_fp, const Bytes& creation_record, int64_t now) {
    std::lock_guard<std::mutex> lock(mutex_);
    Bytes sealed = seal(pack({creation_record}), aad_of(GROUP_INVITE_AAD, conversation_id));
    Stmt(db_, "INSERT OR IGNORE INTO group_invites(conv_id, creator_fp, received_at, sealed) VALUES(?, ?, ?, ?)")
        .blob(1, conversation_id).text(2, creator_fp).i64(3, now).blob(4, sealed).step();
    return sqlite3_changes(db_) > 0;
}

std::optional<HistoryStore::GroupInvite> HistoryStore::group_invite(const Bytes& conversation_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT conv_id, creator_fp, received_at, sealed FROM group_invites WHERE conv_id = ?");
    s.blob(1, conversation_id);
    if (!s.step()) return std::nullopt;
    return open_invite(s.column_blob(0), s.column_text(1), s.column_i64(2), s.column_blob(3));
}

std::vector<HistoryStore::GroupInvite> HistoryStore::group_invites() {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT conv_id, creator_fp, received_at, sealed FROM group_invites ORDER BY received_at, rowid");
    std::vector<GroupInvite> out;
    while (s.step())
        if (auto invite = open_invite(s.column_blob(0), s.column_text(1), s.column_i64(2), s.column_blob(3))) out.push_back(std::move(*invite));
    return out;
}

size_t HistoryStore::group_invite_count() {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT COUNT(*) FROM group_invites");
    return s.step() ? static_cast<size_t>(s.column_i64(0)) : 0;
}

bool HistoryStore::hold_for_invite(const Bytes& conversation_id, const Bytes& record) {
    std::lock_guard<std::mutex> lock(mutex_);
    Transaction tx(db_);
    std::vector<Bytes> records;
    {
        Stmt s(db_, "SELECT sealed FROM group_invites WHERE conv_id = ?");
        s.blob(1, conversation_id);
        if (!s.step()) return false;
        auto plain = unseal(s.column_blob(0), aad_of(GROUP_INVITE_AAD, conversation_id));
        auto unpacked = plain ? unpack(*plain) : std::nullopt;
        if (!unpacked || unpacked->empty()) return false;
        records = std::move(*unpacked);
    }
    if (std::find(records.begin(), records.end(), record) != records.end()) return true;
    if (records.size() >= 1 + MAX_HELD_RECORDS) return false;
    records.push_back(record);
    Stmt(db_, "UPDATE group_invites SET sealed = ? WHERE conv_id = ?")
        .blob(1, seal(pack(records), aad_of(GROUP_INVITE_AAD, conversation_id))).blob(2, conversation_id).step();
    tx.commit();
    return true;
}

void HistoryStore::delete_group_invite(const Bytes& conversation_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "DELETE FROM group_invites WHERE conv_id = ?").blob(1, conversation_id).step();
}

// --- Introduced members ---

void HistoryStore::save_introduced(const std::string& fp, const Bytes& bundle, int64_t issued_at, const std::string& introduced_by, int64_t now) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "INSERT INTO introduced_members(fp, bundle, issued_at, introduced_by, first_seen) VALUES(?, ?, ?, ?, ?) "
              "ON CONFLICT(fp) DO UPDATE SET bundle = excluded.bundle, issued_at = excluded.issued_at "
              "WHERE excluded.issued_at > introduced_members.issued_at")
        .text(1, fp).blob(2, bundle).i64(3, issued_at).text(4, introduced_by).i64(5, now).step();
}

static HistoryStore::IntroducedMember read_introduced(Stmt& s) {
    HistoryStore::IntroducedMember m;
    m.fp = s.column_text(0);
    m.bundle = s.column_blob(1);
    m.issued_at = s.column_i64(2);
    m.introduced_by = s.column_text(3);
    m.first_seen = s.column_i64(4);
    return m;
}

std::optional<HistoryStore::IntroducedMember> HistoryStore::introduced(const std::string& fp) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT fp, bundle, issued_at, introduced_by, first_seen FROM introduced_members WHERE fp = ?");
    s.text(1, fp);
    if (!s.step()) return std::nullopt;
    return read_introduced(s);
}

std::vector<HistoryStore::IntroducedMember> HistoryStore::introduced_members() {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT fp, bundle, issued_at, introduced_by, first_seen FROM introduced_members ORDER BY first_seen, fp");
    std::vector<IntroducedMember> out;
    while (s.step()) out.push_back(read_introduced(s));
    return out;
}

void HistoryStore::delete_introduced_except(const std::set<std::string>& keep) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> doomed;
    {
        Stmt s(db_, "SELECT fp FROM introduced_members");
        while (s.step()) {
            std::string fp = s.column_text(0);
            if (!keep.count(fp)) doomed.push_back(fp);
        }
    }
    for (const auto& fp : doomed) Stmt(db_, "DELETE FROM introduced_members WHERE fp = ?").text(1, fp).step();
}

// --- Chat archives ---

static Bytes archive_secret_aad(const Bytes& conversation_id, const char* what) {
    return aad_of("pq-suite v3 history archive secret", conversation_id, Bytes(what, what + std::strlen(what)));
}

bool HistoryStore::add_archive(const Archive& a) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "INSERT OR IGNORE INTO archives(conv_id, relay_address, relay_id, role, state, archive_key, chat_public, chat_private, join_token, "
              "head_number, head_hash, created_at, note) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .blob(1, a.conversation_id).text(2, a.relay_address).blob(3, a.relay_id).i64(4, a.role).i64(5, a.state)
        .blob(6, seal(a.archive_key, archive_secret_aad(a.conversation_id, "key")))
        .blob(7, a.chat_public_key)
        .blob(8, seal(a.chat_private_key, archive_secret_aad(a.conversation_id, "chat")))
        .blob(9, a.join_token.empty() ? Bytes() : seal(a.join_token, archive_secret_aad(a.conversation_id, "token")))
        .i64(10, static_cast<int64_t>(a.head_number)).blob(11, a.head_hash).i64(12, a.created_at).text(13, a.note).step();
    return sqlite3_changes(db_) > 0;
}

static std::optional<HistoryStore::Archive> read_archive(Stmt& s, const std::function<std::optional<Bytes>(const Bytes&, const Bytes&)>& unseal_fn) {
    HistoryStore::Archive a;
    a.conversation_id = s.column_blob(0);
    a.relay_address = s.column_text(1);
    a.relay_id = s.column_blob(2);
    a.role = static_cast<int>(s.column_i64(3));
    a.state = static_cast<int>(s.column_i64(4));
    auto key = unseal_fn(s.column_blob(5), archive_secret_aad(a.conversation_id, "key"));
    auto priv = unseal_fn(s.column_blob(7), archive_secret_aad(a.conversation_id, "chat"));
    if (!key || !priv) return std::nullopt;  // damaged, or sealed under another key
    a.archive_key = std::move(*key);
    a.chat_public_key = s.column_blob(6);
    a.chat_private_key = std::move(*priv);
    Bytes sealed_token = s.column_blob(8);
    if (!sealed_token.empty()) {
        auto token = unseal_fn(sealed_token, archive_secret_aad(a.conversation_id, "token"));
        if (!token) return std::nullopt;
        a.join_token = std::move(*token);
    }
    a.head_number = static_cast<uint64_t>(s.column_i64(9));
    a.head_hash = s.column_blob(10);
    a.created_at = s.column_i64(11);
    a.note = s.column_text(12);
    a.checkpoint_at = s.column_i64(13);
    a.activity = static_cast<uint64_t>(s.column_i64(14));
    a.checkpoint_seen = static_cast<uint64_t>(s.column_i64(15));
    a.warning = s.column_text(16);
    return a;
}

static const char ARCHIVE_COLUMNS[] =
    "conv_id, relay_address, relay_id, role, state, archive_key, chat_public, chat_private, join_token, head_number, head_hash, created_at, note, "
    "checkpoint_at, activity, checkpoint_seen, warning";

std::optional<HistoryStore::Archive> HistoryStore::archive(const Bytes& conversation_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, (std::string("SELECT ") + ARCHIVE_COLUMNS + " FROM archives WHERE conv_id = ?").c_str());
    s.blob(1, conversation_id);
    if (!s.step()) return std::nullopt;
    return read_archive(s, [this](const Bytes& c, const Bytes& a) { return unseal(c, a); });
}

std::vector<HistoryStore::Archive> HistoryStore::archives() {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, (std::string("SELECT ") + ARCHIVE_COLUMNS + " FROM archives ORDER BY created_at, rowid").c_str());
    std::vector<Archive> out;
    while (s.step())
        if (auto a = read_archive(s, [this](const Bytes& c, const Bytes& aad) { return unseal(c, aad); })) out.push_back(std::move(*a));
    return out;
}

std::vector<HistoryStore::Archive> HistoryStore::archives_in_state(int state) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, (std::string("SELECT ") + ARCHIVE_COLUMNS + " FROM archives WHERE state = ? ORDER BY created_at, rowid").c_str());
    s.i64(1, state);
    std::vector<Archive> out;
    while (s.step())
        if (auto a = read_archive(s, [this](const Bytes& c, const Bytes& aad) { return unseal(c, aad); })) out.push_back(std::move(*a));
    return out;
}

void HistoryStore::set_archive_joined(const Bytes& conversation_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "UPDATE archives SET state = 1, join_token = x'', note = '' WHERE conv_id = ?").blob(1, conversation_id).step();
}

void HistoryStore::set_archive_failed(const Bytes& conversation_id, const std::string& note) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "UPDATE archives SET state = 2, join_token = x'', note = ? WHERE conv_id = ?").text(1, note).blob(2, conversation_id).step();
}

std::vector<HistoryStore::Bytes> HistoryStore::archive_ids(int state) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT conv_id FROM archives WHERE state = ? ORDER BY created_at, rowid");
    s.i64(1, state);
    std::vector<Bytes> out;
    while (s.step()) out.push_back(s.column_blob(0));
    return out;
}

bool HistoryStore::has_archive(const Bytes& conversation_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT 1 FROM archives WHERE conv_id = ?");
    s.blob(1, conversation_id);
    return s.step();
}

void HistoryStore::add_archive_activity(const Bytes& conversation_id, uint64_t entries) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "UPDATE archives SET activity = activity + ? WHERE conv_id = ?").i64(1, static_cast<int64_t>(entries)).blob(2, conversation_id).step();
}

void HistoryStore::note_checkpoint_posted(const Bytes& conversation_id, int64_t now) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "UPDATE archives SET activity = 0, checkpoint_at = ? WHERE conv_id = ?").i64(1, now).blob(2, conversation_id).step();
}

void HistoryStore::note_checkpoint_seen(const Bytes& conversation_id, uint64_t number) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "UPDATE archives SET checkpoint_seen = ? WHERE conv_id = ? AND checkpoint_seen < ?")
        .i64(1, static_cast<int64_t>(number)).blob(2, conversation_id).i64(3, static_cast<int64_t>(number)).step();
}

void HistoryStore::set_archive_warning(const Bytes& conversation_id, const std::string& warning) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "UPDATE archives SET warning = ? WHERE conv_id = ?").text(1, warning).blob(2, conversation_id).step();
}

void HistoryStore::save_archive_hashes(const Bytes& conversation_id, const std::vector<std::pair<uint64_t, Bytes>>& hashes) {
    std::lock_guard<std::mutex> lock(mutex_);
    Transaction tx(db_);
    for (const auto& [number, hash] : hashes)
        Stmt(db_, "INSERT OR IGNORE INTO archive_chain(conv_id, number, hash) VALUES(?, ?, ?)").blob(1, conversation_id).i64(2, static_cast<int64_t>(number)).blob(3, hash).step();
    tx.commit();
}

std::optional<HistoryStore::Bytes> HistoryStore::archive_hash(const Bytes& conversation_id, uint64_t number) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT hash FROM archive_chain WHERE conv_id = ? AND number = ?");
    s.blob(1, conversation_id).i64(2, static_cast<int64_t>(number));
    if (!s.step()) return std::nullopt;
    return s.column_blob(0);
}

std::optional<HistoryStore::Message> HistoryStore::first_message(const Bytes& conversation_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT row, conv_id, msg_id, outgoing, sent_at, received_at, status, gap, entry_hash, sealed "
                "FROM messages WHERE conv_id = ? ORDER BY row LIMIT 1");
    s.blob(1, conversation_id);
    if (!s.step()) return std::nullopt;
    Message m;
    auto opener = [this](const Bytes& sealed, const Bytes& aad) { return unseal(sealed, aad); };
    if (!read_message(s, m, opener)) return std::nullopt;
    return m;
}

void HistoryStore::set_archive_head(const Bytes& conversation_id, uint64_t number, const Bytes& hash) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "UPDATE archives SET head_number = ?, head_hash = ? WHERE conv_id = ? AND head_number < ?")
        .i64(1, static_cast<int64_t>(number)).blob(2, hash).blob(3, conversation_id).i64(4, static_cast<int64_t>(number)).step();
}

// --- Attachments ---

static Bytes attachment_secrets_aad(const Bytes& file_id) { return aad_of("pq-suite v3 history attachment secrets", file_id, Bytes()); }

bool HistoryStore::add_attachment(const Attachment& a) {
    std::lock_guard<std::mutex> lock(mutex_);
    Bytes secrets;
    if (!a.key.empty() || !a.token.empty() || !a.recipient_tokens.empty()) {
        write_blob(secrets, a.key);
        write_blob(secrets, a.token);
        write_u32(secrets, static_cast<uint32_t>(a.recipient_tokens.size()));
        for (const auto& [fp, token] : a.recipient_tokens) {
            write_string(secrets, fp);
            write_blob(secrets, token);
        }
        secrets = seal(secrets, attachment_secrets_aad(a.file_id));
    }
    Stmt(db_, "INSERT OR IGNORE INTO attachments(file_id, conv_id, message_id, outgoing, name, size, sha256, expires_at, relay_address, relay_id, state, secrets, path, note, recipients, redeemed, created_at) "
              "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .blob(1, a.file_id).blob(2, a.conversation_id).blob(3, a.message_id).i64(4, a.outgoing ? 1 : 0).text(5, a.name).i64(6, static_cast<int64_t>(a.size))
        .blob(7, a.sha256).i64(8, a.expires_at).text(9, a.relay_address).blob(10, a.relay_id).i64(11, a.state).blob(12, secrets).text(13, a.path).text(14, a.note)
        .i64(15, a.recipients).i64(16, a.redeemed).i64(17, a.created_at).step();
    return sqlite3_changes(db_) > 0;
}

static const char ATTACHMENT_COLUMNS[] =
    "file_id, conv_id, message_id, outgoing, name, size, sha256, expires_at, relay_address, relay_id, state, secrets, path, note, recipients, redeemed, created_at";

static HistoryStore::Attachment read_attachment(Stmt& s, const std::function<std::optional<Bytes>(const Bytes&, const Bytes&)>& unseal_fn) {
    HistoryStore::Attachment a;
    a.file_id = s.column_blob(0);
    a.conversation_id = s.column_blob(1);
    a.message_id = s.column_blob(2);
    a.outgoing = s.column_i64(3) != 0;
    a.name = s.column_text(4);
    a.size = static_cast<uint64_t>(s.column_i64(5));
    a.sha256 = s.column_blob(6);
    a.expires_at = s.column_i64(7);
    a.relay_address = s.column_text(8);
    a.relay_id = s.column_blob(9);
    a.state = static_cast<int>(s.column_i64(10));
    Bytes sealed = s.column_blob(11);
    if (!sealed.empty()) {
        if (auto plain = unseal_fn(sealed, attachment_secrets_aad(a.file_id))) {
            size_t off = 0;
            auto key = read_blob(plain->data(), plain->size(), off, 64);
            auto token = read_blob(plain->data(), plain->size(), off, 64);
            auto n = read_u32(plain->data(), plain->size(), off);
            if (key && token && n) {
                a.key = std::move(*key);
                a.token = std::move(*token);
                for (uint32_t i = 0; i < *n && i < 64; i++) {
                    auto fp = read_string(plain->data(), plain->size(), off, 128);
                    auto t = read_blob(plain->data(), plain->size(), off, 64);
                    if (!fp || !t) break;
                    a.recipient_tokens.emplace_back(std::move(*fp), std::move(*t));
                }
            }
        }
    }
    a.path = s.column_text(12);
    a.note = s.column_text(13);
    a.recipients = static_cast<uint32_t>(s.column_i64(14));
    a.redeemed = static_cast<uint32_t>(s.column_i64(15));
    a.created_at = s.column_i64(16);
    return a;
}

std::optional<HistoryStore::Attachment> HistoryStore::attachment(const Bytes& file_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, (std::string("SELECT ") + ATTACHMENT_COLUMNS + " FROM attachments WHERE file_id = ?").c_str());
    s.blob(1, file_id);
    if (!s.step()) return std::nullopt;
    return read_attachment(s, [this](const Bytes& c, const Bytes& aad) { return unseal(c, aad); });
}

std::vector<HistoryStore::Attachment> HistoryStore::attachments_in_state(int state) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, (std::string("SELECT ") + ATTACHMENT_COLUMNS + " FROM attachments WHERE state = ? ORDER BY created_at, rowid").c_str());
    s.i64(1, state);
    std::vector<Attachment> out;
    while (s.step()) out.push_back(read_attachment(s, [this](const Bytes& c, const Bytes& aad) { return unseal(c, aad); }));
    return out;
}

void HistoryStore::set_attachment_state(const Bytes& file_id, int state, const std::string& note) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "UPDATE attachments SET state = ?, note = ? WHERE file_id = ?").i64(1, state).text(2, note).blob(3, file_id).step();
}

void HistoryStore::set_attachment_path(const Bytes& file_id, const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "UPDATE attachments SET path = ? WHERE file_id = ?").text(1, path).blob(2, file_id).step();
}

void HistoryStore::set_attachment_redeemed(const Bytes& file_id, uint32_t redeemed) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "UPDATE attachments SET redeemed = ? WHERE file_id = ?").i64(1, redeemed).blob(2, file_id).step();
}

void HistoryStore::drop_attachment_secrets(const Bytes& file_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "UPDATE attachments SET secrets = x'' WHERE file_id = ?").blob(1, file_id).step();
}

void HistoryStore::reset_downloading() {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "UPDATE attachments SET state = 1 WHERE state = 7").step();
}

// --- Deleting by agreement ---

bool HistoryStore::add_deletion(const Deletion& d) {
    std::lock_guard<std::mutex> lock(mutex_);
    Bytes entries;
    write_u32(entries, static_cast<uint32_t>(d.entries.size()));
    for (const auto& h : d.entries) write_blob(entries, h);
    Stmt(db_, "INSERT OR IGNORE INTO deletions(op_id, conv_id, scope, expires_at, requester_fp, entries, state, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)")
        .blob(1, d.op_id).blob(2, d.conversation_id).i64(3, d.scope).i64(4, d.expires_at).text(5, d.requester_fp).blob(6, entries).i64(7, d.state).i64(8, d.created_at).step();
    return sqlite3_changes(db_) > 0;
}

static HistoryStore::Deletion read_deletion(Stmt& s) {
    HistoryStore::Deletion d;
    d.op_id = s.column_blob(0);
    d.conversation_id = s.column_blob(1);
    d.scope = static_cast<int>(s.column_i64(2));
    d.expires_at = s.column_i64(3);
    d.requester_fp = s.column_text(4);
    Bytes entries = s.column_blob(5);
    size_t off = 0;
    if (auto n = read_u32(entries.data(), entries.size(), off))
        for (uint32_t i = 0; i < *n; i++)
            if (auto h = read_blob(entries.data(), entries.size(), off, 64)) d.entries.push_back(std::move(*h));
    d.state = static_cast<int>(s.column_i64(6));
    d.created_at = s.column_i64(7);
    return d;
}

static const char DELETION_COLUMNS[] = "op_id, conv_id, scope, expires_at, requester_fp, entries, state, created_at";

std::optional<HistoryStore::Deletion> HistoryStore::deletion(const Bytes& op_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, (std::string("SELECT ") + DELETION_COLUMNS + " FROM deletions WHERE op_id = ?").c_str());
    s.blob(1, op_id);
    if (!s.step()) return std::nullopt;
    return read_deletion(s);
}

std::vector<HistoryStore::Deletion> HistoryStore::deletions() {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, (std::string("SELECT ") + DELETION_COLUMNS + " FROM deletions ORDER BY created_at DESC, rowid DESC").c_str());
    std::vector<Deletion> out;
    while (s.step()) out.push_back(read_deletion(s));
    return out;
}

void HistoryStore::set_deletion_state(const Bytes& op_id, int state) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "UPDATE deletions SET state = ? WHERE op_id = ?").i64(1, state).blob(2, op_id).step();
}

void HistoryStore::add_deletion_accept(const Bytes& op_id, const Bytes& key_hash, const Bytes& signature, const std::string& member_fp) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "INSERT OR IGNORE INTO deletion_accepts(op_id, key_hash, signature, member_fp) VALUES(?, ?, ?, ?)").blob(1, op_id).blob(2, key_hash).blob(3, signature).text(4, member_fp).step();
}

std::vector<HistoryStore::DeletionAccept> HistoryStore::deletion_accepts(const Bytes& op_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT key_hash, signature, member_fp FROM deletion_accepts WHERE op_id = ? ORDER BY rowid");
    s.blob(1, op_id);
    std::vector<DeletionAccept> out;
    while (s.step()) out.push_back({s.column_blob(0), s.column_blob(1), s.column_text(2)});
    return out;
}

void HistoryStore::save_archive_message(const Bytes& conversation_id, const Bytes& message_id, uint64_t number) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "INSERT OR IGNORE INTO archive_messages(conv_id, msg_id, number) VALUES(?, ?, ?)").blob(1, conversation_id).blob(2, message_id).i64(3, static_cast<int64_t>(number)).step();
}

std::optional<uint64_t> HistoryStore::archive_message_number(const Bytes& conversation_id, const Bytes& message_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT number FROM archive_messages WHERE conv_id = ? AND msg_id = ?");
    s.blob(1, conversation_id).blob(2, message_id);
    if (!s.step()) return std::nullopt;
    return static_cast<uint64_t>(s.column_i64(0));
}

std::vector<HistoryStore::Bytes> HistoryStore::archive_messages_at(const Bytes& conversation_id, uint64_t number) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT msg_id FROM archive_messages WHERE conv_id = ? AND number = ?");
    s.blob(1, conversation_id).i64(2, static_cast<int64_t>(number));
    std::vector<Bytes> out;
    while (s.step()) out.push_back(s.column_blob(0));
    return out;
}

std::optional<uint64_t> HistoryStore::archive_number_of(const Bytes& conversation_id, const Bytes& entry_hash) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT number FROM archive_chain WHERE conv_id = ? AND hash = ?");
    s.blob(1, conversation_id).blob(2, entry_hash);
    if (!s.step()) return std::nullopt;
    return static_cast<uint64_t>(s.column_i64(0));
}

void HistoryStore::mark_archive_redacted(const Bytes& conversation_id, uint64_t number) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "INSERT OR IGNORE INTO archive_redacted(conv_id, number) VALUES(?, ?)").blob(1, conversation_id).i64(2, static_cast<int64_t>(number)).step();
}

bool HistoryStore::archive_redacted(const Bytes& conversation_id, uint64_t number) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT 1 FROM archive_redacted WHERE conv_id = ? AND number = ?");
    s.blob(1, conversation_id).i64(2, static_cast<int64_t>(number));
    return s.step();
}

bool HistoryStore::erase_message(const Bytes& conversation_id, const Bytes& message_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "UPDATE messages SET sealed = x'' WHERE conv_id = ? AND msg_id = ? AND length(sealed) > 0").blob(1, conversation_id).blob(2, message_id).step();
    return sqlite3_changes(db_) > 0;
}

void HistoryStore::erase_conversation_messages(const Bytes& conversation_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    Transaction tx(db_);
    Stmt(db_, "DELETE FROM messages WHERE conv_id = ?").blob(1, conversation_id).step();
    Stmt(db_, "DELETE FROM deliveries WHERE conv_id = ?").blob(1, conversation_id).step();
    tx.commit();
}

void HistoryStore::remove_archive(const Bytes& conversation_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    Transaction tx(db_);
    for (const char* sql : {"DELETE FROM archives WHERE conv_id = ?", "DELETE FROM archive_chain WHERE conv_id = ?", "DELETE FROM archive_messages WHERE conv_id = ?",
                            "DELETE FROM archive_redacted WHERE conv_id = ?"})
        Stmt(db_, sql).blob(1, conversation_id).step();
    tx.commit();
}

// --- Verified people ---

void HistoryStore::set_verified(const std::string& fp, bool verified, int64_t now) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (verified) Stmt(db_, "INSERT OR IGNORE INTO verified_people(fp, verified_at) VALUES(?, ?)").text(1, fp).i64(2, now).step();
    else Stmt(db_, "DELETE FROM verified_people WHERE fp = ?").text(1, fp).step();
}

bool HistoryStore::is_verified(const std::string& fp) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT 1 FROM verified_people WHERE fp = ?");
    s.text(1, fp);
    return s.step();
}

std::vector<std::string> HistoryStore::verified_people() {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT fp FROM verified_people ORDER BY verified_at, fp");
    std::vector<std::string> out;
    while (s.step()) out.push_back(s.column_text(0));
    return out;
}

// --- Member tokens ---

static Bytes member_token_aad(const Bytes& conversation_id, const std::string& member_fp) {
    return aad_of("pq-suite v3 history member token", conversation_id, Bytes(member_fp.begin(), member_fp.end()));
}

void HistoryStore::save_member_token(const Bytes& conversation_id, const std::string& member_fp, const Bytes& token, int64_t now) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt(db_, "INSERT OR REPLACE INTO member_tokens(conv_id, fp, sealed, received_at) VALUES(?, ?, ?, ?)")
        .blob(1, conversation_id).text(2, member_fp).blob(3, seal(token, member_token_aad(conversation_id, member_fp))).i64(4, now).step();
}

std::vector<HistoryStore::MemberTokenRow> HistoryStore::all_member_tokens() {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT conv_id, fp, sealed FROM member_tokens ORDER BY conv_id, fp");
    std::vector<MemberTokenRow> out;
    while (s.step()) {
        MemberTokenRow row;
        row.conversation_id = s.column_blob(0);
        row.member_fp = s.column_text(1);
        if (auto token = unseal(s.column_blob(2), member_token_aad(row.conversation_id, row.member_fp))) {
            row.token = std::move(*token);
            out.push_back(std::move(row));
        }
    }
    return out;
}

std::optional<HistoryStore::Bytes> HistoryStore::member_token(const Bytes& conversation_id, const std::string& member_fp) {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt s(db_, "SELECT sealed FROM member_tokens WHERE conv_id = ? AND fp = ?");
    s.blob(1, conversation_id).text(2, member_fp);
    if (!s.step()) return std::nullopt;
    return unseal(s.column_blob(0), member_token_aad(conversation_id, member_fp));
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
