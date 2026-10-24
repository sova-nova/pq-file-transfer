// Tests for the encrypted local history store.
#include "crypto_engine.h"
#include "history_store.h"
#include "prekey.h"
#include "prekey_vault.h"

#include <sqlite3.h>

#include <algorithm>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>
#include <unistd.h>

namespace fs = std::filesystem;
using Bytes = std::vector<uint8_t>;

static int failures = 0;
#define CHECK(c, msg)                                                  \
    do {                                                               \
        if (c) std::cout << "  PASS " << (msg) << "\n";                \
        else { std::cout << "  FAIL " << (msg) << "\n"; failures++; } \
    } while (0)

template <typename F> static bool throws(F f) { try { f(); } catch (const std::exception&) { return true; } return false; }

static Bytes id(uint8_t n, size_t len = 16) { return Bytes(len, n); }
static Bytes text(const std::string& s) { return Bytes(s.begin(), s.end()); }

static bool file_contains(const fs::path& p, const std::string& needle) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return false;
    std::string data((std::istreambuf_iterator<char>(f)), {});
    return data.find(needle) != std::string::npos;
}

static HistoryStore::Message msg(const Bytes& conv, uint8_t n, bool outgoing, int64_t sent, const std::string& body, int status = 0) {
    HistoryStore::Message m;
    m.conversation_id = conv;
    m.message_id = id(n);
    m.outgoing = outgoing;
    m.sent_at = sent;
    m.received_at = sent + 1;
    m.status = status;
    m.entry_hash = id(static_cast<uint8_t>(0x80 + n), 32);
    m.record = text(body);
    return m;
}


// --- Raw SQLite, for building and inspecting databases the way older versions left them ---

static void raw_exec(const fs::path& p, const std::string& sql) {
    sqlite3* h = nullptr;
    sqlite3_open_v2(p.string().c_str(), &h, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
    char* err = nullptr;
    if (sqlite3_exec(h, sql.c_str(), nullptr, nullptr, &err) != SQLITE_OK) {
        std::cerr << "raw_exec failed: " << (err ? err : "?") << "\n";
        sqlite3_free(err);
    }
    sqlite3_close(h);
}

static int64_t raw_int(const fs::path& p, const std::string& sql) {
    sqlite3* h = nullptr;
    sqlite3_open_v2(p.string().c_str(), &h, SQLITE_OPEN_READWRITE, nullptr);
    sqlite3_stmt* st = nullptr;
    int64_t v = -1;
    if (sqlite3_prepare_v2(h, sql.c_str(), -1, &st, nullptr) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW) v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    sqlite3_close(h);
    return v;
}

static Bytes raw_blob(const fs::path& p, const std::string& sql) {
    sqlite3* h = nullptr;
    sqlite3_open_v2(p.string().c_str(), &h, SQLITE_OPEN_READWRITE, nullptr);
    sqlite3_stmt* st = nullptr;
    Bytes out;
    if (sqlite3_prepare_v2(h, sql.c_str(), -1, &st, nullptr) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW) {
        const uint8_t* b = static_cast<const uint8_t*>(sqlite3_column_blob(st, 0));
        int n = sqlite3_column_bytes(st, 0);
        if (b && n > 0) out.assign(b, b + n);
    }
    sqlite3_finalize(st);
    sqlite3_close(h);
    return out;
}

static std::string hexlit(const Bytes& b) {
    static const char* digits = "0123456789abcdef";
    std::string s = "x'";
    for (uint8_t c : b) { s += digits[c >> 4]; s += digits[c & 15]; }
    return s + "'";
}

// The database exactly as the first release (schema version 1) created it.
static const char* V1_SCHEMA =
    "CREATE TABLE conversations("
    "  id BLOB PRIMARY KEY, contact_fp TEXT NOT NULL UNIQUE,"
    "  created_at INTEGER NOT NULL, last_activity INTEGER NOT NULL,"
    "  send_delivery INTEGER NOT NULL DEFAULT 1, send_read INTEGER NOT NULL DEFAULT 1);"
    "CREATE TABLE messages("
    "  row INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  conv_id BLOB NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,"
    "  msg_id BLOB NOT NULL, outgoing INTEGER NOT NULL,"
    "  sent_at INTEGER NOT NULL, received_at INTEGER NOT NULL,"
    "  status INTEGER NOT NULL, gap INTEGER NOT NULL DEFAULT 0,"
    "  entry_hash BLOB NOT NULL, sealed BLOB NOT NULL,"
    "  UNIQUE(conv_id, msg_id));"
    "CREATE INDEX messages_by_hash ON messages(conv_id, entry_hash);"
    "CREATE TABLE outbox("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT, contact_fp TEXT NOT NULL, kind INTEGER NOT NULL,"
    "  msg_id BLOB NOT NULL, sealed BLOB NOT NULL, due_at INTEGER NOT NULL,"
    "  attempts INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);"
    "CREATE TABLE requests("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT, sender_fp TEXT NOT NULL,"
    "  bundle BLOB NOT NULL, received_at INTEGER NOT NULL, sealed BLOB NOT NULL);"
    "CREATE TABLE issued_tokens("
    "  token_hash BLOB PRIMARY KEY, label TEXT NOT NULL, created_at INTEGER NOT NULL,"
    "  bound_fp TEXT NOT NULL DEFAULT '', revoked INTEGER NOT NULL DEFAULT 0);"
    "CREATE TABLE contact_state("
    "  contact_fp TEXT PRIMARY KEY, bundle_sent INTEGER NOT NULL DEFAULT 0);"
    "PRAGMA user_version=1;";

static std::string fp_of(char c) { return std::string(64, c); }

int main() {
    fs::path dir = fs::temp_directory_path() / ("pqft-history-" + std::to_string(getpid()));
    fs::remove_all(dir);
    fs::create_directories(dir);
    fs::path db = dir / "history.db";
    Bytes key = CryptoEngine::random_bytes(32);
    const std::string fp_a = std::string(64, 'a'), fp_b = std::string(64, 'b');
    Bytes conv_a = id(0xA1), conv_b = id(0xB1);

    std::cout << "Conversations and messages\n";
    {
        HistoryStore h(db, key);
        CHECK(throws([&] { HistoryStore bad(dir / "bad.db", Bytes(31, 1)); }), "a key of the wrong length is refused");
        auto c = h.ensure_conversation(conv_a, fp_a, 1000);
        CHECK(c.id == conv_a && c.contact_fp == fp_a && c.send_delivery_receipts && c.send_read_receipts, "a conversation starts with receipts on");
        CHECK(h.ensure_conversation(conv_a, fp_a, 5000).created_at == 1000, "creating it again returns the same one");
        h.ensure_conversation(conv_b, fp_b, 2000);
        CHECK(h.conversations().size() == 2 && h.conversation_for(fp_a)->id == conv_a && !h.conversation_for(std::string(64, 'c')), "lookup by contact");

        CHECK(h.add_message(msg(conv_a, 1, false, 3000, "first")) && h.add_message(msg(conv_a, 2, true, 3001, "second", 0)) && h.add_message(msg(conv_a, 3, false, 3002, "third")), "messages are stored");
        CHECK(!h.add_message(msg(conv_a, 2, true, 3001, "second again")), "a message ID already in the conversation is refused (replay)");
        CHECK(h.add_message(msg(conv_b, 2, false, 3003, "same ID, other conversation")), "...but the same ID in another conversation is a different message");
        auto all = h.messages(conv_a, 100);
        CHECK(all.size() == 3 && all[0].record == text("first") && all[1].record == text("second") && all[2].record == text("third"), "they come back in order, decrypted");
        CHECK(all.size() == 3 && all[1].outgoing && !all[0].outgoing && all[0].sent_at == 3000, "direction and times are kept");
        auto last2 = h.messages(conv_a, 2);
        CHECK(last2.size() == 2 && last2[0].record == text("second") && last2[1].record == text("third"), "a limit returns the newest ones, still oldest first");
        CHECK(h.conversations().front().id == conv_b, "conversations are listed by most recent activity");
        CHECK(h.find_message(conv_a, id(2))->record == text("second") && !h.find_message(conv_a, id(99)), "a single message can be looked up");

        h.set_receipt_settings(conv_a, true, false);
        CHECK(h.conversation_for(fp_a)->send_delivery_receipts && !h.conversation_for(fp_a)->send_read_receipts, "receipt settings are per conversation");
    }

    std::cout << "Nothing readable on disk\n";
    {
        HistoryStore h(db, key);
        h.add_message(msg(conv_a, 10, false, 4000, "ZEBRA-PASSWORD-IS-HUNTER2"));
        h.enqueue(fp_a, 0, id(11), {text("OUTBOX-SECRET-TEXT")}, 0, 4000);
        h.add_request(fp_b, text("a public bundle"), {text("REQUEST-SECRET-TEXT")}, 4000);
        CHECK(!file_contains(db, "ZEBRA-PASSWORD-IS-HUNTER2") && !file_contains(fs::path(db.string() + "-wal"), "ZEBRA-PASSWORD-IS-HUNTER2"), "message text is not in the database file or its journal");
        CHECK(!file_contains(db, "OUTBOX-SECRET-TEXT") && !file_contains(fs::path(db.string() + "-wal"), "OUTBOX-SECRET-TEXT"), "queued messages are encrypted too");
        CHECK(!file_contains(db, "REQUEST-SECRET-TEXT") && !file_contains(fs::path(db.string() + "-wal"), "REQUEST-SECRET-TEXT"), "and message requests");
        CHECK(h.messages(conv_a, 100).back().record == text("ZEBRA-PASSWORD-IS-HUNTER2"), "(sanity) it reads back fine with the key");
    }

    std::cout << "Wrong key, swapped rows\n";
    {
        {
            HistoryStore other(db, CryptoEngine::random_bytes(32));
            CHECK(other.messages(conv_a, 100).empty(), "with a different key no message can be read (and nothing crashes)");
            CHECK(other.due_items(1 << 30, 10).empty() && other.requests().empty(), "nor the outbox or the requests");
        }
        HistoryStore h(db, key);
        CHECK(h.messages(conv_a, 100).size() == 4, "the right key still reads everything");

        // Copy one row's ciphertext over another's: the row's identity is authenticated, so neither reads.
        sqlite3* raw = nullptr;
        sqlite3_open_v2(db.string().c_str(), &raw, SQLITE_OPEN_READWRITE, nullptr);
        sqlite3_exec(raw, "UPDATE messages SET sealed = (SELECT sealed FROM messages WHERE row = 1) WHERE row = 2", nullptr, nullptr, nullptr);
        sqlite3_close(raw);
        auto after = h.messages(conv_a, 100);
        bool second_gone = true, first_ok = false;
        for (auto& m : after) { if (m.record == text("second")) second_gone = false; if (m.record == text("first")) first_ok = true; }
        CHECK(second_gone && first_ok && after.size() == 3, "a ciphertext copied into another row of the same conversation is rejected");

        raw = nullptr;
        sqlite3_open_v2(db.string().c_str(), &raw, SQLITE_OPEN_READWRITE, nullptr);
        sqlite3_exec(raw, "UPDATE messages SET sealed = (SELECT sealed FROM messages WHERE row = 1) WHERE conv_id = x'B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1'", nullptr, nullptr, nullptr);
        sqlite3_close(raw);
        CHECK(h.messages(conv_b, 100).empty(), "a ciphertext moved into another conversation is rejected");
    }

    std::cout << "Status, read state and entry hashes\n";
    {
        fs::remove(db);
        HistoryStore h(db, key);
        h.ensure_conversation(conv_a, fp_a, 1000);
        h.add_message(msg(conv_a, 1, true, 100, "out one", HistoryStore::Queued));
        h.add_message(msg(conv_a, 2, false, 101, "in one", 0));
        h.add_message(msg(conv_a, 3, false, 102, "in two", 0));
        h.add_message(msg(conv_a, 4, true, 103, "out two", HistoryStore::Queued));

        CHECK(h.raise_status(conv_a, id(1), HistoryStore::Sent) && h.find_message(conv_a, id(1))->status == HistoryStore::Sent, "an outgoing message moves to Sent");
        CHECK(h.raise_status(conv_a, id(1), HistoryStore::Read) && h.find_message(conv_a, id(1))->status == HistoryStore::Read, "...and to Read");
        CHECK(!h.raise_status(conv_a, id(1), HistoryStore::Delivered) && h.find_message(conv_a, id(1))->status == HistoryStore::Read, "a late Delivered never undoes Read");
        CHECK(!h.raise_status(conv_a, id(2), HistoryStore::Read) && h.find_message(conv_a, id(2))->status == 0, "an incoming message's status can't be raised by a receipt");

        CHECK(h.unread_count(conv_a) == 2, "two unread incoming messages");
        auto marked = h.mark_all_read(conv_a);
        CHECK(marked.size() == 2 && marked[0] == id(2) && marked[1] == id(3) && h.unread_count(conv_a) == 0, "marking read returns exactly the messages it changed, oldest first");
        CHECK(h.mark_all_read(conv_a).empty(), "marking again changes nothing");

        CHECK(h.has_entry(conv_a, id(0x81, 32)) && !h.has_entry(conv_a, id(0x7F, 32)) && !h.has_entry(conv_b, id(0x81, 32)), "entries are found by hash, within their conversation");
        CHECK(*h.last_entry_hash(conv_a, true) == id(0x84, 32) && *h.last_entry_hash(conv_a, false) == id(0x83, 32), "the last entry hash is tracked per direction");
        CHECK(!h.last_entry_hash(conv_b, true), "none for a conversation with no messages");
    }

    std::cout << "Outgoing queue\n";
    {
        HistoryStore h(db, key);
        int64_t a = h.enqueue(fp_a, 0, id(1), {text("r1"), text("r2")}, 100, 50);
        int64_t b = h.enqueue(fp_b, 1, id(2), {text("r3")}, 200, 50);
        CHECK(h.outbox_size() == 2, "two items queued");
        auto due = h.due_items(150, 10);
        CHECK(due.size() == 1 && due[0].id == a && due[0].records.size() == 2 && due[0].records[1] == text("r2") && due[0].kind == 0 && due[0].contact_fp == fp_a, "only items that are due come out, with their records");
        CHECK(h.due_items(300, 10).size() == 2 && h.due_items(300, 1).size() == 1, "later both are due; the limit applies");
        h.update_outbox_records(a, {text("grant"), text("r1"), text("r2")});
        CHECK(h.due_items(300, 10)[0].records.size() == 3 && h.due_items(300, 10)[0].records[0] == text("grant"), "an item's records can be extended (a token grant is added)");
        h.outbox_failed(a, 1000);
        auto again = h.due_items(500, 10);
        CHECK(again.size() == 1 && again[0].id == b, "a failed item waits until its next try");
        CHECK(h.due_items(1000, 10).front().attempts == 1, "...and counts its attempts");
        h.outbox_done(a); h.outbox_done(b);
        CHECK(h.outbox_size() == 0, "finished items are removed");
    }

    std::cout << "Requests, issued tokens, first-contact state\n";
    {
        HistoryStore h(db, key);
        h.add_request(fp_b, text("bundle"), {text("m1")}, 10);
        h.add_request(fp_b, text("bundle"), {text("m2"), text("m3")}, 20);
        h.add_request(fp_a, text("bundle a"), {text("x")}, 30);
        auto reqs = h.requests();
        CHECK(reqs.size() == 3 && reqs[1].records.size() == 2 && reqs[1].bundle == text("bundle") && h.request_count() == 3, "pending requests keep their records");
        h.delete_requests(fp_b);
        CHECK(h.requests().size() == 1 && h.requests()[0].sender_fp == fp_a, "deleting a sender's requests leaves others");

        Bytes t1 = id(0x11, 32), t2 = id(0x22, 32);
        h.add_issued_token(t1, "for Bob", "", 100);
        h.add_issued_token(t2, "first message to Carol", fp_b, 101);
        auto f1 = h.find_issued_token(t1);
        CHECK(f1 && f1->label == "for Bob" && f1->bound_fp.empty() && !f1->revoked && h.find_issued_token(t2)->bound_fp == fp_b, "issued tokens are remembered with their label");
        h.bind_issued_token(t1, fp_a);
        h.bind_issued_token(t1, fp_b);
        CHECK(h.find_issued_token(t1)->bound_fp == fp_a, "a token binds to the first person who uses it and stays there");
        h.mark_token_revoked(t1);
        CHECK(h.find_issued_token(t1)->revoked && h.issued_tokens().size() == 2 && h.issued_tokens()[0].hash == t2, "revoking is recorded; the list is newest first");
        CHECK(!h.find_issued_token(id(0x99, 32)), "an unknown token isn't there");

        CHECK(!h.bundle_sent(fp_a), "no bundle sent at first");
        h.set_bundle_sent(fp_a); h.set_bundle_sent(fp_a);
        CHECK(h.bundle_sent(fp_a) && !h.bundle_sent(fp_b), "it is remembered per contact");
    }

    std::cout << "Persistence and concurrency\n";
    {
        { HistoryStore h(db, key); h.ensure_conversation(conv_b, fp_b, 5); h.add_message(msg(conv_b, 50, false, 5000, "kept across restarts")); }
        HistoryStore reopened(db, key);
        CHECK(reopened.messages(conv_b, 10).size() == 1 && reopened.messages(conv_b, 10)[0].record == text("kept across restarts"), "everything survives closing and reopening");

        std::atomic<int> errors{0};
        std::vector<std::thread> threads;
        for (int t = 0; t < 4; t++)
            threads.emplace_back([&, t] {
                for (int i = 0; i < 50; i++) {
                    try {
                        HistoryStore::Message m = msg(conv_b, 0, false, 6000 + i, "t" + std::to_string(t) + "m" + std::to_string(i));
                        m.message_id = Bytes(16, 0);
                        m.message_id[0] = static_cast<uint8_t>(t + 1); m.message_id[1] = static_cast<uint8_t>(i);
                        m.entry_hash = CryptoEngine::random_bytes(32);
                        if (!reopened.add_message(m)) errors++;
                    } catch (...) { errors++; }
                }
            });
        for (auto& th : threads) th.join();
        CHECK(errors == 0 && reopened.messages(conv_b, 1000).size() == 201, "four threads storing at once lose nothing");
    }


    std::cout << "Upgrading a version 1 history keeps everything\n";
    {
        fs::path v1 = dir / "v1.db", scratch = dir / "scratch.db";
        // Real sealed messages (made under the same key) to put into the old-shaped database.
        {
            HistoryStore s(scratch, key);
            s.ensure_conversation(conv_a, fp_a, 1000);
            s.add_message(msg(conv_a, 1, false, 3000, "first"));
            s.add_message(msg(conv_a, 2, true, 3001, "second"));
            s.add_message(msg(conv_a, 3, true, 3002, "third"));
        }
        auto sealed = [&](uint8_t n) { return raw_blob(scratch, "SELECT sealed FROM messages WHERE msg_id = " + hexlit(id(n))); };
        std::string sql = V1_SCHEMA;
        sql += "INSERT INTO conversations VALUES(" + hexlit(conv_a) + ", '" + fp_a + "', 1000, 3002, 1, 0);";
        sql += "INSERT INTO conversations VALUES(" + hexlit(conv_b) + ", '" + fp_b + "', 2000, 2000, 0, 1);";
        auto message_sql = [&](uint8_t n, int outgoing, int64_t sent, int status) {
            return "INSERT INTO messages(conv_id, msg_id, outgoing, sent_at, received_at, status, gap, entry_hash, sealed) VALUES(" +
                   hexlit(conv_a) + ", " + hexlit(id(n)) + ", " + std::to_string(outgoing) + ", " + std::to_string(sent) + ", " +
                   std::to_string(sent + 1) + ", " + std::to_string(status) + ", 0, " + hexlit(id(static_cast<uint8_t>(0x80 + n), 32)) +
                   ", " + hexlit(sealed(n)) + ");";
        };
        sql += message_sql(1, 0, 3000, 0) + message_sql(2, 1, 3001, 1) + message_sql(3, 1, 3002, 2);
        sql += "INSERT INTO outbox(contact_fp, kind, msg_id, sealed, due_at, created_at) VALUES('" + fp_a + "', 0, " + hexlit(id(9)) + ", x'00', 0, 3000);";
        sql += "INSERT INTO requests(sender_fp, bundle, received_at, sealed) VALUES('" + fp_b + "', x'01', 3000, x'02');";
        sql += "INSERT INTO issued_tokens VALUES(" + hexlit(id(0x77, 32)) + ", 'for Bob', 100, '" + fp_a + "', 0);";
        sql += "INSERT INTO contact_state VALUES('" + fp_a + "', 1);";
        raw_exec(v1, sql);
        CHECK(raw_int(v1, "PRAGMA user_version") == 1, "(setup) the fixture really is a version 1 database");

        {
            HistoryStore h(v1, key);
            CHECK(raw_int(v1, "PRAGMA user_version") == 10, "opening it upgrades it to the current version (10)");
            fs::path backup = fs::path(v1.string() + ".before-v2");
            CHECK(fs::exists(backup) && raw_int(backup, "PRAGMA user_version") == 1 && raw_int(backup, "SELECT COUNT(*) FROM conversations") == 2,
                  "the old file is kept next to it, unchanged, before anything is rewritten");

            auto all = h.conversations();
            CHECK(all.size() == 2, "both conversations are still there");
            auto a = h.conversation_for(fp_a);
            CHECK(a && a->id == conv_a && a->kind == HistoryStore::Direct && a->state == HistoryStore::Active && a->mode == HistoryStore::Saved,
                  "an old conversation becomes a direct, active, Saved one with its ID unchanged");
            CHECK(a && a->created_at == 1000 && a->last_activity == 3002 && a->send_delivery_receipts && !a->send_read_receipts,
                  "...with its times and receipt settings");
            CHECK(a && a->title.empty() && a->creator_fp.empty() && a->previous_id.empty() && a->timer_seconds == 0, "...and no group fields");
            CHECK(a && a->members == std::vector<std::string>{fp_a}, "the contact became the conversation's one member");
            auto b = h.conversation_for(fp_b);
            CHECK(b && b->id == conv_b && !b->send_delivery_receipts && b->send_read_receipts && b->members == std::vector<std::string>{fp_b}, "so did the other one, with its own settings");

            auto msgs = h.messages(conv_a, 100);
            CHECK(msgs.size() == 3 && msgs[0].record == text("first") && msgs[1].record == text("second") && msgs[2].record == text("third"),
                  "every message still decrypts, in order");
            CHECK(msgs.size() == 3 && msgs[0].status == 0 && msgs[1].status == HistoryStore::Sent && msgs[2].status == HistoryStore::Delivered &&
                      !msgs[0].outgoing && msgs[1].outgoing, "...with its direction and delivery status");
            CHECK(h.outbox_size() == 1 && h.request_count() == 1, "the outgoing queue and message requests are kept");
            auto token = h.find_issued_token(id(0x77, 32));
            CHECK(token && token->label == "for Bob" && token->bound_fp == fp_a, "issued tokens are kept");
            CHECK(h.bundle_sent(fp_a) && !h.bundle_sent(fp_b), "so is the first-contact state");
            CHECK(raw_int(v1, "SELECT COUNT(*) FROM pragma_foreign_key_check") == 0, "the upgraded database passes SQLite's own integrity check");

            CHECK(h.add_message(msg(conv_a, 4, false, 4000, "after the upgrade")) && h.messages(conv_a, 100).size() == 4, "new messages can be added to an upgraded conversation");
            CHECK(throws([&] { h.add_message(msg(id(0xEE), 5, false, 4001, "nobody's")); }), "foreign keys are enforced again afterwards (a message needs a real conversation)");

            // An old outgoing message gets receipts through the new per-member path.
            CHECK(h.raise_delivery(conv_a, id(2), fp_a, HistoryStore::Delivered) && h.find_message(conv_a, id(2))->status == HistoryStore::Delivered,
                  "a receipt for a message from before the upgrade raises its status");
            CHECK(h.raise_delivery(conv_a, id(2), fp_a, HistoryStore::Read) && h.find_message(conv_a, id(2))->status == HistoryStore::Read, "...and so does the read receipt");
        }
        auto size_of = [](const fs::path& f) { std::error_code ec; auto n = fs::file_size(f, ec); return ec ? int64_t(-1) : static_cast<int64_t>(n); };
        int64_t backup_size = size_of(fs::path(v1.string() + ".before-v2"));
        {
            HistoryStore again(v1, key);
            CHECK(again.messages(conv_a, 100).size() == 4 && raw_int(v1, "PRAGMA user_version") == 10, "opening it again changes nothing");
        }
        CHECK(backup_size > 0 && size_of(fs::path(v1.string() + ".before-v2")) == backup_size, "...and the saved old copy is not overwritten");

        fs::path fresh = dir / "fresh.db";
        { HistoryStore f(fresh, key); }
        CHECK(raw_int(fresh, "PRAGMA user_version") == 10 && !fs::exists(fs::path(fresh.string() + ".before-v2")), "a brand-new history starts at the current version, with nothing to back up");

        fs::path future = dir / "future.db";
        { HistoryStore f(future, key); }
        raw_exec(future, "PRAGMA user_version=99;");
        std::string what;
        bool refused = false;
        try { HistoryStore f(future, key); } catch (const std::exception& e) { refused = true; what = e.what(); }
        CHECK(refused && what.find("newer version") != std::string::npos, "a history made by a newer app is refused with an explanation, not mangled: " + what);
        CHECK(raw_int(future, "PRAGMA user_version") == 99, "...and left exactly as it was");
    }

    std::cout << "Group conversations\n";
    {
        HistoryStore h(dir / "groups.db", key);
        const std::string fp_c = fp_of('c'), fp_d = fp_of('d');
        Bytes g1 = id(0x61), g2 = id(0x62);

        auto g = h.create_group(g1, "Hiking", fp_a, HistoryStore::Saved, 0, Bytes(), {fp_a, fp_b, fp_c}, HistoryStore::SettingUp, 5000);
        CHECK(g.id == g1 && g.kind == HistoryStore::Group && g.title == "Hiking" && g.creator_fp == fp_a && g.mode == HistoryStore::Saved &&
                  g.timer_seconds == 0 && g.state == HistoryStore::SettingUp && g.contact_fp.empty() && g.previous_id.empty() &&
                  g.created_at == 5000 && g.last_activity == 5000,
              "a group is stored with its title, creator, mode, timer and state");
        CHECK(g.members == (std::vector<std::string>{fp_a, fp_b, fp_c}), "its members keep their order");
        auto looked_up = h.conversation(g1);
        CHECK(looked_up && looked_up->id == g1 && looked_up->members == g.members && !h.conversation(id(0x99)), "it can be looked up by ID");

        h.set_conversation_state(g1, HistoryStore::Active);
        CHECK(h.conversation(g1)->state == HistoryStore::Active, "a group stops being 'setting up' when told to");
        CHECK(throws([&] { h.set_conversation_state(g1, 9); }), "an unknown state is refused");

        auto replay = h.create_group(g1, "Changed title", fp_b, HistoryStore::Saved, 0, Bytes(), {fp_d}, HistoryStore::SettingUp, 9000);
        CHECK(replay.title == "Hiking" && replay.creator_fp == fp_a && replay.members.size() == 3 && replay.state == HistoryStore::Active && h.conversations().size() == 1,
              "creating a group that already exists changes nothing (a replayed creation record)");

        size_t before = h.conversations().size();
        std::vector<std::string> sixteen;  // 16 distinct fingerprints
        for (int i = 0; i < 16; i++) { std::string f(64, '0'); f[0] = "0123456789abcdef"[i]; sixteen.push_back(f); }
        std::vector<std::string> fifteen(sixteen.begin(), sixteen.begin() + 15);
        CHECK(throws([&] { h.create_group(id(0x70), "x", fp_a, HistoryStore::Saved, 0, Bytes(), {}, 0, 1); }), "a group with nobody in it is refused");
        CHECK(throws([&] { h.create_group(id(0x71), "x", fp_a, HistoryStore::Saved, 0, Bytes(), sixteen, 0, 1); }), "more than 15 other people (16 with you) is refused");
        CHECK(throws([&] { h.create_group(id(0x72), "x", fp_a, HistoryStore::Saved, 0, Bytes(), {fp_b, fp_b}, 0, 1); }), "listing someone twice is refused");
        CHECK(throws([&] { h.create_group(id(0x73), "x", fp_a, HistoryStore::Saved, 0, Bytes(), {fp_b, "not a fingerprint"}, 0, 1); }), "a member that isn't a fingerprint is refused");
        CHECK(throws([&] { h.create_group(id(0x74), "x", fp_a, HistoryStore::Saved, 0, Bytes(), {std::string(63, 'a') + "A"}, 0, 1); }), "...including upper case, since fingerprints are lower case hex everywhere");
        CHECK(throws([&] { h.create_group(id(0x75), std::string(65, 't'), fp_a, HistoryStore::Saved, 0, Bytes(), {fp_b}, 0, 1); }), "a title over 64 bytes is refused");
        CHECK(throws([&] { h.create_group(id(0x76), "x", "short", HistoryStore::Saved, 0, Bytes(), {fp_b}, 0, 1); }), "a creator that isn't a fingerprint is refused");
        CHECK(throws([&] { h.create_group(id(0x77), "x", fp_a, 2, 0, Bytes(), {fp_b}, 0, 1); }), "a mode other than Saved is refused for now");
        CHECK(throws([&] { h.create_group(Bytes(), "x", fp_a, HistoryStore::Saved, 0, Bytes(), {fp_b}, 0, 1); }), "an empty conversation ID is refused");
        CHECK(h.conversations().size() == before, "none of those created anything");
        CHECK(h.create_group(id(0x78), "Everyone", fp_a, HistoryStore::Saved, 0, Bytes(), fifteen, 0, 1).members.size() == 15, "15 other people (16 in all) is the largest allowed");

        // Directs and groups live side by side.
        h.ensure_conversation(conv_a, fp_a, 6000);
        auto direct = h.conversation_for(fp_a);
        CHECK(direct && direct->id == conv_a && direct->kind == HistoryStore::Direct, "the direct conversation with someone is not confused with a group they are in");
        auto twin = h.create_group(g2, "Hiking again", fp_a, HistoryStore::Saved, 0, g1, {fp_a, fp_b, fp_c}, HistoryStore::Active, 7000);
        CHECK(twin.id == g2 && twin.previous_id == g1 && h.conversation(g1)->members == twin.members, "two groups can have the same members, and one can point to the one it replaces");
        CHECK(!h.conversation_for(fp_d), "a person who is only in a group has no direct conversation");

        // Messages work in groups exactly as in direct conversations.
        CHECK(h.add_message(msg(g1, 1, false, 8000, "hello group")) && h.unread_count(g1) == 1, "messages are stored in a group");
        CHECK(h.mark_all_read(g1).size() == 1 && h.unread_count(g1) == 0, "...and read state works");
        CHECK(h.add_message(msg(g2, 1, false, 8001, "same ID, other group")), "the same message ID in another group is a different message");
    }

    std::cout << "Delivery to each member\n";
    {
        HistoryStore h(dir / "delivery.db", key);
        const std::string fp_c = fp_of('c'), fp_d = fp_of('d');
        Bytes g = id(0x61);
        h.create_group(g, "Trio", fp_a, HistoryStore::Saved, 0, Bytes(), {fp_a, fp_b, fp_c}, HistoryStore::Active, 1000);
        h.add_message(msg(g, 7, true, 2000, "to all three", HistoryStore::Queued));
        auto overall = [&](uint8_t n) { return h.find_message(g, id(n))->status; };
        auto of = [&](uint8_t n, const std::string& who) {
            for (const auto& d : h.deliveries(g, id(n)))
                if (d.member_fp == who) return d.status;
            return -1;
        };

        auto start = h.deliveries(g, id(7));
        CHECK(start.size() == 3 && start[0].member_fp == fp_a && start[1].member_fp == fp_b && start[2].member_fp == fp_c &&
                  start[0].status == 0 && start[1].status == 0 && start[2].status == 0,
              "a new message is Queued for every member, listed in member order");

        CHECK(h.raise_delivery(g, id(7), fp_a, HistoryStore::Sent), "the relay taking it for one member is a change");
        CHECK(of(7, fp_a) == HistoryStore::Sent && of(7, fp_b) == 0 && of(7, fp_c) == 0, "...for that member only");
        CHECK(overall(7) == HistoryStore::Queued, "the message as a whole is not 'sent' while two members still wait");
        h.raise_delivery(g, id(7), fp_b, HistoryStore::Sent);
        CHECK(overall(7) == HistoryStore::Queued, "(still waiting for the third)");
        h.raise_delivery(g, id(7), fp_c, HistoryStore::Sent);
        CHECK(overall(7) == HistoryStore::Sent, "once every member's copy is deposited it is Sent");

        h.raise_delivery(g, id(7), fp_a, HistoryStore::Delivered);
        CHECK(overall(7) == HistoryStore::Sent && of(7, fp_a) == HistoryStore::Delivered, "one member confirming delivery doesn't make it Delivered");
        h.raise_delivery(g, id(7), fp_b, HistoryStore::Delivered);
        h.raise_delivery(g, id(7), fp_c, HistoryStore::Delivered);
        CHECK(overall(7) == HistoryStore::Delivered, "when all have, it is Delivered");
        h.raise_delivery(g, id(7), fp_a, HistoryStore::Read);
        h.raise_delivery(g, id(7), fp_b, HistoryStore::Read);
        CHECK(overall(7) == HistoryStore::Delivered, "Read needs everyone too");
        h.raise_delivery(g, id(7), fp_c, HistoryStore::Read);
        CHECK(overall(7) == HistoryStore::Read, "...and then it is Read");

        CHECK(!h.raise_delivery(g, id(7), fp_a, HistoryStore::Sent) && of(7, fp_a) == HistoryStore::Read && overall(7) == HistoryStore::Read, "a state never goes down");
        CHECK(!h.raise_delivery(g, id(7), fp_d, HistoryStore::Read), "a receipt from someone who isn't a member counts for nothing");
        CHECK(!h.raise_delivery(g, id(99), fp_a, HistoryStore::Read), "nor does one for a message that doesn't exist");
        h.add_message(msg(g, 8, false, 2001, "someone else's"));
        CHECK(!h.raise_delivery(g, id(8), fp_a, HistoryStore::Read), "nor one for a message we received rather than sent");

        h.add_message(msg(g, 9, true, 2002, "mixed", HistoryStore::Queued));
        h.raise_delivery(g, id(9), fp_a, HistoryStore::Read);
        h.raise_delivery(g, id(9), fp_b, HistoryStore::Delivered);
        h.raise_delivery(g, id(9), fp_c, HistoryStore::Sent);
        CHECK(overall(9) == HistoryStore::Sent, "the overall state is that of the slowest member");
        CHECK(of(9, fp_a) == HistoryStore::Read && of(9, fp_b) == HistoryStore::Delivered && of(9, fp_c) == HistoryStore::Sent, "...while each member's own state is kept");

        // Direct conversations behave exactly as before, through the same path.
        h.ensure_conversation(conv_a, fp_a, 3000);
        h.add_message(msg(conv_a, 1, true, 3000, "direct", HistoryStore::Queued));
        CHECK(h.raise_delivery(conv_a, id(1), fp_a, HistoryStore::Sent) && h.find_message(conv_a, id(1))->status == HistoryStore::Sent, "in a direct conversation the one member's state is the message's state");
        CHECK(h.raise_delivery(conv_a, id(1), fp_a, HistoryStore::Read) && h.find_message(conv_a, id(1))->status == HistoryStore::Read, "...all the way to Read");
        CHECK(!h.raise_delivery(conv_a, id(1), fp_b, HistoryStore::Read), "and someone else's receipt is ignored there too");
    }

    std::cout << "Upgrading a version 2 history adds the new tables\n";
    {
        fs::path v2 = dir / "v2.db";
        const std::string fp_c = fp_of('c');
        {
            HistoryStore h(v2, key);
            h.create_group(id(0x61), "Kept through the upgrade", fp_a, HistoryStore::Saved, 0, Bytes(), {fp_a, fp_b, fp_c}, HistoryStore::Active, 100);
            h.add_message(msg(id(0x61), 1, true, 200, "still here", HistoryStore::Sent));
        }
        // Make it exactly what version 2 left: no invitation or introduced-member tables.
        raw_exec(v2, "DROP TABLE group_invites; DROP TABLE introduced_members; DROP TABLE member_tokens; DROP TABLE verified_people; DROP TABLE archives; DROP TABLE archive_chain; DROP TABLE deletions; DROP TABLE deletion_accepts; DROP TABLE archive_messages; DROP TABLE archive_redacted; DROP TABLE attachments; DROP TABLE peer_prekeys; PRAGMA user_version=2;");
        CHECK(raw_int(v2, "PRAGMA user_version") == 2 && raw_int(v2, "SELECT COUNT(*) FROM sqlite_master WHERE name = 'group_invites'") == 0, "(setup) the fixture really is a version 2 database");
        {
            HistoryStore h(v2, key);
            CHECK(raw_int(v2, "PRAGMA user_version") == 10, "opening it upgrades it to the current version (10)");
            auto g = h.conversation(id(0x61));
            CHECK(g && g->title == "Kept through the upgrade" && g->members.size() == 3 && h.messages(id(0x61), 10).size() == 1 && h.messages(id(0x61), 10)[0].record == text("still here"),
                  "the groups and messages it held are untouched");
            CHECK(h.add_group_invite(id(0x70), fp_b, text("creation"), 300) && h.group_invite_count() == 1, "the new tables work straight away");
        }
        CHECK(!fs::exists(fs::path(v2.string() + ".before-v2")), "adding tables needs no backup of the old file");
    }

    std::cout << "Pending group invitations\n";
    {
        HistoryStore h(dir / "invites.db", key);
        const std::string fp_c = fp_of('c');
        Bytes inv1 = id(0x71), inv2 = id(0x72);
        CHECK(h.group_invite_count() == 0 && h.group_invites().empty() && !h.group_invite(inv1), "there are none to begin with");
        CHECK(h.add_group_invite(inv1, fp_a, text("CREATION-RECORD-ONE"), 1000), "an invitation is stored");
        CHECK(!h.add_group_invite(inv1, fp_b, text("a different record"), 2000), "a second with the same conversation ID is refused");
        auto one = h.group_invite(inv1);
        CHECK(one && one->conversation_id == inv1 && one->creator_fp == fp_a && one->received_at == 1000 && one->records.size() == 1 && one->records[0] == text("CREATION-RECORD-ONE"),
              "it is read back with its creator, time and the original record (not the refused one)");
        h.add_group_invite(inv2, fp_c, text("CREATION-RECORD-TWO"), 500);
        auto both = h.group_invites();
        CHECK(both.size() == 2 && both[0].conversation_id == inv2 && both[1].conversation_id == inv1 && h.group_invite_count() == 2, "they are listed oldest first");

        CHECK(h.hold_for_invite(inv1, text("message 1")) && h.hold_for_invite(inv1, text("message 2")), "messages that arrive before the user decides are held");
        auto held = h.group_invite(inv1);
        CHECK(held && held->records.size() == 3 && held->records[0] == text("CREATION-RECORD-ONE") && held->records[1] == text("message 1") && held->records[2] == text("message 2"), "...in order, after the creation record");
        CHECK(h.hold_for_invite(inv1, text("message 1")) && h.group_invite(inv1)->records.size() == 3, "holding the same record twice keeps one copy");
        CHECK(!h.hold_for_invite(id(0x99), text("for nobody")), "a message for a conversation with no invitation is not held");
        for (size_t i = 0; i < HistoryStore::MAX_HELD_RECORDS - 2; i++) h.hold_for_invite(inv1, text("filler " + std::to_string(i)));
        CHECK(h.group_invite(inv1)->records.size() == 1 + HistoryStore::MAX_HELD_RECORDS && !h.hold_for_invite(inv1, text("one too many")), "at most 200 are held per invitation");
        CHECK(h.group_invite(inv2)->records.size() == 1, "(another invitation is not affected)");

        CHECK(!file_contains(dir / "invites.db", "CREATION-RECORD-ONE") && !file_contains(fs::path((dir / "invites.db").string() + "-wal"), "CREATION-RECORD-ONE") &&
                  !file_contains(dir / "invites.db", "message 1") && !file_contains(fs::path((dir / "invites.db").string() + "-wal"), "message 1"),
              "nothing of an invitation or the messages held with it is readable on disk");
        h.delete_group_invite(inv1);
        CHECK(!h.group_invite(inv1) && h.group_invite_count() == 1 && h.group_invites()[0].conversation_id == inv2, "declining removes it, and what was held with it");
        HistoryStore other(dir / "invites.db", CryptoEngine::random_bytes(32));
        CHECK(other.group_invites().empty() && !other.group_invite(inv2), "with a different key an invitation can't be read (and nothing crashes)");
    }

    std::cout << "People introduced by a group's creator\n";
    {
        HistoryStore h(dir / "introduced.db", key);
        const std::string fp_c = fp_of('c');
        CHECK(h.introduced_members().empty() && !h.introduced(fp_b), "nobody is introduced to begin with");
        h.save_introduced(fp_b, text("bundle b v1"), 100, fp_a, 1000);
        auto b = h.introduced(fp_b);
        CHECK(b && b->fp == fp_b && b->bundle == text("bundle b v1") && b->issued_at == 100 && b->introduced_by == fp_a && b->first_seen == 1000, "an introduced person is stored with who introduced them and when");
        h.save_introduced(fp_b, text("bundle b v2"), 200, fp_c, 2000);
        b = h.introduced(fp_b);
        CHECK(b && b->bundle == text("bundle b v2") && b->issued_at == 200 && b->introduced_by == fp_a && b->first_seen == 1000, "a newer bundle replaces the old one, while who introduced them first is kept");
        h.save_introduced(fp_b, text("an OLD bundle"), 50, fp_c, 3000);
        CHECK(h.introduced(fp_b)->bundle == text("bundle b v2"), "an older bundle is ignored");
        h.save_introduced(fp_c, text("bundle c"), 10, fp_a, 1500);
        auto all = h.introduced_members();
        CHECK(all.size() == 2 && all[0].fp == fp_b && all[1].fp == fp_c, "they are listed in the order they were first seen");
        h.delete_introduced_except({fp_c});
        CHECK(!h.introduced(fp_b) && h.introduced(fp_c) && h.introduced_members().size() == 1, "people no longer in any group or invitation can be forgotten");
        h.delete_introduced_except({});
        CHECK(h.introduced_members().empty(), "...all of them if need be");
    }

    std::cout << "Finding the conversation of an outgoing message\n";
    {
        HistoryStore h(dir / "outgoing.db", key);
        h.ensure_conversation(conv_a, fp_a, 1000);
        h.create_group(id(0x61), "G", fp_a, HistoryStore::Saved, 0, Bytes(), {fp_a, fp_b}, HistoryStore::Active, 1000);
        h.add_message(msg(conv_a, 1, true, 2000, "direct out"));
        h.add_message(msg(id(0x61), 2, true, 2001, "group out"));
        h.add_message(msg(id(0x61), 3, false, 2002, "group in"));
        auto of = [&](uint8_t n) { return h.conversation_of_outgoing(id(n)); };
        CHECK(of(1) && *of(1) == conv_a && of(2) && *of(2) == id(0x61), "an outgoing message is found in its direct or group conversation");
        CHECK(!of(3) && !of(99), "a message we received, or one that doesn't exist, is not");
    }

    std::cout << "Chat archives\n";
    {
        const Bytes conv = id(0x61), other = id(0x62);
        const std::string key_marker = "ARCHIVE-KEY-MARKER-0123456789ABC", priv_marker = "CHAT-PRIVATE-MARKER-0123456789AB", token_marker = "JOIN-TOKEN-MARKER-0123456789ABC";
        HistoryStore::Archive a;
        a.conversation_id = conv;
        a.relay_address = "10.0.0.248:9000";
        a.relay_id = id(0x71, 32);
        a.role = HistoryStore::ArchiveMember;
        a.state = HistoryStore::ArchiveGranted;
        a.archive_key = text(key_marker);
        a.chat_public_key = id(0x33, 50);
        a.chat_private_key = text(priv_marker);
        a.join_token = text(token_marker);
        a.created_at = 1000;
        {
            HistoryStore h(dir / "archive.db", key);
            CHECK(!h.archive(conv) && h.archives().empty(), "there is no archive to begin with");
            CHECK(h.add_archive(a), "an archive is stored");
            auto got = h.archive(conv);
            CHECK(got && got->relay_address == a.relay_address && got->relay_id == a.relay_id && got->role == HistoryStore::ArchiveMember && got->state == HistoryStore::ArchiveGranted &&
                      got->archive_key == a.archive_key && got->chat_public_key == a.chat_public_key && got->chat_private_key == a.chat_private_key && got->join_token == a.join_token &&
                      got->head_number == 0 && got->head_hash.empty() && got->created_at == 1000,
                  "it is read back exactly: address, relay identity, keys, token and state");
            HistoryStore::Archive changed = a;
            changed.relay_address = "evil:1";
            changed.archive_key = text("A DIFFERENT KEY..................");
            CHECK(!h.add_archive(changed) && h.archive(conv)->relay_address == a.relay_address && h.archive(conv)->archive_key == a.archive_key, "a second archive for the same chat is refused and changes nothing (a replayed grant)");
            HistoryStore::Archive second = a;
            second.conversation_id = other;
            second.created_at = 2000;
            second.state = HistoryStore::ArchiveJoined;
            h.add_archive(second);
            auto all = h.archives();
            CHECK(all.size() == 2 && all[0].conversation_id == conv && all[1].conversation_id == other, "archives are listed oldest first");
            auto waiting = h.archives_in_state(HistoryStore::ArchiveGranted);
            CHECK(waiting.size() == 1 && waiting[0].conversation_id == conv && h.archives_in_state(HistoryStore::ArchiveJoined).size() == 1 && h.archives_in_state(HistoryStore::ArchiveFailed).empty(), "those waiting to join can be found");

            h.set_archive_joined(conv);
            auto joined = h.archive(conv);
            CHECK(joined && joined->state == HistoryStore::ArchiveJoined && joined->join_token.empty() && joined->archive_key == a.archive_key, "joining marks it joined and forgets the one-time token");
            h.set_archive_failed(other, "registration closed");
            auto failed = h.archive(other);
            CHECK(failed && failed->state == HistoryStore::ArchiveFailed && failed->note == "registration closed" && failed->join_token.empty(), "a refusal marks it failed, with the reason");

            h.set_archive_head(conv, 5, id(0x55, 32));
            CHECK(h.archive(conv)->head_number == 5 && h.archive(conv)->head_hash == id(0x55, 32), "the checked head moves forward");
            h.set_archive_head(conv, 3, id(0x33, 32));
            h.set_archive_head(conv, 5, id(0x56, 32));
            CHECK(h.archive(conv)->head_number == 5 && h.archive(conv)->head_hash == id(0x55, 32), "but never backwards, and not sideways");
            h.set_archive_head(conv, 9, id(0x59, 32));
            CHECK(h.archive(conv)->head_number == 9, "(and on again)");
        }
        CHECK(!file_contains(dir / "archive.db", key_marker) && !file_contains(fs::path((dir / "archive.db").string() + "-wal"), key_marker) &&
                  !file_contains(dir / "archive.db", priv_marker) && !file_contains(fs::path((dir / "archive.db").string() + "-wal"), priv_marker) &&
                  !file_contains(dir / "archive.db", token_marker) && !file_contains(fs::path((dir / "archive.db").string() + "-wal"), token_marker),
              "the archive key, this device's private key and the join token are not readable on disk");
        HistoryStore wrong(dir / "archive.db", CryptoEngine::random_bytes(32));
        CHECK(!wrong.archive(conv) && wrong.archives().empty(), "with a different key none of it can be read (and nothing crashes)");
        HistoryStore again(dir / "archive.db", key);
        CHECK(again.archive(conv) && again.archive(conv)->head_number == 9 && again.archive(conv)->archive_key == a.archive_key && again.archives().size() == 2, "archives survive a restart");
    }

    std::cout << "Archive upkeep: checkpoints, warnings and the checked chain\n";
    {
        const Bytes conv = id(0x61), other = id(0x62);
        HistoryStore::Archive a;
        a.conversation_id = conv;
        a.relay_address = "10.0.0.248:9000";
        a.relay_id = id(0x71, 32);
        a.archive_key = id(0x11, 32);
        a.chat_public_key = id(0x33, 50);
        a.chat_private_key = id(0x44, 80);
        a.created_at = 1000;
        HistoryStore h(dir / "upkeep.db", key);
        h.ensure_conversation(conv_a, fp_a, 1000);
        CHECK(!h.has_archive(conv) && h.archive_ids(HistoryStore::ArchiveGranted).empty(), "no archive yet");
        h.add_archive(a);
        a.conversation_id = other;
        a.state = HistoryStore::ArchiveJoined;
        a.created_at = 2000;
        h.add_archive(a);
        CHECK(h.has_archive(conv) && h.has_archive(other) && !h.has_archive(id(0x99)), "it can be asked cheaply whether a chat has one");
        auto granted = h.archive_ids(HistoryStore::ArchiveGranted), joined = h.archive_ids(HistoryStore::ArchiveJoined);
        CHECK(granted.size() == 1 && granted[0] == conv && joined.size() == 1 && joined[0] == other && h.archive_ids(HistoryStore::ArchiveFailed).empty(), "and which chats are in which state, without opening any secrets");

        auto fresh = h.archive(conv);
        CHECK(fresh && fresh->checkpoint_at == 0 && fresh->activity == 0 && fresh->checkpoint_seen == 0 && fresh->warning.empty(), "a new archive has no activity, checkpoint or warning");
        h.add_archive_activity(conv, 3);
        h.add_archive_activity(conv, 4);
        CHECK(h.archive(conv)->activity == 7, "activity since the last checkpoint adds up");
        h.note_checkpoint_posted(conv, 5000);
        CHECK(h.archive(conv)->activity == 0 && h.archive(conv)->checkpoint_at == 5000, "adding a checkpoint resets it and records when");
        h.note_checkpoint_seen(conv, 40);
        h.note_checkpoint_seen(conv, 25);
        CHECK(h.archive(conv)->checkpoint_seen == 40, "the latest entry a checkpoint has vouched for only moves forward");
        h.set_archive_warning(conv, "the relay's copy changed");
        CHECK(h.archive(conv)->warning == "the relay's copy changed" && h.archive(other)->warning.empty(), "a warning is kept for that chat only");
        h.set_archive_warning(conv, "");
        CHECK(h.archive(conv)->warning.empty(), "and can be cleared");

        CHECK(!h.archive_hash(conv, 1), "no chain hashes are held to begin with");
        h.save_archive_hashes(conv, {{1, id(0xA1, 32)}, {2, id(0xA2, 32)}, {3, id(0xA3, 32)}});
        h.save_archive_hashes(conv, {{3, id(0xEE, 32)}, {4, id(0xA4, 32)}});
        CHECK(h.archive_hash(conv, 2) == id(0xA2, 32) && h.archive_hash(conv, 4) == id(0xA4, 32) && !h.archive_hash(conv, 5) && !h.archive_hash(other, 2),
              "the hash of each checked entry is kept, per chat");
        CHECK(h.archive_hash(conv, 3) == id(0xA3, 32), "an entry's hash is never replaced by a later claim");

        CHECK(!h.first_message(conv_a), "a conversation with nothing in it has no first message");
        h.add_message(msg(conv_a, 1, true, 3000, "the first one"));
        h.add_message(msg(conv_a, 2, false, 3001, "the second one"));
        auto first = h.first_message(conv_a);
        CHECK(first && first->record == text("the first one") && first->message_id == id(1), "the first message stored is found");
    }

    std::cout << "Member tokens, for the keyring\n";
    {
        HistoryStore h(dir / "membertokens.db", key);
        CHECK(h.all_member_tokens().empty(), "there are none to begin with");
        h.save_member_token(id(0x62), fp_b, id(0x11, 32), 100);
        h.save_member_token(id(0x61), fp_a, id(0x22, 32), 101);
        h.save_member_token(id(0x61), fp_b, id(0x33, 32), 102);
        auto all = h.all_member_tokens();
        CHECK(all.size() == 3 && all[0].conversation_id == id(0x61) && all[0].member_fp == fp_a && all[0].token == id(0x22, 32) && all[1].member_fp == fp_b && all[1].token == id(0x33, 32) &&
                  all[2].conversation_id == id(0x62) && all[2].token == id(0x11, 32),
              "every token comes back with its chat and member, in a fixed order");
        h.save_member_token(id(0x61), fp_a, id(0x44, 32), 200);
        CHECK(h.all_member_tokens().size() == 3 && h.all_member_tokens()[0].token == id(0x44, 32), "a token saved again replaces the old one");
        HistoryStore wrong(dir / "membertokens.db", CryptoEngine::random_bytes(32));
        CHECK(wrong.all_member_tokens().empty(), "with a different key none can be opened, and nothing crashes");
    }

    std::cout << "Deleting by agreement\n";
    {
        HistoryStore h(dir / "deleting.db", key);
        const Bytes conv = id(0x61), op = id(0x71, 16), op2 = id(0x72, 16);
        h.ensure_conversation(conv_a, fp_a, 1000);
        HistoryStore::Deletion d;
        d.op_id = op; d.conversation_id = conv; d.scope = 2; d.expires_at = 9000; d.requester_fp = fp_a; d.entries = {id(0xA1, 32), id(0xA2, 32)}; d.state = HistoryStore::DeletionPending; d.created_at = 1000;
        CHECK(!h.deletion(op) && h.deletions().empty(), "there are no deletions to begin with");
        CHECK(h.add_deletion(d), "a deletion request is stored");
        auto got = h.deletion(op);
        CHECK(got && got->conversation_id == conv && got->scope == 2 && got->expires_at == 9000 && got->requester_fp == fp_a && got->entries == d.entries && got->state == HistoryStore::DeletionPending && got->created_at == 1000, "with its scope, expiry, requester and entries, exactly");
        HistoryStore::Deletion other = d;
        other.scope = 1; other.entries.clear(); other.expires_at = 1;
        CHECK(!h.add_deletion(other) && h.deletion(op)->scope == 2 && h.deletion(op)->expires_at == 9000, "the same operation again (a replay) is refused and changes nothing");
        d.op_id = op2; d.scope = 1; d.entries.clear(); d.created_at = 2000;
        h.add_deletion(d);
        auto all = h.deletions();
        CHECK(all.size() == 2 && all[0].op_id == op2 && all[0].entries.empty() && all[1].op_id == op, "they are listed newest first");
        h.set_deletion_state(op, HistoryStore::DeletionAccepted);
        CHECK(h.deletion(op)->state == HistoryStore::DeletionAccepted && h.deletion(op2)->state == HistoryStore::DeletionPending, "a request's state changes on its own");
        CHECK(h.deletion_accepts(op).empty(), "no acceptances yet");
        h.add_deletion_accept(op, id(0xB1, 32), id(0x11, 100), fp_a);
        h.add_deletion_accept(op, id(0xB2, 32), id(0x22, 100), fp_b);
        h.add_deletion_accept(op, id(0xB1, 32), id(0x99, 100), fp_a);
        auto accepts = h.deletion_accepts(op);
        CHECK(accepts.size() == 2 && accepts[0].key_hash == id(0xB1, 32) && accepts[0].signature == id(0x11, 100) && accepts[1].member_fp == fp_b && h.deletion_accepts(op2).empty(),
              "acceptances are kept per request, one per key, and a second from the same key changes nothing");
        { HistoryStore again(dir / "deleting.db", key); CHECK(again.deletion(op) && again.deletion_accepts(op).size() == 2, "all of it survives a restart"); }

        h.add_message(msg(conv_a, 1, true, 3000, "keep me"));
        h.add_message(msg(conv_a, 2, false, 3001, "remove me"));
        h.add_message(msg(conv_a, 3, false, 3002, "and me"));
        auto before = h.messages(conv_a, 10);
        CHECK(before.size() == 3 && !before[1].deleted && before[1].record == text("remove me"), "(three messages)");
        CHECK(h.erase_message(conv_a, id(2)) && !h.erase_message(conv_a, id(2)) && !h.erase_message(conv_a, id(99)), "a message can be erased once; erasing it again, or one that isn't there, reports that");
        auto after = h.messages(conv_a, 10);
        CHECK(after.size() == 3 && after[1].deleted && after[1].record.empty() && after[1].message_id == id(2) && after[1].sent_at == 3001 && !after[0].deleted && after[0].record == text("keep me") && !after[2].deleted,
              "it keeps its place, its time and its ID, but its content is gone; the others are untouched");
        CHECK(!file_contains(dir / "deleting.db", "remove me") && !file_contains(fs::path((dir / "deleting.db").string() + "-wal"), "remove me"), "and its text is not recoverable from the file");
        CHECK(h.has_entry(conv_a, before[1].entry_hash), "its hash is still known, so chain checks and gap detection carry on");
        h.erase_conversation_messages(conv_a);
        CHECK(h.messages(conv_a, 10).empty() && h.conversation(conv_a), "erasing a whole conversation removes its messages but not the conversation");

        const Bytes archive = id(0x81);
        CHECK(!h.archive_message_number(archive, id(5)) && h.archive_messages_at(archive, 7).empty() && !h.archive_redacted(archive, 7), "nothing is mapped to begin with");
        h.save_archive_message(archive, id(5), 7);
        h.save_archive_message(archive, id(6), 7);
        h.save_archive_message(archive, id(5), 99);
        CHECK(h.archive_message_number(archive, id(5)) == 7u && h.archive_messages_at(archive, 7).size() == 2 && h.archive_messages_at(archive, 8).empty(), "a message is mapped to its entry, and an entry to its messages, and a repeat changes nothing");
        h.save_archive_hashes(archive, {{7, id(0xA7, 32)}});
        CHECK(h.archive_number_of(archive, id(0xA7, 32)) == 7u && !h.archive_number_of(archive, id(0xEE, 32)), "an entry can be found again from its hash");
        h.mark_archive_redacted(archive, 7);
        CHECK(h.archive_redacted(archive, 7) && !h.archive_redacted(archive, 8), "entries seen redacted are remembered");
        HistoryStore::Archive ar;
        ar.conversation_id = archive; ar.relay_address = "10.0.0.248:9000"; ar.relay_id = id(0x71, 32); ar.archive_key = id(0x11, 32); ar.chat_public_key = id(0x33, 50); ar.chat_private_key = id(0x44, 80); ar.created_at = 1;
        h.add_archive(ar);
        h.remove_archive(archive);
        CHECK(!h.has_archive(archive) && !h.archive_message_number(archive, id(5)) && !h.archive_hash(archive, 7) && !h.archive_redacted(archive, 7), "forgetting a chat's archive removes its keys, its checked chain and its message map");
    }

    std::cout << "Contacts that have had prekeys\n";
    {
        HistoryStore h(dir / "peer-prekeys.db", key);
        CHECK(!h.peer_had_prekeys(fp_a), "nobody has had prekeys to begin with");
        h.note_peer_prekeys(fp_a, 100);
        h.note_peer_prekeys(fp_a, 200);
        CHECK(h.peer_had_prekeys(fp_a) && !h.peer_had_prekeys(fp_b), "a contact sealed to once is remembered, and only that one");
        HistoryStore again(dir / "peer-prekeys.db", key);
        CHECK(again.peer_had_prekeys(fp_a), "and it survives a restart");
    }

    std::cout << "The prekey store\n";
    {
        const fs::path vp = dir / "vault.db";
        const Bytes vkey = id(0x33, 32), gen1 = id(0x41, 16), gen2 = id(0x42, 16);
        auto identity = CryptoEngine::generate_sig_keypair();
        auto g1 = prekey::generate(identity.private_key, false, 100), g2 = prekey::generate(identity.private_key, false, 100), lr = prekey::generate(identity.private_key, true, 100);
        {
            PrekeyVault v(vp, vkey);
            CHECK(v.generation().empty() && v.counts().one_time == 0 && !v.current_last_resort_created(), "a new store is empty, with no generation");
            v.start_generation(gen1);
            v.add(g1, 100);
            v.add(g2, 100);
            v.add(lr, 100);
            auto c = v.counts();
            CHECK(v.generation() == gen1 && c.one_time == 2 && c.last_resort == 1 && c.pending == 3, "it holds two one-time prekeys and a last-resort one, all waiting to be uploaded");
            auto up = v.not_uploaded();
            bool all_verify = up.size() == 3 && up.back().last_resort;
            for (const auto& p : up) all_verify &= prekey::verify(p, identity.public_key);
            CHECK(all_verify, "it hands back their signed public halves for uploading (the last-resort one last)");
            auto found = v.find(g1.prekey.id);
            CHECK(found && found->kem_private == g1.secret.kem_private && found->x25519_private == g1.secret.x25519_private, "a private half is found by the prekey's ID");
            for (const auto& p : up) v.mark_uploaded(p.id);
            CHECK(v.counts().pending == 0 && v.not_uploaded().empty() && v.current_last_resort_created() == std::optional<int64_t>(100), "once uploaded, nothing is waiting, and the current last-resort one is known");
        }
        // Secure deletion: the sealed private half's bytes are nowhere in the file afterwards.
        Bytes sealed;
        {
            sqlite3* raw = nullptr;
            sqlite3_open_v2(vp.string().c_str(), &raw, SQLITE_OPEN_READWRITE, nullptr);
            sqlite3_stmt* st = nullptr;
            sqlite3_prepare_v2(raw, "SELECT sealed FROM prekeys WHERE id = ?", -1, &st, nullptr);
            sqlite3_bind_blob(st, 1, g1.prekey.id.data(), static_cast<int>(g1.prekey.id.size()), SQLITE_TRANSIENT);
            if (sqlite3_step(st) == SQLITE_ROW) {
                const auto* b = static_cast<const uint8_t*>(sqlite3_column_blob(st, 0));
                sealed.assign(b, b + sqlite3_column_bytes(st, 0));
            }
            sqlite3_finalize(st);
            sqlite3_close(raw);
        }
        const std::string slice(sealed.begin() + 100, sealed.begin() + std::min<size_t>(sealed.size(), 164));
        CHECK(sealed.size() > 2000 && file_contains(vp, slice) && !file_contains(vp, std::string(g1.secret.kem_private.begin(), g1.secret.kem_private.begin() + 64)),
              "(the private half is on disk only sealed: its own bytes are not in the file)");
        {
            PrekeyVault v(vp, vkey);
            CHECK(v.erase(g1.prekey.id) && !v.find(g1.prekey.id) && !v.erase(g1.prekey.id), "a used prekey is deleted, once");
        }
        CHECK(!file_contains(vp, slice) && !file_contains(fs::path(vp.string() + "-journal"), slice) && !file_contains(fs::path(vp.string() + "-wal"), slice),
              "and its sealed bytes are gone from the file: overwritten, not just unlinked (and no journal keeps a copy)");
        {
            PrekeyVault wrong(vp, id(0x34, 32));
            CHECK(!wrong.find(g2.prekey.id), "with a different key, nothing can be read from the store");
        }
        {
            PrekeyVault v(vp, vkey);
            CHECK(v.find(g2.prekey.id) && v.generation() == gen1, "the rest survives being reopened");
            auto lr2 = prekey::generate(identity.private_key, true, 200);
            v.add(lr2, 200);
            v.mark_uploaded(lr2.prekey.id);
            v.retire_last_resort_except(lr2.prekey.id, 200);
            auto c = v.counts();
            CHECK(c.last_resort == 1 && c.retired == 1 && v.current_last_resort_created() == std::optional<int64_t>(200) && v.find(lr.prekey.id), "a new last-resort prekey retires the old one, which is kept for envelopes on their way");
            CHECK(v.forget_old(300, 50) == 1 && !v.find(lr.prekey.id) && v.find(g2.prekey.id), "a retired one past its time is forgotten; a one-time one isn't, until it is old enough");
            CHECK(v.forget_old(0, 150) == 1 && !v.find(g2.prekey.id), "an unused one-time prekey older than any envelope could be is forgotten");
            v.add(g1, 300);
            v.start_generation(gen2);
            CHECK(v.generation() == gen2 && v.counts().one_time == 0 && v.counts().last_resort == 0 && !v.find(g1.prekey.id), "starting a new generation forgets every prekey");
        }
        const fs::path damaged = dir / "damaged-vault.db";
        { std::ofstream f(damaged, std::ios::binary); f << std::string(5000, 'x'); }
        {
            PrekeyVault v(damaged, vkey);
            CHECK(v.generation().empty() && v.counts().one_time == 0, "a damaged store is started afresh (the app then replaces the pool on the relay)");
        }
    }

    std::cout << "Attachments\n";
    {
        const std::string key_marker = "FILE-KEY-MARKER-0123456789ABCDEF", token_marker = "DOWNLOAD-TOKEN-MARKER-0123456789A";
        HistoryStore::Attachment in;
        in.file_id = id(0xF1, 16); in.conversation_id = id(0x61); in.message_id = id(0x62); in.outgoing = false;
        in.name = "holiday photo.jpg"; in.size = 123456; in.sha256 = id(0x55, 32); in.expires_at = 9000;
        in.relay_address = "10.0.0.248:9000"; in.relay_id = id(0x71, 32); in.state = HistoryStore::AttachAvailable;
        in.key = text(key_marker); in.token = text(token_marker); in.created_at = 1000;
        HistoryStore::Attachment out = in;
        out.file_id = id(0xF2, 16); out.outgoing = true; out.state = HistoryStore::AttachUploading; out.key = id(0x11, 32); out.token.clear();
        out.recipient_tokens = {{fp_a, id(0x21, 32)}, {fp_b, id(0x22, 32)}};
        out.path = "/home/me/holiday photo.jpg"; out.recipients = 2;
        {
            HistoryStore h(dir / "attachments.db", key);
            CHECK(!h.attachment(in.file_id) && h.attachments_in_state(HistoryStore::AttachAvailable).empty(), "there are no attachments to begin with");
            CHECK(h.add_attachment(in) && h.add_attachment(out), "an incoming and an outgoing attachment are stored");
            auto got = h.attachment(in.file_id);
            CHECK(got && got->conversation_id == in.conversation_id && got->message_id == in.message_id && !got->outgoing && got->name == in.name && got->size == 123456 && got->sha256 == in.sha256 && got->expires_at == 9000 &&
                      got->relay_address == in.relay_address && got->relay_id == in.relay_id && got->state == HistoryStore::AttachAvailable && got->key == in.key && got->token == in.token && got->recipient_tokens.empty(),
                  "an incoming one comes back exactly, with its key and token");
            auto sent = h.attachment(out.file_id);
            CHECK(sent && sent->outgoing && sent->key == out.key && sent->recipient_tokens.size() == 2 && sent->recipient_tokens[0].first == fp_a && sent->recipient_tokens[1].second == id(0x22, 32) && sent->path == out.path && sent->recipients == 2 && sent->redeemed == 0,
                  "an outgoing one comes back with each recipient's own token, the file's path and the recipient count");
            HistoryStore::Attachment other = in;
            other.name = "replaced.bin"; other.key = text("A DIFFERENT KEY......................");
            CHECK(!h.add_attachment(other) && h.attachment(in.file_id)->name == in.name && h.attachment(in.file_id)->key == in.key, "the same file again (a replay) is refused and changes nothing");
            CHECK(h.attachments_in_state(HistoryStore::AttachAvailable).size() == 1 && h.attachments_in_state(HistoryStore::AttachUploading).size() == 1 && h.attachments_in_state(HistoryStore::AttachExpired).empty(), "they can be listed by state");

            h.set_attachment_state(in.file_id, HistoryStore::AttachDownloading, "");
            CHECK(h.attachment(in.file_id)->state == HistoryStore::AttachDownloading, "a state changes on its own");
            h.reset_downloading();
            CHECK(h.attachment(in.file_id)->state == HistoryStore::AttachAvailable && h.attachment(out.file_id)->state == HistoryStore::AttachUploading, "after a restart nothing is 'downloading' any more, and nothing else is touched");
            h.set_attachment_state(in.file_id, HistoryStore::AttachFailed, "the file changed after it was attached");
            CHECK(h.attachment(in.file_id)->note == "the file changed after it was attached", "a reason is kept with it");
            h.set_attachment_path(in.file_id, "/home/me/Downloads/holiday photo.jpg");
            h.set_attachment_redeemed(out.file_id, 1);
            CHECK(h.attachment(in.file_id)->path == "/home/me/Downloads/holiday photo.jpg" && h.attachment(out.file_id)->redeemed == 1, "where it was saved, and how many have fetched it, are kept");
            h.drop_attachment_secrets(out.file_id);
            auto dropped = h.attachment(out.file_id);
            CHECK(dropped && dropped->key.empty() && dropped->recipient_tokens.empty() && dropped->name == out.name && dropped->recipients == 2, "once every recipient has been told, the sender's copy of the key and tokens is forgotten");
        }
        {   // An attachment that arrived first without its key (from an archive) gets it when the envelope turns up.
            HistoryStore h(dir / "attachments.db", key);
            HistoryStore::Attachment early = in;
            early.file_id = id(0xF3, 16); early.key.clear(); early.token.clear(); early.state = HistoryStore::AttachUnavailable;
            h.add_attachment(early);
            CHECK(h.attachment(early.file_id)->key.empty() && h.attachment(early.file_id)->state == HistoryStore::AttachUnavailable, "(one that arrived without a key)");
            h.grant_attachment(early.file_id, id(0x81, 32), id(0x82, 32), HistoryStore::AttachAvailable, "");
            auto upgraded = h.attachment(early.file_id);
            CHECK(upgraded && upgraded->key == id(0x81, 32) && upgraded->token == id(0x82, 32) && upgraded->state == HistoryStore::AttachAvailable, "the key and token that come later are kept, and it can be fetched");
            h.grant_attachment(early.file_id, id(0x91, 32), id(0x92, 32), HistoryStore::AttachAvailable, "");
            CHECK(h.attachment(early.file_id)->key == id(0x81, 32), "but a later grant never replaces a key it already has");
            h.grant_attachment(out.file_id, id(0x91, 32), id(0x92, 32), HistoryStore::AttachAvailable, "");
            CHECK(h.attachment(out.file_id)->key.empty() && h.attachment(out.file_id)->outgoing, "and one we sent is never touched by it");
        }
        CHECK(!file_contains(dir / "attachments.db", key_marker) && !file_contains(fs::path((dir / "attachments.db").string() + "-wal"), key_marker) &&
                  !file_contains(dir / "attachments.db", token_marker) && !file_contains(fs::path((dir / "attachments.db").string() + "-wal"), token_marker),
              "the file key and download token are not readable on disk");
        HistoryStore wrong(dir / "attachments.db", CryptoEngine::random_bytes(32));
        auto unreadable = wrong.attachment(in.file_id);
        CHECK(unreadable && unreadable->key.empty() && unreadable->token.empty() && unreadable->name == in.name, "with a different key the secrets can't be opened (and nothing crashes), though what the chat shows is still there");
        HistoryStore again(dir / "attachments.db", key);
        CHECK(again.attachment(in.file_id) && again.attachment(in.file_id)->key == in.key && again.attachment(in.file_id)->path == "/home/me/Downloads/holiday photo.jpg", "attachments survive a restart");
    }

    std::cout << "Upgrading a version 6 history\n";
    {
        fs::path v6 = dir / "v6.db";
        const Bytes conv = id(0x61);
        {
            HistoryStore h(v6, key);
            HistoryStore::Archive a;
            a.conversation_id = conv;
            a.relay_address = "10.0.0.248:9000";
            a.relay_id = id(0x71, 32);
            a.role = HistoryStore::ArchiveCreator;
            a.state = HistoryStore::ArchiveJoined;
            a.archive_key = id(0x11, 32);
            a.chat_public_key = id(0x33, 50);
            a.chat_private_key = id(0x44, 80);
            a.created_at = 1234;
            h.add_archive(a);
            h.set_archive_head(conv, 9, id(0x99, 32));
        }
        // Make it what version 6 left: the archive table without its four newer columns, and no chain table.
        raw_exec(v6, "CREATE TABLE archives_old AS SELECT conv_id, relay_address, relay_id, role, state, archive_key, chat_public, chat_private, join_token, head_number, head_hash, created_at, note FROM archives;"
                     "DROP TABLE archives; ALTER TABLE archives_old RENAME TO archives; DROP TABLE archive_chain; PRAGMA user_version=6;");
        CHECK(raw_int(v6, "PRAGMA user_version") == 6 && raw_int(v6, "SELECT COUNT(*) FROM pragma_table_info('archives') WHERE name = 'warning'") == 0, "(setup) the fixture really is a version 6 database");
        {
            HistoryStore h(v6, key);
            CHECK(raw_int(v6, "PRAGMA user_version") == 10, "opening it upgrades it to the current version (10)");
            auto a = h.archive(conv);
            CHECK(a && a->relay_address == "10.0.0.248:9000" && a->role == HistoryStore::ArchiveCreator && a->state == HistoryStore::ArchiveJoined && a->archive_key == id(0x11, 32) &&
                      a->head_number == 9 && a->head_hash == id(0x99, 32) && a->created_at == 1234,
                  "the archive it held is untouched");
            CHECK(a && a->checkpoint_at == 0 && a->activity == 0 && a->checkpoint_seen == 0 && a->warning.empty(), "the new columns start empty");
            h.add_archive_activity(conv, 2);
            h.save_archive_hashes(conv, {{1, id(0xA1, 32)}});
            CHECK(h.archive(conv)->activity == 2 && h.archive_hash(conv, 1) == id(0xA1, 32), "and work straight away");
        }
        CHECK(!fs::exists(fs::path(v6.string() + ".before-v2")), "adding columns needs no backup of the old file");
        { HistoryStore again(v6, key); CHECK(again.archive(conv) && again.archive(conv)->activity == 2, "opening it again is harmless"); }
    }

    std::cout << "People the user has verified\n";
    {
        HistoryStore h(dir / "verified.db", key);
        const std::string fp_c = fp_of('c');
        CHECK(!h.is_verified(fp_a) && h.verified_people().empty(), "nobody is verified to begin with");
        h.set_verified(fp_b, true, 100);
        h.set_verified(fp_a, true, 200);
        h.set_verified(fp_b, true, 300);
        CHECK(h.is_verified(fp_a) && h.is_verified(fp_b) && !h.is_verified(fp_c), "people are marked verified one by one");
        auto all = h.verified_people();
        CHECK(all.size() == 2 && all[0] == fp_b && all[1] == fp_a, "marking someone again changes nothing, and they are listed in the order verified");
        h.set_verified(fp_b, false, 400);
        CHECK(!h.is_verified(fp_b) && h.is_verified(fp_a), "it can be taken back");
        h.set_verified(fp_c, false, 500);
        CHECK(!h.is_verified(fp_c) && h.verified_people().size() == 1, "taking it back from someone not verified is harmless");
    }

    std::cout << "Send tokens other group members gave us\n";
    {
        HistoryStore h(dir / "tokens.db", key);
        const std::string fp_c = fp_of('c');
        Bytes g1 = id(0x61), g2 = id(0x62);
        const std::string secret = "TOKEN-SECRET-MARKER-0123456789AB";  // 32 bytes
        CHECK(!h.member_token(g1, fp_b), "there is none to begin with");
        h.save_member_token(g1, fp_b, text(secret), 100);
        auto t = h.member_token(g1, fp_b);
        CHECK(t && *t == text(secret), "a token is stored and read back");
        CHECK(!h.member_token(g2, fp_b) && !h.member_token(g1, fp_c), "it is good for that group and that member only");
        h.save_member_token(g1, fp_b, id(0x55, 32), 200);
        CHECK(h.member_token(g1, fp_b) && *h.member_token(g1, fp_b) == id(0x55, 32), "saving again for the same group and member replaces it");
        h.save_member_token(g1, fp_c, text(secret), 300);
        CHECK(!file_contains(dir / "tokens.db", secret) && !file_contains(fs::path((dir / "tokens.db").string() + "-wal"), secret), "a token is a secret: it is not readable on disk");
        HistoryStore other(dir / "tokens.db", CryptoEngine::random_bytes(32));
        CHECK(!other.member_token(g1, fp_c), "with a different key it can't be read (and nothing crashes)");
    }

    std::cout << "Groups and delivery survive a restart\n";
    {
        {
            HistoryStore h(dir / "persist.db", key);
            h.create_group(id(0x61), "Kept", fp_a, HistoryStore::Saved, 0, Bytes(), {fp_a, fp_b}, HistoryStore::SettingUp, 100);
            h.add_message(msg(id(0x61), 1, true, 200, "hi", HistoryStore::Queued));
            h.raise_delivery(id(0x61), id(1), fp_a, HistoryStore::Delivered);
        }
        HistoryStore h(dir / "persist.db", key);
        auto g = h.conversation(id(0x61));
        auto d = h.deliveries(id(0x61), id(1));
        CHECK(g && g->title == "Kept" && g->state == HistoryStore::SettingUp && g->members == (std::vector<std::string>{fp_a, fp_b}), "a group is still there with its members and state");
        CHECK(d.size() == 2 && d[0].status == HistoryStore::Delivered && d[1].status == 0 && h.find_message(id(0x61), id(1))->status == 0, "per-member delivery is kept, and the message still waits for the second member");
    }

    fs::remove_all(dir);
    std::cout << (failures ? "\nFAILURES: " : "\nAll checks passed. ") << failures << "\n";
    return failures ? 1 : 0;
}
