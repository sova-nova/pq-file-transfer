// Tests for the encrypted local history store.
#include "crypto_engine.h"
#include "history_store.h"

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
            CHECK(raw_int(v1, "PRAGMA user_version") == 2, "opening it upgrades it to version 2");
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
            CHECK(again.messages(conv_a, 100).size() == 4 && raw_int(v1, "PRAGMA user_version") == 2, "opening it again changes nothing");
        }
        CHECK(backup_size > 0 && size_of(fs::path(v1.string() + ".before-v2")) == backup_size, "...and the saved old copy is not overwritten");

        fs::path fresh = dir / "fresh.db";
        { HistoryStore f(fresh, key); }
        CHECK(raw_int(fresh, "PRAGMA user_version") == 2 && !fs::exists(fs::path(fresh.string() + ".before-v2")), "a brand-new history starts at version 2, with nothing to back up");

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
