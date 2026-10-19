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

    fs::remove_all(dir);
    std::cout << (failures ? "\nFAILURES: " : "\nAll checks passed. ") << failures << "\n";
    return failures ? 1 : 0;
}
