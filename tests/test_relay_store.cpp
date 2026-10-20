// Tests for the relay's SQLite store, with a controlled clock (no waiting for expiry).
#include "relay_store.h"

#include <sqlite3.h>

#include <atomic>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>
#include <unistd.h>

using relay::Bytes;
using relay::RelayStore;
namespace fs = std::filesystem;

static int failures = 0;
#define CHECK(c, msg)                                                  \
    do {                                                               \
        if (c) std::cout << "  PASS " << (msg) << "\n";                \
        else { std::cout << "  FAIL " << (msg) << "\n"; failures++; } \
    } while (0)

template <typename F> static bool throws(F f) { try { f(); } catch (const std::exception&) { return true; } return false; }

static Bytes id(uint8_t n, size_t len = 16) { return Bytes(len, n); }
static Bytes envelope(size_t size, uint8_t fill = 7) { return Bytes(size, fill); }

static const size_t MAX_MAILBOXES = 100;

static RelayStore::RegisterResult reg(RelayStore& s, uint8_t invite, uint8_t mailbox, int64_t now, uint8_t token = 0xAA) {
    return s.register_mailbox(id(invite, 32), id(mailbox), id(0x55, 64), id(token, 32), now, MAX_MAILBOXES);
}

int main() {
    fs::path dir = fs::temp_directory_path() / ("pqft-store-" + std::to_string(getpid()));
    fs::remove_all(dir);
    fs::create_directories(dir);
    fs::path db = dir / "relay.db";
    using R = RelayStore::RegisterResult;

    std::cout << "Invites and registration\n";
    {
        RelayStore s(db);
        s.add_invite(id(1, 32), 2000);
        s.add_invite(id(2, 32), 2000);
        s.add_invite(id(3, 32), 500);

        CHECK(reg(s, 9, 1, 1000) == R::BadInvite, "an unknown invite is refused");
        CHECK(reg(s, 3, 1, 1000) == R::BadInvite, "an expired invite is refused");
        CHECK(reg(s, 1, 1, 1000) == R::Ok, "a valid invite creates the mailbox");
        CHECK(reg(s, 1, 2, 1000) == R::BadInvite, "an invite works only once");
        CHECK(reg(s, 2, 1, 1000) == R::MailboxExists, "a taken mailbox ID is refused");
        CHECK(reg(s, 2, 2, 1000) == R::Ok, "...and that failed attempt did not burn the invite");
        CHECK(s.mailbox_count() == 2, "two mailboxes exist");
        CHECK(s.access_key(id(1)) == id(0x55, 64) && !s.access_key(id(99)), "the access key is stored; unknown mailboxes have none");

        s.add_invite(id(4, 32), 2000);
        CHECK(s.register_mailbox(id(4, 32), id(3), id(0x55, 64), id(0xAA, 32), 1000, 2) == R::LimitReached, "the mailbox limit is enforced");
        CHECK(s.register_mailbox(id(4, 32), id(3), id(0x55, 64), id(0xAA, 32), 1000, 10) == R::Ok, "...without burning the invite");
    }

    std::cout << "Send tokens\n";
    {
        RelayStore s(db);
        CHECK(s.token_valid(id(1), id(0xAA, 32)), "the first token from registration is valid");
        CHECK(!s.token_valid(id(2), id(0xBB, 32)) && !s.token_valid(id(1), id(0xBB, 32)), "an unknown token is not valid");
        CHECK(!s.token_valid(id(99), id(0xAA, 32)), "an unknown mailbox has no valid tokens");

        CHECK(s.add_token(id(1), id(0xBB, 32), 1000, 3) == RelayStore::TokenResult::Ok && s.token_valid(id(1), id(0xBB, 32)), "a second token can be added");
        CHECK(s.add_token(id(1), id(0xBB, 32), 1000, 3) == RelayStore::TokenResult::Ok, "adding the same token twice is harmless");
        CHECK(!s.token_valid(id(2), id(0xBB, 32)), "a token works only for its own mailbox");
        CHECK(s.add_token(id(1), id(0xCC, 32), 1000, 3) == RelayStore::TokenResult::Ok, "a third token fits");
        CHECK(s.add_token(id(1), id(0xDD, 32), 1000, 3) == RelayStore::TokenResult::LimitReached, "the per-mailbox token limit is enforced");
        CHECK(s.add_token(id(99), id(0xDD, 32), 1000, 3) == RelayStore::TokenResult::NoSuchMailbox, "tokens can't be added to a missing mailbox");
        CHECK(s.revoke_token(id(1), id(0xBB, 32)) && !s.token_valid(id(1), id(0xBB, 32)), "a revoked token stops working");
        CHECK(s.token_valid(id(1), id(0xAA, 32)), "...while the others keep working");
        CHECK(!s.revoke_token(id(1), id(0xBB, 32)), "revoking a token that is already gone does nothing");
        CHECK(!s.revoke_token(id(2), id(0xCC, 32)) && s.token_valid(id(1), id(0xCC, 32)), "revoking through the wrong mailbox does nothing to the right one");
    }

    std::cout << "Envelopes, ordering and expiry\n";
    {
        RelayStore s(db);
        using D = RelayStore::DepositResult;
        CHECK(s.deposit(id(1), id(0x11), envelope(100, 1), id(0x7A, 32), 1000, 10, 1 << 20) == D::Ok, "deposit one");
        CHECK(s.deposit(id(1), id(0x12), envelope(100, 2), id(0x7A, 32), 1001, 100, 1 << 20) == D::Ok, "deposit two");
        CHECK(s.deposit(id(1), id(0x13), envelope(100, 3), id(0x7A, 32), 1002, 100, 1 << 20) == D::Ok, "deposit three");
        CHECK(s.deposit(id(2), id(0x21), envelope(50, 9), id(0x7A, 32), 1002, 100, 1 << 20) == D::Ok, "deposit to another mailbox");

        auto all = s.fetch(id(1), 0, 1005, 100);
        CHECK(all.size() == 3 && all[0].id == id(0x11) && all[1].id == id(0x12) && all[2].id == id(0x13), "envelopes come back oldest first");
        CHECK(all.size() == 3 && all[0].envelope == envelope(100, 1) && all[0].deposited_at == 1000, "contents and deposit time are intact");
        CHECK(s.fetch(id(2), 0, 1005, 100).size() == 1, "each mailbox sees only its own envelopes");
        auto page = s.fetch(id(1), all[0].seq, 1005, 100);
        CHECK(page.size() == 2 && page[0].id == id(0x12), "paging continues after a given sequence number");
        CHECK(s.fetch(id(1), 0, 1005, 2).size() == 2, "the limit is honoured");

        CHECK(s.fetch(id(1), 0, 1009, 100).size() == 3, "just before its expiry an envelope is still delivered");
        auto expired = s.fetch(id(1), 0, 1010, 100);
        CHECK(expired.size() == 2 && expired[0].id == id(0x12), "an expired envelope is not delivered even before it is swept");
        CHECK(s.envelope_count(id(1)) == 3, "...though it still occupies storage");
        auto swept = s.sweep(1010);
        CHECK(swept.envelopes == 1 && s.envelope_count(id(1)) == 2, "sweeping removes exactly the expired envelope");
        CHECK(s.sweep(1010).envelopes == 0, "sweeping twice is harmless");
        CHECK(s.sweep(100000).envelopes == 3, "everything older than its TTL goes eventually");
    }

    std::cout << "Quota\n";
    {
        RelayStore s(db);
        using D = RelayStore::DepositResult;
        CHECK(s.deposit(id(1), id(0x31), envelope(400), id(0x7A, 32), 5000, 100, 1000) == D::Ok, "400 of 1000 bytes");
        CHECK(s.deposit(id(1), id(0x32), envelope(400), id(0x7A, 32), 5000, 100, 1000) == D::Ok, "800 of 1000 bytes");
        CHECK(s.deposit(id(1), id(0x33), envelope(400), id(0x7A, 32), 5000, 100, 1000) == D::MailboxFull, "a deposit that would exceed the quota is refused");
        CHECK(s.envelope_count(id(1)) == 2, "...and nothing was stored");
        CHECK(s.deposit(id(2), id(0x34), envelope(400), id(0x7A, 32), 5000, 100, 1000) == D::Ok, "another mailbox has its own quota");
        CHECK(s.deposit(id(1), id(0x35), envelope(400), id(0x7A, 32), 5101, 100, 1000) == D::Ok, "expired envelopes no longer count toward the quota");
        s.sweep(100000);
    }

    std::cout << "Acknowledging\n";
    {
        RelayStore s(db);
        s.deposit(id(1), id(0x41), envelope(10), id(0x7A, 32), 7000, 1000, 1 << 20);
        s.deposit(id(1), id(0x42), envelope(10), id(0x7A, 32), 7000, 1000, 1 << 20);
        s.deposit(id(2), id(0x43), envelope(10), id(0x7A, 32), 7000, 1000, 1 << 20);
        CHECK(s.ack(id(2), {id(0x41), id(0x42)}) == 0 && s.envelope_count(id(1)) == 2, "another mailbox can't acknowledge (delete) my envelopes");
        CHECK(s.ack(id(1), {id(0x41), id(0x77)}) == 1 && s.envelope_count(id(1)) == 1, "acknowledging deletes only the named envelopes that exist");
        CHECK(s.ack(id(1), {id(0x41)}) == 0, "acknowledging twice deletes nothing more");
        CHECK(s.ack(id(1), {}) == 0, "an empty acknowledgement is fine");
    }

    std::cout << "Persistence, hostile input and concurrency\n";
    {
        { RelayStore s(db); s.deposit(id(1), id(0x51), envelope(10, 5), id(0x7A, 32), 8000, 1000, 1 << 20); }
        RelayStore reopened(db);
        auto got = reopened.fetch(id(1), 0, 8001, 100);
        bool found = false;
        for (auto& e : got) if (e.id == id(0x51) && e.envelope == envelope(10, 5)) found = true;
        CHECK(found && reopened.access_key(id(1)).has_value(), "envelopes and mailboxes survive closing and reopening the database");

        CHECK(throws([&] { reopened.deposit(id(77), id(0x52), envelope(10), id(0x7A, 32), 8000, 1000, 1 << 20); }), "depositing to a mailbox that doesn't exist is an error, not corruption");
        CHECK(reopened.deposit(id(1), id(0x53), Bytes(), id(0x7A, 32), 8000, 1000, 1 << 20) == RelayStore::DepositResult::Ok, "an empty envelope is stored as empty, not NULL");
        CHECK(throws([&] { reopened.deposit(id(1), id(0x53), envelope(5), id(0x7A, 32), 8000, 1000, 1 << 20); }), "a duplicate envelope ID is refused");
        CHECK(!reopened.token_valid(Bytes(), Bytes()) && !reopened.access_key(Bytes()), "empty IDs just don't match anything");

        std::atomic<int> errors{0};
        std::vector<std::thread> threads;
        for (int t = 0; t < 4; t++)
            threads.emplace_back([&, t] {
                for (int i = 0; i < 50; i++) {
                    try {
                        Bytes eid(16, 0);
                        eid[0] = 0xE0; eid[1] = static_cast<uint8_t>(t); eid[2] = static_cast<uint8_t>(i);
                        reopened.deposit(id(2), eid, envelope(10), id(0x7A, 32), 9000, 1000, 1 << 24);
                    } catch (...) { errors++; }
                }
            });
        for (auto& th : threads) th.join();
        CHECK(errors == 0 && reopened.envelope_count(id(2)) >= 200, "four threads depositing at once all succeed");
    }

    std::cout << "Token hashes and schema migration\n";
    {
        RelayStore s(db);
        s.deposit(id(1), id(0x61), envelope(10, 1), id(0x7B, 32), 9500, 1000, 1 << 20);
        auto got = s.fetch(id(1), 0, 9501, 100);
        bool found = false;
        for (auto& e : got) if (e.id == id(0x61) && e.token_hash == id(0x7B, 32)) found = true;
        CHECK(found, "the send token's hash is stored with the envelope and returned to the owner");
    }
    {
        // A database exactly as the first release created it: no token_hash column, version 1.
        fs::path old_db = dir / "old.db";
        sqlite3* raw = nullptr;
        sqlite3_open_v2(old_db.string().c_str(), &raw, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
        const char* old_schema =
            "CREATE TABLE invites(hash BLOB PRIMARY KEY, expires_at INTEGER NOT NULL);"
            "CREATE TABLE mailboxes(id BLOB PRIMARY KEY, access_public_key BLOB NOT NULL, created_at INTEGER NOT NULL);"
            "CREATE TABLE tokens(mailbox_id BLOB NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE, hash BLOB NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY(mailbox_id, hash));"
            "CREATE TABLE envelopes(seq INTEGER PRIMARY KEY AUTOINCREMENT, id BLOB NOT NULL UNIQUE, mailbox_id BLOB NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE, size INTEGER NOT NULL, envelope BLOB NOT NULL, deposited_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);"
            "CREATE INDEX envelopes_by_mailbox ON envelopes(mailbox_id, seq);"
            "CREATE INDEX envelopes_by_expiry ON envelopes(expires_at);"
            "INSERT INTO mailboxes VALUES(x'01010101010101010101010101010101', x'AA', 100);"
            "INSERT INTO envelopes(id, mailbox_id, size, envelope, deposited_at, expires_at) "
            "  VALUES(x'0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A', x'01010101010101010101010101010101', 3, x'010203', 9000, 99999999);"
            "PRAGMA user_version=1;";
        sqlite3_exec(raw, old_schema, nullptr, nullptr, nullptr);
        sqlite3_close(raw);

        RelayStore migrated(old_db);
        Bytes box(16, 1);
        auto old = migrated.fetch(box, 0, 10000, 10);
        CHECK(old.size() == 1 && old[0].envelope == Bytes({1, 2, 3}) && old[0].token_hash == Bytes(32, 0),
              "an envelope stored by the first release is still delivered, with an all-zero token hash");
        CHECK(migrated.deposit(box, id(0x62), envelope(5, 4), id(0x7C, 32), 10000, 1000, 1 << 20) == RelayStore::DepositResult::Ok,
              "and new deposits work on the migrated database");
        auto both = migrated.fetch(box, 0, 10001, 10);
        CHECK(both.size() == 2 && both[1].token_hash == id(0x7C, 32), "old and new envelopes sit side by side");
        { RelayStore again(old_db); CHECK(again.fetch(box, 0, 10001, 10).size() == 2, "opening a migrated database again is harmless"); }

        sqlite3* check = nullptr;
        sqlite3_open_v2(old_db.string().c_str(), &check, SQLITE_OPEN_READWRITE, nullptr);
        sqlite3_stmt* st = nullptr;
        sqlite3_prepare_v2(check, "PRAGMA user_version", -1, &st, nullptr);
        sqlite3_step(st);
        long long version = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
        sqlite3_close(check);
        CHECK(version == 4, "the schema version is now 4");
        auto ms = migrated.members();
        CHECK(ms.size() == 1 && ms[0].invited_by.empty() && ms[0].envelopes == 2, "a mailbox from the first release shows as an operator invite, with its queued envelopes");
        CHECK(migrated.add_member_invite(box, id(0x71, 32), 10000, 20000, 2, 3) == RelayStore::IssueResult::Ok, "and it can vouch for a friend straight away");
    }

    std::cout << "Members vouching for friends\n";
    {
        // The current release's database: token hashes, but nobody has been recorded as vouching yet.
        fs::path v2_db = dir / "v2.db";
        sqlite3* raw = nullptr;
        sqlite3_open_v2(v2_db.string().c_str(), &raw, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
        using R = RelayStore::RegisterResult;
        const std::string v2_schema =
            "CREATE TABLE invites(hash BLOB PRIMARY KEY, expires_at INTEGER NOT NULL);"
            "CREATE TABLE mailboxes(id BLOB PRIMARY KEY, access_public_key BLOB NOT NULL, created_at INTEGER NOT NULL);"
            "CREATE TABLE tokens(mailbox_id BLOB NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE, hash BLOB NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY(mailbox_id, hash));"
            "CREATE TABLE envelopes(seq INTEGER PRIMARY KEY AUTOINCREMENT, id BLOB NOT NULL UNIQUE, mailbox_id BLOB NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE, size INTEGER NOT NULL, envelope BLOB NOT NULL, deposited_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, token_hash BLOB);"
            "CREATE INDEX envelopes_by_mailbox ON envelopes(mailbox_id, seq);"
            "CREATE INDEX envelopes_by_expiry ON envelopes(expires_at);"
            "INSERT INTO mailboxes VALUES(x'01010101010101010101010101010101', x'AA', 100);"
            "INSERT INTO invites VALUES(x'" + std::string(64, 'E') + "', 99999999);"
            "PRAGMA user_version=2;";
        sqlite3_exec(raw, v2_schema.c_str(), nullptr, nullptr, nullptr);
        sqlite3_close(raw);

        RelayStore s(v2_db);
        auto old_members = s.members();
        CHECK(old_members.size() == 1 && old_members[0].invited_by.empty(), "a version 2 database opens, its mailbox shown as an operator invite");
        CHECK(s.create_archive(id(0x31), {id(0xA1, 32)}, id(0x47, 32), 1000, 5000, 10) == RelayStore::CreateArchiveResult::Ok && s.archive_count() == 1, "and it can hold chat archives straight away");
        CHECK(s.register_mailbox(Bytes(32, 0xEE), id(2), id(0x55, 64), id(0xAA, 32), 1000, 10) == R::Ok, "an invite the operator made before the upgrade still works");

        Bytes box1(16, 1), box2 = id(2);
        CHECK(s.add_member_invite(id(99), id(0x81, 32), 1000, 5000, 2, 3) == RelayStore::IssueResult::NoSuchMailbox, "only an existing mailbox can make invites");
        CHECK(s.add_member_invite(box1, id(0x81, 32), 1000, 5000, 2, 3) == RelayStore::IssueResult::Ok, "a mailbox makes an invite");
        CHECK(s.add_member_invite(box1, id(0x82, 32), 1000, 5000, 2, 3) == RelayStore::IssueResult::Ok, "and a second");
        CHECK(s.add_member_invite(box1, id(0x83, 32), 1000, 5000, 2, 3) == RelayStore::IssueResult::TooManyOutstanding, "but not a third unused one");
        CHECK(s.add_member_invite(box1, id(0x83, 32), 5001, 9000, 2, 3) == RelayStore::IssueResult::Ok, "unused invites that have expired stop counting");
        CHECK(s.register_mailbox(id(0x83, 32), id(3), id(0x55, 64), id(0xAA, 32), 5002, 10) == R::Ok, "the friend registers with the third");
        auto after = s.members();
        Bytes invited;
        for (auto& m : after) if (m.id == id(3)) invited = m.invited_by;
        CHECK(invited == box1, "the new mailbox is recorded as invited by the one who made the invite");
        CHECK(s.add_member_invite(box1, id(0x84, 32), 5003, 9000, 5, 1) == RelayStore::IssueResult::TooManyIssued, "the lifetime limit counts people already invited");
        CHECK(s.add_member_invite(box2, id(0x85, 32), 5003, 9000, 5, 1) == RelayStore::IssueResult::Ok, "(each mailbox has its own allowance)");

        s.deposit(id(3), id(0x61), envelope(5), id(0x7C, 32), 5100, 1000, 1 << 20);
        CHECK(s.delete_mailbox(id(3)) && !s.access_key(id(3)) && s.envelope_count(id(3)) == 0 && !s.token_valid(id(3), id(0xAA, 32)),
              "removing a mailbox takes its keys, tokens and queued envelopes with it");
        CHECK(s.delete_mailbox(box1) && s.add_member_invite(box2, id(0x86, 32), 5200, 9000, 5, 5) == RelayStore::IssueResult::Ok, "removing a mailbox also removes the unused invites it made (and others are unaffected)");
        CHECK(s.register_mailbox(id(0x82, 32), id(4), id(0x55, 64), id(0xAA, 32), 5300, 10) == R::BadInvite, "...so an invitation it left behind no longer works");
        CHECK(!s.delete_mailbox(id(77)), "removing a mailbox that doesn't exist reports that");

        // Looking at one's own invites, and cancelling one. A fresh mailbox, so nothing else is counted.
        s.add_invite(id(0xA1, 32), 99999);
        CHECK(s.register_mailbox(id(0xA1, 32), id(20), id(0x55, 64), id(0xAA, 32), 6000, 30) == R::Ok, "(setup) a new mailbox");
        Bytes lister = id(20);
        CHECK(s.add_member_invite(lister, id(0x91, 32), 6000, 9500, 5, 9) == RelayStore::IssueResult::Ok && s.add_member_invite(lister, id(0x92, 32), 6000, 9000, 5, 9) == RelayStore::IssueResult::Ok &&
                  s.add_member_invite(lister, id(0x93, 32), 6000, 6001, 5, 9) == RelayStore::IssueResult::Ok, "(setup) it makes three invites, one about to expire");
        auto unused = s.unused_invites(lister, 6000);
        CHECK(unused.size() == 3 && unused[0].hash == id(0x93, 32) && unused[1].hash == id(0x92, 32) && unused[2].expires_at == 9500, "its unused invites are listed soonest to expire first");
        CHECK(s.unused_invites(lister, 6002).size() == 2, "an expired one is no longer listed");
        CHECK(!s.cancel_member_invite(id(88), id(0x92, 32)) && s.unused_invites(lister, 6002).size() == 2, "someone else cannot cancel it");
        CHECK(s.cancel_member_invite(lister, id(0x92, 32)) && s.unused_invites(lister, 6002).size() == 1, "its owner can");
        CHECK(!s.cancel_member_invite(lister, id(0x92, 32)) && !s.cancel_member_invite(lister, id(0xFE, 32)), "cancelling twice, or something that never existed, reports that");
        CHECK(s.register_mailbox(id(0x92, 32), id(9), id(0x55, 64), id(0xAA, 32), 6003, 30) == R::BadInvite, "a cancelled invite can't be used");
        CHECK(s.register_mailbox(id(0x91, 32), id(10), id(0x55, 64), id(0xAA, 32), 6004, 30) == R::Ok, "(another one still can)");
        auto joined = s.joined_through(lister);
        CHECK(joined.size() == 1 && joined[0].mailbox_id == id(10) && joined[0].joined_at == 6004 && s.joined_through(id(88)).empty(), "the people who used a member's invites are listed with when they joined");

    }


    std::cout << "Chat archives\n";
    {
        RelayStore s(dir / "archives.db");
        using C = RelayStore::CreateArchiveResult;
        using J = RelayStore::JoinResult;
        using A = RelayStore::AppendResult;
        const Bytes arch = id(0x31), genesis = id(0x47, 32), k1 = id(0xB1, 32), k2 = id(0xB2, 32), k3 = id(0xB3, 32);
        const std::vector<Bytes> tokens = {id(0xA1, 32), id(0xA2, 32), id(0xA3, 32)};

        CHECK(s.create_archive(arch, tokens, genesis, 1000, 5000, 2) == C::Ok, "an archive is created for three members");
        CHECK(s.create_archive(arch, tokens, genesis, 1000, 5000, 2) == C::Exists, "creating one with the same ID is refused");
        CHECK(s.create_archive(id(0x32), tokens, genesis, 1000, 5000, 2) == C::Ok && s.create_archive(id(0x33), tokens, genesis, 1000, 5000, 2) == C::LimitReached && s.archive_count() == 2,
              "the relay-wide limit on archives is enforced");
        auto info = s.archive_info(arch, 1000);
        CHECK(info && info->member_count == 3 && info->joined == 0 && info->registration_open && info->head.number == 0 && info->head.hash == genesis && info->bytes == 0, "a new archive is empty, at its genesis, open for members to join");
        CHECK(!s.archive_info(id(0x99), 1000), "an unknown archive has no info");

        CHECK(s.join_archive(arch, id(0xEE, 32), k1, id(1, 50), 1001) == J::BadToken && s.join_archive(id(0x99), tokens[0], k1, id(1, 50), 1001) == J::NoSuchArchive, "a wrong token, or an unknown archive, is refused");
        CHECK(s.join_archive(arch, tokens[0], k1, id(1, 50), 1001) == J::Ok, "a member joins with their token");
        CHECK(s.join_archive(arch, tokens[0], k2, id(2, 50), 1001) == J::BadToken, "a token works once");
        CHECK(s.join_archive(arch, tokens[1], k1, id(1, 50), 1001) == J::KeyExists, "a key can't be registered twice...");
        CHECK(s.join_archive(arch, tokens[1], k2, id(2, 50), 1002) == J::Ok, "...and that refused attempt did not spend the token");
        CHECK(s.archive_member_key(arch, k1) == id(1, 50) && s.archive_member_key(arch, k2) == id(2, 50) && !s.archive_member_key(arch, k3) && !s.archive_member_key(id(0x32), k1), "registered keys are found, others and other archives' are not");
        CHECK(s.join_archive(arch, tokens[2], k3, id(3, 50), 1003) == J::Ok, "the third joins");
        info = s.archive_info(arch, 1003);
        CHECK(info && info->joined == 3 && !info->registration_open, "registration closes once everyone has joined");
        CHECK(s.join_archive(arch, id(0xA9, 32), id(0xB9, 32), id(9, 50), 1004) == J::BadToken, "and there is no token left to join with");

        const Bytes late = id(0x34);
        s.create_archive(late, {id(0xA1, 32), id(0xA2, 32)}, genesis, 1000, 2000, 10);
        CHECK(s.join_archive(late, id(0xA1, 32), k1, id(1, 50), 1999) == J::Ok && s.join_archive(late, id(0xA2, 32), k2, id(2, 50), 2000) == J::Closed, "after the registration window, nobody else can join");
        CHECK(!s.archive_info(late, 2000)->registration_open, "(and it is reported closed)");

        // Appending: compare and swap on the head.
        Bytes h1 = id(0xC1, 32), h2 = id(0xC2, 32), h3 = id(0xC3, 32);
        RelayStore::ArchiveState head;
        CHECK(s.append_entry(arch, 0, genesis, h1, envelope(100, 1), 1100, 1 << 20, &head) == A::Ok && head.number == 1 && head.hash == h1, "the first entry extends the genesis");
        CHECK(s.append_entry(arch, 0, genesis, id(0xCC, 32), envelope(100, 9), 1101, 1 << 20, &head) == A::Stale && head.number == 1 && head.hash == h1,
              "a second sender who also extended the genesis is told the head moved, and where it is");
        CHECK(s.append_entry(arch, 1, id(0xDD, 32), id(0xCC, 32), envelope(100, 9), 1102, 1 << 20, &head) == A::Stale, "naming the right number but the wrong hash is stale too");
        CHECK(s.append_entry(arch, 1, h1, h2, envelope(50, 2), 1103, 1 << 20, &head) == A::Ok && head.number == 2 && head.hash == h2, "extending the real head works");
        CHECK(s.append_entry(id(0x99), 0, genesis, h1, envelope(10), 1104, 1 << 20, &head) == A::NoSuchArchive, "an unknown archive refuses appends");
        info = s.archive_info(arch, 1200);
        CHECK(info && info->head.number == 2 && info->head.hash == h2 && info->bytes == 150, "the head and the byte count follow the appends");
        CHECK(s.append_entry(arch, 2, h2, h3, envelope(100, 3), 1105, 200, &head) == A::ArchiveFull && head.number == 2, "an archive over its quota refuses more, and says nothing changed");
        CHECK(s.archive_info(arch, 1200)->head.number == 2, "(the refused entry was not stored)");

        auto all = s.fetch_entries(arch, 1, 10);
        CHECK(all.size() == 2 && all[0].number == 1 && all[0].hash == h1 && all[0].ciphertext == envelope(100, 1) && all[1].number == 2 && all[1].hash == h2, "entries come back in order with their hashes");
        auto tail = s.fetch_entries(arch, 2, 10);
        CHECK(tail.size() == 1 && tail[0].number == 2 && s.fetch_entries(arch, 3, 10).empty() && s.fetch_entries(arch, 1, 1).size() == 1 && s.fetch_entries(id(0x99), 1, 10).empty(),
              "fetching from a number onwards, with a limit, from an unknown archive, or past the end");

        // Nothing ties an archive to a mailbox or a person.
        sqlite3* raw = nullptr;
        sqlite3_open_v2((dir / "archives.db").string().c_str(), &raw, SQLITE_OPEN_READWRITE, nullptr);
        std::string columns;
        for (const char* table : {"archives", "archive_join_tokens", "archive_keys", "archive_entries"}) {
            sqlite3_stmt* st = nullptr;
            std::string sql = std::string("SELECT name FROM pragma_table_info('") + table + "')";
            sqlite3_prepare_v2(raw, sql.c_str(), -1, &st, nullptr);
            while (sqlite3_step(st) == SQLITE_ROW) columns += std::string(static_cast<const char*>(sqlite3_column_blob(st, 0)), static_cast<size_t>(sqlite3_column_bytes(st, 0))) + " ";
            sqlite3_finalize(st);
        }
        sqlite3_close(raw);
        CHECK(columns.find("mailbox") == std::string::npos && columns.find("creator") == std::string::npos, "the relay stores nothing that links an archive to a mailbox");

        // Archives nobody joined are cleaned up; ones with members are kept.
        s.create_archive(id(0x35), {id(0xA1, 32)}, genesis, 1000, 3000, 10);
        auto swept = s.sweep(2500);
        CHECK(swept.archives == 0 && s.archive_info(id(0x35), 2500), "an archive still inside its registration window is kept");
        swept = s.sweep(3001);
        CHECK(swept.archives >= 1 && !s.archive_info(id(0x35), 3001), "one nobody joined by the end of the window is removed");
        CHECK(s.archive_info(arch, 3001) && s.fetch_entries(arch, 1, 10).size() == 2, "while one with members keeps all its entries");
        { RelayStore reopened(dir / "archives.db"); CHECK(reopened.archive_info(arch, 3001) && reopened.archive_info(arch, 3001)->head.hash == h2, "archives survive a restart"); }
    }

    fs::remove_all(dir);
    std::cout << (failures ? "\nFAILURES: " : "\nAll checks passed. ") << failures << "\n";
    return failures ? 1 : 0;
}
