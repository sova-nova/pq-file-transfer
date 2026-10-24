// Integration tests for one-to-one Saved chats: real relay process, real MessagingEngines.
// POSIX only. Usage: test_chat /path/to/pq-server
#include "crypto_engine.h"
#include "envelope.h"
#include "messaging_engine.h"
#include "prekey.h"
#include "prekey_vault.h"
#include "envelope.h"
#include <sqlite3.h>
#include "message_record.h"
#include "protocol.h"
#include "relay_client.h"
#include "sharing.h"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <thread>

#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

namespace fs = std::filesystem;
using Bytes = std::vector<uint8_t>;

static int failures = 0;
#define CHECK(c, msg)                                                  \
    do {                                                               \
        if (c) std::cout << "  PASS " << (msg) << "\n";                \
        else { std::cout << "  FAIL " << (msg) << "\n"; failures++; } \
    } while (0)

static bool has(const std::string& s, const char* needle) { return s.find(needle) != std::string::npos; }
static void sleep_ms(int ms) { std::this_thread::sleep_for(std::chrono::milliseconds(ms)); }

static std::string SERVER_BIN;
static fs::path ROOT;

// --- The relay under test ---

struct Server {
    int port = 0;
    fs::path storage;
    pid_t pid = -1;

    bool start() {
        pid = fork();
        if (pid == 0) {
            int log = open((storage.parent_path() / "relay.log").c_str(), O_WRONLY | O_CREAT | O_APPEND, 0600);
            if (log >= 0) { dup2(log, 1); dup2(log, 2); }
            std::string p = std::to_string(port), s = storage.string();
            execl(SERVER_BIN.c_str(), SERVER_BIN.c_str(), "--port", p.c_str(), "--bind", "127.0.0.1", "--storage", s.c_str(),
                  "--sweep-seconds", "1", "--rate-limit", "100000", "--prekey-takes-per-hour", "100000", static_cast<char*>(nullptr));
            _exit(127);
        }
        for (int i = 0; i < 100; i++) {
            RelayClient probe;
            std::string err;
            if (probe.connect("127.0.0.1", static_cast<uint16_t>(port), {}, 2, err)) return true;
            sleep_ms(50);
        }
        return false;
    }
    void stop() { if (pid > 0) { kill(pid, SIGTERM); waitpid(pid, nullptr, 0); pid = -1; } }
    std::optional<RelayInvite> invite() {
        std::string cmd = "\"" + SERVER_BIN + "\" --storage \"" + storage.string() + "\" --create-invite --public-address 127.0.0.1:" + std::to_string(port) + " 2>&1";
        FILE* p = popen(cmd.c_str(), "r");
        if (!p) return std::nullopt;
        std::string out; char buf[512];
        while (fgets(buf, sizeof(buf), p)) out += buf;
        pclose(p);
        size_t at = out.find("pqft-relay://");
        return at == std::string::npos ? std::nullopt : parse_relay_invite(out.substr(at, out.find('\n', at) - at));
    }
    ~Server() { stop(); }
};

// --- People ---

static MessagingEngine::Options test_options() {
    MessagingEngine::Options o;
    o.prekey_check_seconds = 1;           // tests don't wait a minute for the pool
    o.last_resort_rotate_seconds = 5;     // nor a week for a new last-resort prekey
    o.receipt_delay_max_seconds = 0;
    o.reconnect_min_seconds = 1;
    o.reconnect_max_seconds = 2;
    o.connect_timeout_seconds = 3;
    o.retry_base_seconds = 1;
    o.archive_check_seconds = 3600;  // these tests are about plain messaging: chat archives are tested in test_group
    return o;
}

struct User {
    std::string name;
    fs::path home;
    std::unique_ptr<KeyStore> keys;
    std::unique_ptr<MessagingEngine> engine;
    std::string fp;
    fs::path history() const { return home / "history.db"; }
};

static std::map<std::string, std::unique_ptr<User>> users;
static void as(const User& u) { setenv("HOME", u.home.c_str(), 1); }

static User& make_user(const std::string& name, bool with_engine = true) {
    auto u = std::make_unique<User>();
    u->name = name;
    u->home = ROOT / name;
    fs::create_directories(u->home);
    setenv("HOME", u->home.c_str(), 1);
    u->keys = std::make_unique<KeyStore>();
    u->keys->initialize_keys();
    u->fp = u->keys->own_fingerprint();
    if (with_engine) {
        u->engine = std::make_unique<MessagingEngine>(*u->keys, u->history(), test_options());
        u->engine->set_display_name(name);
    }
    User& ref = *u;
    users[name] = std::move(u);
    return ref;
}

static void restart_engine(User& u) {
    u.engine.reset();
    as(u);
    u.engine = std::make_unique<MessagingEngine>(*u.keys, u.history(), test_options());
    u.engine->set_display_name(u.name);
}

// Runs every engine until `cond` holds or the time is up.
static bool wait_for(const std::function<bool()>& cond, int timeout_ms = 10000) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (cond()) return true;
        for (auto& [_, u] : users) if (u->engine) u->engine->pump(20);
    }
    return cond();
}

static void run_for(int ms) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    while (std::chrono::steady_clock::now() < deadline)
        for (auto& [_, u] : users) if (u->engine) u->engine->pump(20);
}

static bool setup_user(Server& srv, User& u) {
    auto invite = srv.invite();
    std::string err;
    return invite && u.engine->setup(*invite, err);
}

// Imports a card the way the app does.
static bool import_card(User& owner, const std::string& card, const std::string& name) {
    std::string err;
    auto c = decode_any_contact_card(card, &err);
    if (!c || !c->bundle) return false;
    as(owner);
    owner.keys->save_contact_bundle(name, *c->bundle);
    if (!c->send_token.empty()) owner.keys->save_contact_token(name, c->send_token);
    return true;
}

// Alice makes a card for Bob and Bob imports it.
static std::string introduce(User& issuer, User& receiver, const std::string& name_for_issuer, const std::string& label) {
    std::string card, err;
    if (!issuer.engine->make_card(label, card, err)) { std::cout << "  (make_card failed: " << err << ")\n"; return ""; }
    import_card(receiver, card, name_for_issuer);
    return card;
}

static size_t count_incoming(User& u, const std::string& from_fp) {
    size_t n = 0;
    for (auto& m : u.engine->messages(from_fp)) if (!m.outgoing) n++;
    return n;
}

static int status_of(User& u, const std::string& contact_fp, const std::string& text) {
    for (auto& m : u.engine->messages(contact_fp)) if (m.outgoing && m.text == text) return m.status;
    return -1;
}

static size_t position_of(const std::vector<MessagingEngine::ChatMessage>& v, const std::string& text) {
    for (size_t i = 0; i < v.size(); i++) if (v[i].text == text) return i;
    return std::string::npos;
}

static bool file_contains(const fs::path& p, const std::string& needle) {
    std::ifstream f(p, std::ios::binary);
    std::string data((std::istreambuf_iterator<char>(f)), {});
    return data.find(needle) != std::string::npos;
}

static bool any_notice(User& u, const char* needle, std::vector<std::string>* keep = nullptr) {
    auto n = u.engine->take_notices();
    bool found = false;
    for (auto& line : n) { if (has(line, needle)) found = true; if (keep) keep->push_back(line); }
    return found;
}

int main(int argc, char** argv) {
    if (argc < 2) { std::cerr << "usage: test_chat /path/to/pq-server\n"; return 2; }
    SERVER_BIN = argv[1];
    ROOT = fs::temp_directory_path() / ("pqft-chat-" + std::to_string(getpid()));
    fs::remove_all(ROOT);
    fs::create_directories(ROOT);
    platform_init();

    Server srv{21000 + static_cast<int>(getpid() % 5000), ROOT / "relay-data/s"};
    fs::create_directories(srv.storage.parent_path());
    if (!srv.start()) { std::cout << "FAIL could not start the relay\n"; return 1; }
    auto first_invite = srv.invite();
    Bytes relay_id = first_invite->relay_id;

    User& alice = make_user("alice");
    User& bob = make_user("bob");

    std::cout << "1. Setting up messaging\n";
    {
        std::string err, card;
        CHECK(!alice.engine->is_set_up() && !alice.engine->make_card("x", card, err) && has(err, "Set up"), "before setup there is nothing to make a card with");
        CHECK(!alice.engine->send_text(bob.fp, "hi", err), "...and nothing to send with: " + err);

        RelayInvite wrong = *first_invite;
        wrong.relay_id[0] ^= 1;
        CHECK(!alice.engine->setup(wrong, err) && has(err, "does not match") && !alice.engine->is_set_up(), "an invite naming a different relay key is refused: " + err);
        CHECK(alice.engine->setup(*first_invite, err) && alice.engine->is_set_up(), "setting up with a good invite works (" + err + ")");
        auto cfg = alice.keys->load_mailbox_config();
        CHECK(cfg && cfg->relay_id == relay_id && cfg->mailbox_id.size() == 16 && alice.keys->has_access_key(), "the mailbox and its access key are saved");
        CHECK(!alice.engine->setup(*first_invite, err) && has(err, "already"), "setting up twice is refused: " + err);

        User& zed = make_user("zed");
        CHECK(!zed.engine->setup(*first_invite, err) && !zed.engine->is_set_up() && !zed.keys->load_mailbox_config(), "a used invite fails and leaves nothing half-set-up: " + err);
        users.erase("zed");

        CHECK(setup_user(srv, bob), "Bob sets up too");
    }

    std::cout << "2. Contact cards carry a per-contact send token\n";
    std::string alice_card_for_bob = introduce(alice, bob, "Alice", "for Bob");
    std::string bob_card_for_alice = introduce(bob, alice, "Bob", "for Alice");
    {
        auto c = decode_any_contact_card(alice_card_for_bob);
        CHECK(c && c->bundle && c->bundle->has_mailbox() && c->send_token.size() == 32 && c->bundle->relay_id == relay_id, "the card holds a signed mailbox address and a 32-byte send token");
        auto tokens = alice.engine->issued_tokens();
        CHECK(tokens.size() == 1 && tokens[0].label == "for Bob" && tokens[0].used_by.empty() && !tokens[0].revoked, "Alice's list shows it, unused");
        std::string second, err;
        alice.engine->make_card("for someone else", second, err);
        CHECK(second != alice_card_for_bob && alice.engine->issued_tokens().size() == 2 && decode_any_contact_card(second)->send_token != c->send_token, "every card gets its own token");
        as(bob);
        auto contact = bob.keys->find_contact_by_fingerprint(alice.fp);
        CHECK(contact && contact->can_message(), "Bob can message Alice once he has the card");
        auto summary = bob.engine->chats();
        CHECK(summary.size() == 1 && summary[0].contact_name == "Alice" && summary[0].can_send, "Bob's chat list shows her, ready");
    }

    std::cout << "3. Messages both ways, receipts, ordering\n";
    {
        std::string err;
        CHECK(bob.engine->send_text(alice.fp, "hello Alice", err), "Bob sends");
        CHECK(status_of(bob, alice.fp, "hello Alice") == 0, "it is queued until the engine runs");
        CHECK(wait_for([&] { return count_incoming(alice, bob.fp) == 1; }), "Alice receives it");
        auto m = alice.engine->messages(bob.fp);
        CHECK(m.size() == 1 && m[0].text == "hello Alice" && !m[0].outgoing && !m[0].gap && m[0].status == 0, "intact, from Bob, unread, no gap");
        CHECK(wait_for([&] { return status_of(bob, alice.fp, "hello Alice") >= 2; }), "Bob's copy becomes Delivered once Alice's app has stored it");
        CHECK(alice.engine->chats().size() == 1 && alice.engine->chats()[0].unread == 1, "Alice sees one unread message");

        // The first message introduced Bob to Alice: her token for him came inside it, and her own card already gave him one.
        alice.engine->mark_read(bob.fp);
        CHECK(alice.engine->chats()[0].unread == 0, "reading it clears the unread count");
        CHECK(wait_for([&] { return status_of(bob, alice.fp, "hello Alice") == 3; }), "...and Bob's copy becomes Read");

        CHECK(alice.engine->send_text(bob.fp, "hi Bob, got it", err) && wait_for([&] { return count_incoming(bob, alice.fp) == 1; }), "Alice replies and Bob receives it");

        for (int i = 1; i <= 10; i++) bob.engine->send_text(alice.fp, "burst " + std::to_string(i), err);
        CHECK(wait_for([&] { return count_incoming(alice, bob.fp) == 11; }), "a burst of ten arrives");
        auto all = alice.engine->messages(bob.fp);
        bool ordered = true, no_gaps = true;
        size_t last = 0;
        for (int i = 1; i <= 10; i++) {
            size_t at = position_of(all, "burst " + std::to_string(i));
            if (at == std::string::npos || (i > 1 && at <= last)) ordered = false;
            last = at;
        }
        for (auto& x : all) if (x.gap) no_gaps = false;
        CHECK(ordered && no_gaps, "in order, and the sender's chain of previous-entry hashes shows no gaps");
        alice.engine->mark_read(bob.fp);
        wait_for([&] { return status_of(bob, alice.fp, "burst 10") == 3; });
        CHECK(status_of(bob, alice.fp, "burst 10") == 3, "receipts for the whole burst arrive");

        std::string unicode = "héllo wörld 你好 🙂", big(30 * 1024, 'x');
        bob.engine->send_text(alice.fp, unicode, err);
        bob.engine->send_text(alice.fp, big, err);
        bool both = wait_for([&] { return count_incoming(alice, bob.fp) == 13; });
        auto after = alice.engine->messages(bob.fp);
        CHECK(both && position_of(after, unicode) != std::string::npos && position_of(after, big) != std::string::npos, "Unicode and a 30 KiB message round-trip");
        alice.engine->mark_read(bob.fp);
    }

    std::cout << "4. Offline recipient, restart, nothing readable on disk\n";
    {
        std::string err;
        std::string secret = "UNIQUE-SECRET-MESSAGE-42";
        alice.engine.reset();  // Alice's app is closed
        bob.engine->send_text(alice.fp, secret, err);
        bob.engine->send_text(alice.fp, "while you were out 2", err);
        bob.engine->send_text(alice.fp, "while you were out 3", err);
        CHECK(wait_for([&] { return status_of(bob, alice.fp, secret) == 1; }), "with Alice offline, the relay accepts them (status Sent)");
        restart_engine(alice);
        size_t before = count_incoming(alice, bob.fp);
        CHECK(wait_for([&] { return count_incoming(alice, bob.fp) == before + 3; }), "when Alice's app starts, the three waiting messages arrive");
        auto m = alice.engine->messages(bob.fp);
        CHECK(m[m.size() - 3].text == secret && m[m.size() - 1].text == "while you were out 3", "in order");
        CHECK(!file_contains(alice.history(), secret) && !file_contains(fs::path(alice.history().string() + "-wal"), secret) &&
                  !file_contains(bob.history(), secret) && !file_contains(fs::path(bob.history().string() + "-wal"), secret),
              "neither person's history file contains the text");
        restart_engine(bob);
        run_for(800);
        CHECK(count_incoming(alice, bob.fp) == before + 3 && alice.engine->messages(bob.fp).size() == m.size(), "restarting an app doesn't duplicate anything");
        CHECK(bob.engine->messages(alice.fp).size() >= 15, "history survives a restart");
        alice.engine->mark_read(bob.fp);
    }

    std::cout << "5. Hostile envelopes aimed at Alice\n";
    {
        // The attacker has Bob's token for Alice's mailbox, as anyone holding Bob's card would.
        as(bob);
        auto bobs_view_of_alice = bob.keys->find_contact_by_fingerprint(alice.fp);
        auto alice_cfg = alice.keys->load_mailbox_config();
        auto deposit = [&](const Bytes& envelope) {
            RelayClient c; std::string err;
            return c.connect("127.0.0.1", static_cast<uint16_t>(srv.port), relay_id, 3, err) &&
                   c.deposit(alice_cfg->mailbox_id, bobs_view_of_alice->send_token, envelope, 600, nullptr, err);
        };
        auto bob_dsa = bob.keys->load_private_dsa();
        Bytes bob_fp_raw = *hex_to_bytes(bob.fp), alice_fp_raw = *hex_to_bytes(alice.fp);
        auto record_from_bob = [&](const std::string& text, const Bytes& conv, const Bytes& recipients, const Bytes& own_prev = {}) {
            chat::Record r;
            r.conversation_id = conv; r.message_id = CryptoEngine::random_bytes(16); r.sender = bob_fp_raw; r.recipients_hash = recipients;
            r.sent_at = 1700000000; r.type = chat::RecordType::Text; r.payload.assign(text.begin(), text.end()); r.own_prev = own_prev;
            return chat::sign_record(r, bob_dsa);
        };
        Bytes good_conv = chat::conversation_id_for(bob_fp_raw, alice_fp_raw), good_rh = chat::recipients_hash_for({bob_fp_raw, alice_fp_raw});
        size_t base = count_incoming(alice, bob.fp);

        CHECK(deposit(CryptoEngine::random_bytes(3000)), "(setup) random bytes can be deposited with a valid token");
        CHECK(deposit(chat::seal_envelope({{}, {Bytes(50, 1)}}, alice.keys->load_public_kem())), "(setup) so can a sealed envelope holding nonsense");
        run_for(1000);
        CHECK(count_incoming(alice, bob.fp) == base && alice.engine->requests().empty(), "garbage and malformed records produce nothing");

        // Forged sender: Mallory signs a record claiming to be Bob.
        User& mallory = make_user("mallory", false);
        as(mallory);
        auto mal_dsa = mallory.keys->load_private_dsa();
        chat::Record lie;
        lie.conversation_id = good_conv; lie.message_id = CryptoEngine::random_bytes(16); lie.sender = bob_fp_raw; lie.recipients_hash = good_rh;
        lie.sent_at = 1700000000; lie.type = chat::RecordType::Text; lie.payload = Bytes{'f', 'a', 'k', 'e'};
        deposit(chat::seal_envelope({{}, {chat::sign_record(lie, mal_dsa)}}, alice.keys->load_public_kem()));
        run_for(1000);
        CHECK(count_incoming(alice, bob.fp) == base, "a record claiming to be Bob but signed by Mallory is dropped");

        // Unknown sender without an introduction: dropped. With one: a request, never a chat message.
        chat::Record plain = lie;
        plain.sender = *hex_to_bytes(mallory.fp);
        plain.conversation_id = chat::conversation_id_for(plain.sender, alice_fp_raw);
        plain.recipients_hash = chat::recipients_hash_for({plain.sender, alice_fp_raw});
        plain.payload = Bytes{'h', 'i'};
        Bytes mal_record = chat::sign_record(plain, mal_dsa);
        deposit(chat::seal_envelope({{}, {mal_record}}, alice.keys->load_public_kem()));
        run_for(800);
        CHECK(alice.engine->requests().empty(), "a stranger with no introduction is dropped");
        deposit(chat::seal_envelope({mallory.keys->make_own_bundle("Mallory"), {mal_record}}, alice.keys->load_public_kem()));
        CHECK(wait_for([&] { return alice.engine->requests().size() == 1; }), "with a self-signed introduction it waits as a request");
        auto reqs = alice.engine->requests();
        CHECK(reqs[0].display_name == "Mallory" && reqs[0].first_text == "hi" && alice.engine->chats().size() == 1, "...showing who it says it is, and not appearing among the chats");
        alice.engine->decline_request(mallory.fp);
        CHECK(alice.engine->requests().empty(), "declining removes it");

        // Replay: the same genuine envelope deposited twice.
        Bytes genuine = chat::seal_envelope({{}, {record_from_bob("replay me", good_conv, good_rh)}}, alice.keys->load_public_kem());
        deposit(genuine); deposit(genuine);
        CHECK(wait_for([&] { return count_incoming(alice, bob.fp) == base + 1; }), "a genuine message arrives");
        run_for(800);
        CHECK(count_incoming(alice, bob.fp) == base + 1, "...and exactly once, even though it was deposited twice");

        // Redirected: a record Bob signed for a conversation with someone else.
        Bytes carol_fp = CryptoEngine::random_bytes(32);
        deposit(chat::seal_envelope({{}, {record_from_bob("meant for Carol", chat::conversation_id_for(bob_fp_raw, carol_fp), chat::recipients_hash_for({bob_fp_raw, carol_fp}))}}, alice.keys->load_public_kem()));
        deposit(chat::seal_envelope({{}, {record_from_bob("right conversation, wrong audience", good_conv, chat::recipients_hash_for({bob_fp_raw, carol_fp}))}}, alice.keys->load_public_kem()));
        run_for(1000);
        CHECK(count_incoming(alice, bob.fp) == base + 1, "records signed by Bob but made for a different conversation or audience are dropped");

        // A record pointing at an earlier message that never arrived is shown, flagged.
        deposit(chat::seal_envelope({{}, {record_from_bob("after a missing one", good_conv, good_rh, CryptoEngine::random_bytes(32))}}, alice.keys->load_public_kem()));
        CHECK(wait_for([&] { return count_incoming(alice, bob.fp) == base + 2; }), "a message whose predecessor never arrived is delivered");
        auto msgs = alice.engine->messages(bob.fp);
        bool flagged = false, others_clean = true;
        for (auto& m : msgs) { if (m.text == "after a missing one") flagged = m.gap; else if (m.gap) others_clean = false; }
        CHECK(flagged && others_clean, "...and flagged as following a gap");
        alice.engine->mark_read(bob.fp);
        any_notice(alice, "");
    }

    std::cout << "6. Message requests\n";
    {
        User& dave = make_user("dave");
        std::string err;
        setup_user(srv, dave);
        std::string alice_card_for_dave = introduce(alice, dave, "Alice", "for Dave");
        CHECK(dave.engine->send_text(alice.fp, "Hi Alice, it's Dave", err), "Dave, who has Alice's card, writes to her");
        CHECK(wait_for([&] { return alice.engine->requests().size() == 1; }), "Alice (who doesn't know Dave) gets a message request");
        auto r = alice.engine->requests();
        CHECK(r[0].display_name == "dave" && r[0].message_count == 1 && r[0].first_text == "Hi Alice, it's Dave" && r[0].sender_fp == dave.fp, "it shows his name, his fingerprint and what he said");
        CHECK(alice.engine->chats().size() == 1, "he is not among her chats yet");
        run_for(600);
        CHECK(status_of(dave, alice.fp, "Hi Alice, it's Dave") == 1, "and Dave's copy stays 'sent': no receipt goes out before she decides");

        CHECK(!alice.engine->accept_request(dave.fp, "bad/name", err), "accepting with an invalid name is refused: " + err);
        CHECK(!alice.engine->accept_request(dave.fp, "Bob", err) && has(err, "different contact"), "so is a name another contact already has: " + err);
        CHECK(alice.engine->accept_request(dave.fp, "Dave", err), "she accepts (after checking his fingerprint)");
        auto contact = alice.keys->find_contact_by_fingerprint(dave.fp);
        CHECK(contact && contact->can_message() && contact->kem_verified, "Dave is now a contact she can write back to (address from his bundle, token from his first message)");
        CHECK(alice.engine->requests().empty() && count_incoming(alice, dave.fp) == 1 && alice.engine->messages(dave.fp)[0].text == "Hi Alice, it's Dave", "his message moved into the chat");
        CHECK(wait_for([&] { return status_of(dave, alice.fp, "Hi Alice, it's Dave") >= 2; }), "now the delivery receipt goes back to Dave");
        CHECK(alice.engine->send_text(dave.fp, "Hello Dave!", err) && wait_for([&] { return count_incoming(dave, alice.fp) == 1; }), "Alice's reply reaches him through the token he gave her");

        // A decline leaves nothing behind.
        User& erin = make_user("erin");
        setup_user(srv, erin);
        introduce(alice, erin, "Alice", "for Erin");
        erin.engine->send_text(alice.fp, "hello from Erin", err);
        wait_for([&] { return alice.engine->requests().size() == 1; });
        alice.engine->decline_request(erin.fp);
        run_for(500);
        CHECK(alice.engine->requests().empty() && !alice.keys->find_contact_by_fingerprint(erin.fp) && alice.engine->chats().size() == 2, "declining stores no contact and no message");
    }

    std::cout << "7. A passed-on card is noticed\n";
    {
        // Alice's card for Bob was first used by Bob. Eve gets hold of the same card text and writes to Alice with it.
        any_notice(alice, "");
        User& eve = make_user("eve");
        setup_user(srv, eve);
        import_card(eve, alice_card_for_bob, "Alice");
        std::string err;
        eve.engine->send_text(alice.fp, "I found your card", err);
        std::vector<std::string> seen;
        CHECK(wait_for([&] { return any_notice(alice, "passed on", &seen); }), "Alice is told that the card she made for Bob has been used by someone else");
        bool names_card = false;
        for (auto& l : seen) if (has(l.c_str(), "for Bob")) names_card = true;
        CHECK(names_card, "naming the card it was");
        auto tokens = alice.engine->issued_tokens();
        bool bound_to_bob = false;
        for (auto& t : tokens) if (t.label == "for Bob") bound_to_bob = t.used_by == bob.fp;
        CHECK(bound_to_bob, "the token stays attributed to the first person who used it");
        alice.engine->decline_request(eve.fp);
    }

    std::cout << "8. Revoking a card, and getting back in with a new one\n";
    {
        std::string err;
        // Revoking just the card is not enough: Alice's first message to Bob carried a second token, and Bob uses that one now.
        Bytes card_token;
        for (auto& t : alice.engine->issued_tokens()) if (t.label == "for Bob") card_token = t.hash;
        CHECK(!card_token.empty() && alice.engine->revoke_token(card_token, err), "Alice revokes the card she gave Bob (" + err + ")");
        bob.engine->send_text(alice.fp, "still gets through on the other token", err);
        CHECK(wait_for([&] { return status_of(bob, alice.fp, "still gets through on the other token") >= 1; }), "...but Bob is still writing with the token that came with Alice's first message, so it works");

        int revoked = alice.engine->revoke_tokens_for(bob.fp, err);
        CHECK(revoked >= 1 && revoked != 99, "Alice then revokes everything Bob has (" + std::to_string(revoked) + " more tokens)");
        CHECK(alice.engine->revoke_tokens_for(bob.fp, err) == 0, "doing it again finds nothing left");
        CHECK(bob.engine->send_text(alice.fp, "does this get through?", err), "Bob writes anyway");
        run_for(3500);
        CHECK(status_of(bob, alice.fp, "does this get through?") == 0, "it stays queued: the relay no longer accepts that token");
        std::vector<std::string> n;
        any_notice(bob, "", &n);
        bool told = false;
        for (auto& l : n) if (has(l.c_str(), "no longer works")) told = true;
        CHECK(told, "and Bob is told the card no longer works");
        CHECK(count_incoming(alice, bob.fp) > 0 && alice.engine->messages(bob.fp).back().text != "does this get through?", "nothing was delivered");

        introduce(alice, bob, "Alice", "for Bob, again");
        CHECK(wait_for([&] { return status_of(bob, alice.fp, "does this get through?") >= 1; }, 12000), "after Bob imports a new card, the waiting message goes out by itself");
        CHECK(wait_for([&] { return alice.engine->messages(bob.fp).back().text == "does this get through?"; }), "and Alice receives it");
    }

    std::cout << "9. Receipt settings\n";
    {
        std::string err;
        alice.engine->set_receipts(bob.fp, true, false);
        bool d = false, r = true;
        alice.engine->receipts_enabled(bob.fp, &d, &r);
        CHECK(d && !r, "Alice turns off read receipts for this chat");
        bob.engine->send_text(alice.fp, "do you read receipts?", err);
        CHECK(wait_for([&] { return status_of(bob, alice.fp, "do you read receipts?") == 2; }), "Bob still gets 'delivered'");
        alice.engine->mark_read(bob.fp);
        run_for(1500);
        CHECK(status_of(bob, alice.fp, "do you read receipts?") == 2 && alice.engine->chats()[0].unread == 0, "...but not 'read', while Alice's own unread count still clears");
        alice.engine->set_receipts(bob.fp, false, false);
        bob.engine->send_text(alice.fp, "now neither", err);
        wait_for([&] { return count_incoming(alice, bob.fp) > 0 && alice.engine->messages(bob.fp).back().text == "now neither"; });
        run_for(1500);
        CHECK(status_of(bob, alice.fp, "now neither") == 1, "with delivery receipts off too, Bob only ever sees 'sent'");
        alice.engine->set_receipts(bob.fp, true, true);
    }

    std::cout << "10. The relay goes away and comes back\n";
    {
        std::string err;
        srv.stop();
        wait_for([&] { return !alice.engine->connected(); }, 6000);
        CHECK(!alice.engine->connected() && !alice.engine->status().empty(), "Alice's app notices: " + alice.engine->status().substr(0, 60));
        bob.engine->send_text(alice.fp, "sent into the void", err);
        run_for(1500);
        CHECK(status_of(bob, alice.fp, "sent into the void") == 0, "Bob's message waits in his queue");
        CHECK(srv.start(), "the relay returns");
        CHECK(wait_for([&] { return alice.engine->messages(bob.fp).back().text == "sent into the void"; }, 25000), "both apps reconnect on their own and the message is delivered");
        CHECK(alice.engine->connected(), "Alice shows as connected again");
        alice.engine->mark_read(bob.fp);
    }

    std::cout << "11. Things the app refuses\n";
    {
        std::string err;
        CHECK(!bob.engine->send_text(alice.fp, "", err) && has(err, "nothing"), "an empty message: " + err);
        CHECK(!bob.engine->send_text(alice.fp, std::string(32 * 1024 + 1, 'x'), err) && has(err, "too long"), "an over-long message: " + err);
        CHECK(!bob.engine->send_text(std::string(64, 'f'), "hi", err) && has(err, "isn't in your list"), "a stranger: " + err);

        // A contact from an old card has no mailbox address; one from key files isn't verified.
        as(bob);
        std::string old_card = encode_contact_card_v2(alice.keys->make_own_bundle("OldAlice"));
        auto decoded = decode_any_contact_card(old_card);
        User& ollie = make_user("ollie", false);
        as(bob);
        bob.keys->save_contact_bundle("Ollie", *decode_any_contact_card(encode_contact_card_v2(ollie.keys->make_own_bundle("Ollie")))->bundle);
        CHECK(!bob.engine->send_text(ollie.fp, "hi", err) && has(err, "messaging address"), "a contact from a v2 card has no messaging address: " + err);
        User& file_user = make_user("fiona", false);
        as(bob);
        bob.keys->save_contact("Fiona", file_user.keys->load_public_kem(), file_user.keys->load_public_dsa());
        CHECK(!bob.engine->send_text(file_user.fp, "hi", err) && has(err, "verified"), "a contact added from key files isn't verified: " + err);
        bool explained = false;
        for (auto& c : bob.engine->chats()) if (c.contact_name == "Fiona" || c.contact_name == "Ollie") explained |= !c.can_send && !c.cannot_send_reason.empty();
        CHECK(explained, "the chat list says why, in words");
    }

    std::cout << "11b. One-time prekeys on the relay\n";
    {
        // (Messages in the sections before used some of Alice's prekeys, as they should: the counts here are relative.)
        CHECK(wait_for([&] { auto i = alice.engine->prekey_info(); return i.relay_matches && i.relay_one_time >= 30 && i.relay_last_resort && i.pending_upload == 0; }, 30000),
              "Alice's app keeps a pool of one-time prekeys and a last-resort one on her relay");
        auto before = alice.engine->prekey_info();
        CHECK(before.local_one_time >= before.relay_one_time && before.local_last_resort == 1, "and keeps their private halves");
        auto contact = bob.keys->find_contact_by_fingerprint(alice.fp);
        auto address = contact ? parse_server_address(contact->relay_address) : std::nullopt;
        RelayClient c;
        std::string e;
        const int to_take = static_cast<int>(before.relay_one_time) - 25;  // leave 25: below the point where the app tops up
        int good = 0;
        if (address && c.connect(address->host, address->port, contact->relay_id, 5, e)) {
            for (int i = 0; i < to_take; i++) {
                relay::PrekeyData d;
                if (!c.take_prekey(contact->mailbox_id, contact->send_token, d, e)) break;
                auto p = prekey::decode(d.blob);
                if (p && !d.last_resort && prekey::verify(*p, contact->pub_dsa)) good++;
            }
        }
        CHECK(good == to_take, "Bob takes all but 25 with his send token for Alice's mailbox (" + std::to_string(to_take) + "), and each is signed by Alice's identity key");
        // (The app reports the relay's count as of its last check, so wait for the top-up itself.)
        CHECK(wait_for([&] { auto i = alice.engine->prekey_info(); return i.relay_matches && i.relay_one_time == 100 && i.local_one_time >= before.local_one_time + 75 && i.pending_upload == 0; }, 30000),
              "Alice's app notices her pool is low and tops it back up to 100");
        {
            auto i = alice.engine->prekey_info();
            CHECK(i.local_one_time - i.relay_one_time == (before.local_one_time - before.relay_one_time) + static_cast<size_t>(to_take),
                  "it keeps the private halves of the ones that were taken, for the envelopes they will be used for");
        }
        CHECK(wait_for([&] { auto i = alice.engine->prekey_info(); return i.local_retired >= 1 && i.relay_last_resort && i.local_last_resort == 1; }, 30000),
              "a new last-resort prekey replaces the old one on schedule (every 5 seconds here), and the old one is kept for envelopes on their way");
        const std::string old_generation = alice.engine->prekey_info().generation;
        const fs::path store = alice.engine->prekey_store_path();
        alice.engine.reset();
        CHECK(fs::exists(store), "(her prekey store is a file next to her history)");
        fs::remove(store);
        restart_engine(alice);
        CHECK(wait_for([&] { auto i = alice.engine->prekey_info(); return i.relay_matches && i.generation != old_generation && i.relay_one_time == 100 && i.relay_last_resort; }, 30000),
              "with the store gone (as after a restore), the app replaces the whole pool on the relay with a new set");
        CHECK(alice.engine->prekey_info().local_one_time == 100, "and holds only the new set's private halves");
    }

    std::cout << "11c. Forward secrecy, end to end\n";
    {
        std::string err;
        auto texts = [&](User& u, const std::string& from) { std::vector<std::string> t; for (auto& m : u.engine->messages(from)) t.push_back(m.text); return t; };
        auto has_text = [&](User& u, const std::string& from, const std::string& text) { for (auto& t : texts(u, from)) if (t == text) return true; return false; };
        // 1. An ordinary message uses one of the recipient's one-time prekeys, which is deleted once the message is stored.
        wait_for([&] { auto i = bob.engine->prekey_info(); return i.relay_matches && i.pending_upload == 0; }, 30000);
        const size_t before = bob.engine->prekey_info().local_one_time;
        CHECK(alice.engine->send_text(bob.fp, "sealed to a one-time key", err) && wait_for([&] { return has_text(bob, alice.fp, "sealed to a one-time key"); }, 30000), "Alice sends Bob a message, and he gets it");
        CHECK(wait_for([&] { return bob.engine->prekey_info().local_one_time == before - 1; }, 10000), "it was sealed to one of Bob's one-time prekeys, whose private half is now deleted");

        // 2. The proof: an envelope captured on the relay can't be opened afterwards, even with every key Bob still has.
        const fs::path bob_store = bob.engine->prekey_store_path();
        bob.engine.reset();
        CHECK(alice.engine->send_text(bob.fp, "captured on the relay", err), "with Bob's app closed, Alice sends another");
        Bytes captured;
        const fs::path relay_db = ROOT / "relay-data/s/v3/relay.db";
        as(bob);
        const Bytes bob_kem = bob.keys->load_private_kem();
        const Bytes vault_key = bob.keys->derive_local_key("prekey vault key");
        const Bytes bob_mailbox = alice.keys->find_contact_by_fingerprint(bob.fp)->mailbox_id;
        wait_for([&] {  // the envelope holding that message, among those waiting for Bob (as an eavesdropper on the relay would take it)
            sqlite3* db = nullptr;
            if (sqlite3_open_v2(relay_db.string().c_str(), &db, SQLITE_OPEN_READWRITE, nullptr) != SQLITE_OK) return false;
            sqlite3_stmt* st = nullptr;
            sqlite3_prepare_v2(db, "SELECT envelope FROM envelopes WHERE mailbox_id = ?", -1, &st, nullptr);
            sqlite3_bind_blob(st, 1, bob_mailbox.data(), static_cast<int>(bob_mailbox.size()), SQLITE_TRANSIENT);
            std::vector<Bytes> waiting;
            while (sqlite3_step(st) == SQLITE_ROW) {
                const auto* b = static_cast<const uint8_t*>(sqlite3_column_blob(st, 0));
                waiting.emplace_back(b, b + sqlite3_column_bytes(st, 0));
            }
            sqlite3_finalize(st);
            sqlite3_close(db);
            PrekeyVault store(bob_store, vault_key);
            for (const auto& env : waiting) {
                auto inner = chat::open_envelope(env, bob_kem, [&](const Bytes& id) { return store.find(id); });
                if (!inner) continue;
                for (const auto& raw : inner->records)
                    if (auto r = chat::parse_record(raw); r && std::string(r->record.payload.begin(), r->record.payload.end()) == "captured on the relay") captured = env;
            }
            return !captured.empty();
        }, 20000);
        CHECK(chat::envelope_prekey_id(captured).has_value() && !chat::open_envelope(captured, bob_kem), "(an envelope is taken off the relay, as an eavesdropper would): Bob's long-term key alone can't open it");
        {
            PrekeyVault store(bob_store, vault_key);
            CHECK(chat::open_envelope(captured, bob_kem, [&](const Bytes& id) { return store.find(id); }).has_value(), "with his one-time prekey (still held) it opens");
        }
        restart_engine(bob);
        CHECK(wait_for([&] { return has_text(bob, alice.fp, "captured on the relay"); }, 30000), "Bob's app comes back and receives the message");
        run_for(1500);
        bob.engine.reset();
        {
            PrekeyVault store(bob_store, vault_key);
            CHECK(!chat::open_envelope(captured, bob_kem, [&](const Bytes& id) { return store.find(id); }), "and now the captured envelope can't be opened at all, with every key Bob has: forward secrecy");
        }
        restart_engine(bob);

        // 3. With Bob's one-time prekeys all taken, a message still goes, sealed to his last-resort prekey (which is kept).
        auto contact = alice.keys->find_contact_by_fingerprint(bob.fp);
        auto address = contact ? parse_server_address(contact->relay_address) : std::nullopt;
        RelayClient c;
        int drained = 0;
        if (address && c.connect(address->host, address->port, contact->relay_id, 5, err)) {
            relay::PrekeyData d;
            while (drained < 500 && c.take_prekey(contact->mailbox_id, contact->send_token, d, err) && !d.last_resort) drained++;
        }
        CHECK(drained > 0, "(Bob's one-time prekeys are all taken: " + std::to_string(drained) + ")");
        CHECK(alice.engine->send_text(bob.fp, "to the last-resort key", err) && wait_for([&] { return has_text(bob, alice.fp, "to the last-resort key"); }, 30000) && bob.engine->prekey_info().local_last_resort == 1,
              "a message still gets through, sealed to his last-resort prekey, which he keeps");

        // 4. Losing the store (as after a restore): what was sealed to the old keys is lost, and Bob is told; new messages work.
        bob.engine.reset();
        CHECK(alice.engine->send_text(bob.fp, "sent to the old keys", err), "with Bob's app closed, Alice sends a message");
        wait_for([&] { return alice.engine->messages(bob.fp).back().status >= HistoryStore::Sent; }, 20000);
        fs::remove(bob_store);
        restart_engine(bob);
        CHECK(wait_for([&] { for (auto& n : bob.engine->take_notices()) if (n.find("could not be read") != std::string::npos) return true; return false; }, 30000),
              "Bob's store is gone (as after a restore): the message sealed to his old keys can't be read, and he is told");
        CHECK(!has_text(bob, alice.fp, "sent to the old keys"), "(it is not shown)");
        CHECK(wait_for([&] { auto i = bob.engine->prekey_info(); return i.relay_matches && i.relay_one_time > 0; }, 30000), "his app puts a new set of prekeys on the relay");
        CHECK(alice.engine->send_text(bob.fp, "after the new keys", err) && wait_for([&] { return has_text(bob, alice.fp, "after the new keys"); }, 30000), "and messages work again");

        // 5. A relay that hands out a prekey that isn't Bob's: Alice's app notices, and sends without forward secrecy instead of to the wrong key.
        auto mallory_identity = CryptoEngine::generate_sig_keypair();
        const Bytes forged = prekey::encode(prekey::generate(mallory_identity.private_key, false, 1).prekey);
        {
            sqlite3* db = nullptr;
            sqlite3_open_v2(relay_db.string().c_str(), &db, SQLITE_OPEN_READWRITE, nullptr);
            sqlite3_stmt* st = nullptr;
            sqlite3_prepare_v2(db, "UPDATE prekeys SET blob = ? WHERE last_resort = 0", -1, &st, nullptr);
            sqlite3_bind_blob(st, 1, forged.data(), static_cast<int>(forged.size()), SQLITE_TRANSIENT);
            sqlite3_step(st);
            sqlite3_finalize(st);
            sqlite3_close(db);
        }
        alice.engine->take_notices();
        const size_t held = bob.engine->prekey_info().local_one_time;
        CHECK(alice.engine->send_text(bob.fp, "past a forged key", err) && wait_for([&] { return has_text(bob, alice.fp, "past a forged key"); }, 30000), "the relay hands Alice a forged prekey: the message is still delivered");
        bool warned = false;
        for (auto& n : alice.engine->take_notices()) warned |= n.find("isn't theirs") != std::string::npos;
        CHECK(warned && bob.engine->prekey_info().local_one_time == held, "but sealed to Bob's long-term key, not the forged one, and Alice is told");

        // 6. A relay that suddenly says Bob has no prekeys at all: the message still goes, and Alice, who has sealed to his prekeys before, is told.
        bob.engine.reset();
        {
            sqlite3* db = nullptr;
            sqlite3_open_v2(relay_db.string().c_str(), &db, SQLITE_OPEN_READWRITE, nullptr);
            sqlite3_stmt* st = nullptr;
            sqlite3_prepare_v2(db, "DELETE FROM prekeys WHERE mailbox_id = ?", -1, &st, nullptr);
            sqlite3_bind_blob(st, 1, bob_mailbox.data(), static_cast<int>(bob_mailbox.size()), SQLITE_TRANSIENT);
            sqlite3_step(st);
            sqlite3_finalize(st);
            sqlite3_close(db);
        }
        alice.engine->take_notices();
        CHECK(alice.engine->send_text(bob.fp, "after the pool vanished", err), "(Bob's relay drops all his prekeys, and Alice sends a message)");
        CHECK(wait_for([&] { for (auto& n : alice.engine->take_notices()) if (n.find("no one-time keys any more") != std::string::npos) return true; return false; }, 20000),
              "Alice's app has sealed to Bob's prekeys before, so a relay suddenly saying he has none stands out: she is told");
        restart_engine(bob);
        CHECK(wait_for([&] { return has_text(bob, alice.fp, "after the pool vanished"); }, 30000), "the message is still delivered (without forward secrecy)");
        CHECK(wait_for([&] { auto i = bob.engine->prekey_info(); return i.relay_matches && i.relay_one_time > 0 && i.relay_last_resort; }, 30000), "and Bob's app puts prekeys back");

        // 7. A replay: the envelope captured earlier, which Bob has already handled, is deposited again.
        const size_t shown = texts(bob, alice.fp).size();
        RelayClient again;
        std::string rerr;
        CHECK(address && again.connect(address->host, address->port, contact->relay_id, 5, rerr) && again.deposit(contact->mailbox_id, contact->send_token, captured, 3600, nullptr, rerr),
              "an envelope Bob has already handled is put in his mailbox again (" + rerr + ")");
        run_for(4000);
        CHECK(texts(bob, alice.fp).size() == shown, "it can't be opened (its one-time key is gone) and changes nothing: replays are harmless");
    }

    std::cout << "12. Locked keys\n";
    {
        setenv("HOME", (ROOT / "lockbox").c_str(), 1);
        fs::create_directories(ROOT / "lockbox");
        KeyStore protected_keys;
        protected_keys.set_kdf_cost(10);
        protected_keys.initialize_keys("lockbox passphrase");
        KeyStore reopened;
        reopened.set_kdf_cost(10);
        reopened.initialize_keys();
        bool threw = false;
        try { MessagingEngine locked(reopened, ROOT / "lockbox/history.db"); } catch (const std::exception& e) { threw = has(e.what(), "locked"); }
        CHECK(threw, "an engine can't be started while the keys are locked");
        reopened.unlock("lockbox passphrase");
        bool works = true;
        try { MessagingEngine ok(reopened, ROOT / "lockbox/history.db"); } catch (...) { works = false; }
        CHECK(works, "once unlocked it can");
    }

    for (auto& [_, u] : users) u->engine.reset();
    srv.stop();
    std::error_code ec;
    fs::remove_all(ROOT, ec);
    std::cout << (failures ? "\nFAILURES: " : "\nAll checks passed. ") << failures << "\n";
    return failures ? 1 : 0;
}
