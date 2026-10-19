// Integration tests for one-to-one Saved chats: real relay process, real MessagingEngines.
// POSIX only. Usage: test_chat /path/to/pq-server
#include "crypto_engine.h"
#include "envelope.h"
#include "messaging_engine.h"
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
                  "--sweep-seconds", "1", "--rate-limit", "100000", static_cast<char*>(nullptr));
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
    o.receipt_delay_max_seconds = 0;
    o.reconnect_min_seconds = 1;
    o.reconnect_max_seconds = 2;
    o.connect_timeout_seconds = 3;
    o.retry_base_seconds = 1;
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
