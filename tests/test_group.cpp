// Integration tests for group chats: a real relay process and real MessagingEngines for several
// people. POSIX only. Usage: test_group /path/to/pq-server
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

#include <sqlite3.h>

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
static int PORT = 0;
static Bytes RELAY_ID;

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
                  "--sweep-seconds", "1", "--rate-limit", "100000", "--mailbox-quota-kib", "4096", static_cast<char*>(nullptr));
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

static int g_archive_check_seconds = 1;  // how often an engine looks for chats that need an archive

static MessagingEngine::Options test_options() {
    MessagingEngine::Options o;
    o.receipt_delay_max_seconds = 0;
    o.reconnect_min_seconds = 1;
    o.reconnect_max_seconds = 2;
    o.connect_timeout_seconds = 3;
    o.retry_base_seconds = 1;
    o.archive_check_seconds = g_archive_check_seconds;  // chat archives are made and caught up on quickly...
    o.archive_sync_seconds = 2;
    o.archive_checkpoint_every = 5;   // ...and checkpointed after 5 entries instead of 50
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

static User& make_user(const std::string& name) {
    auto u = std::make_unique<User>();
    u->name = name;
    u->home = ROOT / name;
    fs::create_directories(u->home);
    setenv("HOME", u->home.c_str(), 1);
    u->keys = std::make_unique<KeyStore>();
    u->keys->initialize_keys();
    u->fp = u->keys->own_fingerprint();
    u->engine = std::make_unique<MessagingEngine>(*u->keys, u->history(), test_options());
    u->engine->set_display_name(name);
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

static bool wait_for(const std::function<bool()>& cond, int timeout_ms = 15000) {
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

// The relay allows only 10 mailbox registrations per minute from one address, so with many people this
// waits for the window to pass, running the engines meanwhile.
static bool setup_user_patiently(Server& srv, User& u) {
    for (int attempt = 0; attempt < 40; attempt++) {
        if (setup_user(srv, u)) return true;
        run_for(2000);
    }
    return false;
}

static bool import_card(User& owner, const std::string& card, const std::string& name) {
    auto c = decode_any_contact_card(card);
    if (!c || !c->bundle) return false;
    as(owner);
    owner.keys->save_contact_bundle(name, *c->bundle);
    if (!c->send_token.empty()) owner.keys->save_contact_token(name, c->send_token);
    return true;
}

// `issuer` makes a card and `receiver` imports it: afterwards `receiver` can message `issuer`.
static bool give_card(User& issuer, User& receiver, const std::string& name_for_issuer) {
    std::string card, err;
    if (!issuer.engine->make_card("for " + receiver.name, card, err)) { std::cout << "  (make_card failed: " << err << ")\n"; return false; }
    return import_card(receiver, card, name_for_issuer);
}

static std::string cap(std::string s) { if (!s.empty()) s[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(s[0]))); return s; }

// Both can message each other.
static bool befriend(User& a, User& b) { return give_card(a, b, cap(a.name)) && give_card(b, a, cap(b.name)); }

// --- Looking at groups ---

static std::optional<MessagingEngine::GroupSummary> find_group(User& u, const std::string& id) {
    for (auto& g : u.engine->groups()) if (g.id == id) return g;
    return std::nullopt;
}
static std::optional<MessagingEngine::GroupInvite> find_invite(User& u, const std::string& id) {
    for (auto& i : u.engine->group_invites()) if (i.id == id) return i;
    return std::nullopt;
}
static size_t incoming_count(User& u, const std::string& g, const std::string& text) {
    size_t n = 0;
    for (auto& m : u.engine->group_messages(g)) if (!m.outgoing && m.text == text) n++;
    return n;
}
static bool got(User& u, const std::string& g, const std::string& text) { return incoming_count(u, g, text) > 0; }
static std::optional<MessagingEngine::GroupMessage> outgoing_message(User& u, const std::string& g, const std::string& text) {
    for (auto& m : u.engine->group_messages(g)) if (m.outgoing && m.text == text) return m;
    return std::nullopt;
}
static int overall(User& u, const std::string& g, const std::string& text) {
    auto m = outgoing_message(u, g, text);
    return m ? m->status : -1;
}
static int member_status(User& u, const std::string& g, const std::string& text, const std::string& member_fp) {
    auto m = outgoing_message(u, g, text);
    if (!m) return -1;
    for (auto& d : u.engine->group_delivery(g, m->message_id)) if (d.fp == member_fp) return d.status;
    return -1;
}
static bool any_notice(User& u, const char* needle) {
    bool found = false;
    for (auto& line : u.engine->take_notices()) if (has(line, needle)) found = true;
    return found;
}
static bool file_contains(const fs::path& p, const std::string& needle) {
    std::ifstream f(p, std::ios::binary);
    std::string data((std::istreambuf_iterator<char>(f)), {});
    return data.find(needle) != std::string::npos;
}

static void sql_exec(const fs::path& db, const std::string& sql) {
    sqlite3* h = nullptr;
    sqlite3_open_v2(db.string().c_str(), &h, SQLITE_OPEN_READWRITE, nullptr);
    char* err = nullptr;
    if (sqlite3_exec(h, sql.c_str(), nullptr, nullptr, &err) != SQLITE_OK) {
        std::cout << "  (sql failed: " << (err ? err : "?") << ")\n";
        sqlite3_free(err);
    }
    sqlite3_close(h);
}

static std::string hex_literal(const Bytes& b) { return "x'" + bytes_to_hex(b) + "'"; }

// --- Hand-made envelopes, for the hostile cases ---

static Bytes fp_raw(const User& u) { return *hex_to_bytes(u.fp); }

static Bytes sign_as(User& signer, chat::Record r) {
    as(signer);
    r.sender = fp_raw(signer);
    return chat::sign_record(r, signer.keys->load_private_dsa());
}

static chat::Record base_record(const Bytes& conv, const Bytes& recipients, chat::RecordType type) {
    chat::Record r;
    r.conversation_id = conv;
    r.message_id = CryptoEngine::random_bytes(chat::ID_BYTES);
    r.recipients_hash = recipients;
    r.sent_at = static_cast<uint64_t>(std::time(nullptr));
    r.type = type;
    return r;
}

static Bytes group_text(User& signer, const Bytes& conv, const std::vector<Bytes>& everyone, const std::string& text) {
    chat::Record r = base_record(conv, chat::recipients_hash_for(everyone), chat::RecordType::Text);
    r.payload.assign(text.begin(), text.end());
    return sign_as(signer, r);
}

static Bytes creation_record(User& creator, const Bytes& conv, const std::string& title, const std::vector<Bytes>& members, const Bytes& recipients = {}) {
    chat::ConversationInfo info;
    info.title = title;
    info.members = members;
    chat::Record r = base_record(conv, recipients.empty() ? chat::recipients_hash_for(members) : recipients, chat::RecordType::Conversation);
    r.payload = chat::conversation_payload(info);
    return sign_as(creator, r);
}

// Puts an envelope in `target`'s mailbox using `token`, a send token `target` issued.
static bool deposit_to(User& target, const Bytes& token, const Bytes& envelope) {
    auto cfg = target.keys->load_mailbox_config();
    RelayClient c;
    std::string err;
    return cfg && c.connect("127.0.0.1", static_cast<uint16_t>(PORT), RELAY_ID, 3, err) && c.deposit(cfg->mailbox_id, token, envelope, 600, nullptr, err);
}

// The token `from` was given for writing to `to` (from the card `to` made).
static Bytes token_for(User& from, User& to) {
    auto c = from.keys->find_contact_by_fingerprint(to.fp);
    return c ? c->send_token : Bytes();
}

static bool send_envelope(User& target, const Bytes& token, const chat::Inner& inner) {
    return deposit_to(target, token, chat::seal_envelope(inner, target.keys->load_public_kem()));
}

// What is waiting in someone's mailbox, read as its owner and left there. Their engine must not be running.
static std::vector<Bytes> mailbox_envelopes(User& u) {
    std::vector<Bytes> out;
    auto cfg = u.keys->load_mailbox_config();
    Bytes access = u.keys->load_access_private();
    RelayClient c;
    std::string err;
    if (!cfg || access.empty() || !c.connect("127.0.0.1", static_cast<uint16_t>(PORT), RELAY_ID, 3, err) ||
        !c.authenticate(cfg->mailbox_id, access, err) || !c.collect(err))
        return out;
    for (int i = 0; i < 60; i++) {
        auto e = c.next_event(250);
        if (e.kind == RelayClient::Event::Kind::Envelope) out.push_back(e.envelope.envelope);
        else if (e.kind == RelayClient::Event::Kind::CollectEnd || e.kind == RelayClient::Event::Kind::Closed) break;
    }
    return out;
}

// Throws away everything waiting in someone's mailbox, as if it had never arrived. Their engine must not be running.
static size_t empty_mailbox(User& u) {
    auto cfg = u.keys->load_mailbox_config();
    Bytes access = u.keys->load_access_private();
    RelayClient c;
    std::string err;
    std::vector<Bytes> ids;
    if (!cfg || access.empty() || !c.connect("127.0.0.1", static_cast<uint16_t>(PORT), RELAY_ID, 3, err) || !c.authenticate(cfg->mailbox_id, access, err) || !c.collect(err)) return 0;
    for (int i = 0; i < 60; i++) {
        auto e = c.next_event(250);
        if (e.kind == RelayClient::Event::Kind::Envelope) ids.push_back(e.envelope.id);
        else if (e.kind == RelayClient::Event::Kind::CollectEnd || e.kind == RelayClient::Event::Kind::Closed) break;
    }
    size_t deleted = 0;
    if (!ids.empty()) c.acknowledge(ids, &deleted, err);
    return deleted;
}

static Bytes bundle_of(User& u) {
    as(u);
    auto cfg = u.keys->load_mailbox_config();
    BundleAddress address;
    address.relay_hint = "127.0.0.1:" + std::to_string(PORT);
    address.relay_id = cfg->relay_id;
    address.mailbox_id = cfg->mailbox_id;
    return u.keys->make_own_bundle(u.name, address);
}

int main(int argc, char** argv) {
    if (argc < 2) { std::cerr << "usage: test_group /path/to/pq-server\n"; return 2; }
    SERVER_BIN = argv[1];
    ROOT = fs::temp_directory_path() / ("pqft-group-" + std::to_string(getpid()));
    fs::remove_all(ROOT);
    fs::create_directories(ROOT);
    platform_init();

    PORT = 31000 + static_cast<int>(getpid() % 5000);
    Server srv{PORT, ROOT / "relay-data/s"};
    fs::create_directories(srv.storage.parent_path());
    if (!srv.start()) { std::cout << "FAIL could not start the relay\n"; return 1; }
    RELAY_ID = srv.invite()->relay_id;

    User& alice = make_user("alice");
    User& bob = make_user("bob");
    User& carol = make_user("carol");
    User& dave = make_user("dave");
    User& mallory = make_user("mallory");
    for (User* u : {&alice, &bob, &carol, &dave, &mallory}) {
        if (!setup_user(srv, *u)) { std::cout << "FAIL could not set up " << u->name << "\n"; return 1; }
    }
    // Alice, Bob and Carol know each other. Dave knows only Alice. Mallory is Bob's contact and nobody else's.
    bool befriended = befriend(alice, bob) && befriend(alice, carol) && befriend(bob, carol) && befriend(alice, dave) && befriend(bob, mallory);
    CHECK(befriended, "(setup) five people on one relay, with the contacts described above");
    const Bytes a = fp_raw(alice), b = fp_raw(bob), c = fp_raw(carol), d = fp_raw(dave), m = fp_raw(mallory);

    std::string hiking;  // the group of Alice, Bob and Carol

    std::cout << "1. Creating a group\n";
    {
        std::string id, err;
        CHECK(!alice.engine->create_group("x", {}, id, err) && has(err, "at least one"), "a group needs someone in it: " + err);
        CHECK(!alice.engine->create_group("x", {std::string(64, 'a')}, id, err) && has(err, "isn't in your contacts"), "only contacts can be invited: " + err);
        CHECK(!alice.engine->create_group("x", {alice.fp}, id, err) && has(err, "already in"), "you can't invite yourself: " + err);
        CHECK(!alice.engine->create_group("x", {bob.fp, bob.fp}, id, err) && has(err, "twice"), "or the same person twice: " + err);
        CHECK(!alice.engine->create_group(std::string(65, 't'), {bob.fp}, id, err) && has(err, "too long"), "a name over 64 bytes is refused: " + err);
        std::vector<std::string> many(16, bob.fp);
        CHECK(!alice.engine->create_group("x", many, id, err) && has(err, "at most 16"), "more than 15 others is refused: " + err);
        User& zed = make_user("zed");
        CHECK(!zed.engine->create_group("x", {bob.fp}, id, err) && has(err, "Set up"), "before messaging is set up there is nothing to create with: " + err);
        users.erase("zed");
        CHECK(alice.engine->groups().empty(), "(none of those created anything)");

        CHECK(alice.engine->create_group("Hiking", {bob.fp, carol.fp}, hiking, err) && hiking.size() == 32, "Alice creates a group with Bob and Carol (" + err + ")");
        auto g = find_group(alice, hiking);
        CHECK(g && g->title == "Hiking" && g->created_by_me && g->members.size() == 2 && g->members[0].fp == bob.fp && g->members[1].fp == carol.fp, "it is in her list, with her as creator and the others as members");
        CHECK(g && g->ready && g->members[0].is_contact && g->members[0].can_send && g->members[0].name == "Bob", "all its members are contacts she can write to, so it is ready");
        CHECK(alice.engine->group_messages(hiking).empty(), "it starts empty (the creation record is not a message)");
    }

    std::cout << "2. Invitations wait for an answer, and messages wait with them\n";
    {
        std::string err;
        CHECK(alice.engine->send_group_text(hiking, "welcome everyone", err), "Alice writes to the group straight away");
        CHECK(wait_for([&] { return find_invite(bob, hiking) && find_invite(carol, hiking); }), "Bob and Carol each receive an invitation");
        auto invite = find_invite(bob, hiking);
        CHECK(invite && invite->title == "Hiking" && invite->creator_fp == alice.fp && invite->creator_name == "Alice" && invite->members.size() == 2, "it shows the name, who invited them and who else is in it");
        bool names = false;
        if (invite) {
            for (auto& mem : invite->members) if (mem.fp == carol.fp && mem.name == "Carol" && mem.is_contact) names = true;
        }
        CHECK(names, "the other member is shown by name (Carol is Bob's contact)");
        CHECK(any_notice(bob, "invited you to the group"), "Bob is told about it");
        CHECK(bob.engine->groups().empty() && bob.engine->requests().empty(), "it is not a group yet, and not a message request either");
        CHECK(wait_for([&] { auto i = find_invite(bob, hiking); return i && i->held_messages == 1; }), "Alice's first message arrived while Bob was deciding, and is held");
        CHECK(bob.engine->group_messages(hiking).empty(), "(nothing is shown until he accepts)");

        CHECK(bob.engine->accept_group_invite(hiking, err), "Bob accepts (" + err + ")");
        auto g = find_group(bob, hiking);
        CHECK(g && g->title == "Hiking" && g->creator_fp == alice.fp && !g->created_by_me && g->members.size() == 2 && g->ready, "the group is now his, ready (Alice and Carol are both his contacts)");
        bool contact_labels = false;
        if (g) for (auto& mem : g->members) if (mem.fp == carol.fp && mem.trust == MessagingEngine::Trust::Contact && mem.label == "Contact") contact_labels = true;
        CHECK(contact_labels, "Bob's contacts in the group are labelled \"Contact\" (not verified)");
        CHECK(!find_invite(bob, hiking) && got(bob, hiking, "welcome everyone"), "the held message was delivered, and the invitation is gone");
        auto first = bob.engine->group_messages(hiking);
        CHECK(first.size() == 1 && first[0].sender_fp == alice.fp && first[0].sender_name == "Alice" && !first[0].gap && !first[0].outgoing, "it shows who wrote it, with no gap");
        CHECK(!bob.engine->accept_group_invite(hiking, err) && has(err, "no longer"), "accepting twice is refused: " + err);

        CHECK(wait_for([&] { auto i = find_invite(carol, hiking); return i && i->held_messages == 1; }), "Alice's first message is held for Carol too");
        CHECK(carol.engine->accept_group_invite(hiking, err) && got(carol, hiking, "welcome everyone"), "Carol accepts too, and gets the held message");
        CHECK(wait_for([&] { return overall(alice, hiking, "welcome everyone") == 2; }), "Alice's message becomes Delivered once both of them have stored it");
        CHECK(member_status(alice, hiking, "welcome everyone", bob.fp) >= 2 && member_status(alice, hiking, "welcome everyone", carol.fp) >= 2, "...each member's own state shows it");
    }

    std::cout << "3. Everyone can write to everyone\n";
    {
        std::string err;
        CHECK(bob.engine->send_group_text(hiking, "Bob here", err) && carol.engine->send_group_text(hiking, "Carol here", err), "Bob and Carol write to the group");
        CHECK(wait_for([&] { return got(alice, hiking, "Bob here") && got(alice, hiking, "Carol here") && got(carol, hiking, "Bob here") && got(bob, hiking, "Carol here"); }),
              "each message reaches both of the others");
        auto seen_by_alice = alice.engine->group_messages(hiking);
        bool names = false, no_gaps = true;
        for (auto& msg : seen_by_alice) {
            if (msg.text == "Bob here" && msg.sender_name == "Bob") names = true;
            if (msg.gap) no_gaps = false;
        }
        CHECK(names && no_gaps, "with the right sender on each, and nothing reported missing");

        for (int i = 1; i <= 5; i++) alice.engine->send_group_text(hiking, "burst " + std::to_string(i), err);
        CHECK(wait_for([&] { return got(bob, hiking, "burst 5") && got(carol, hiking, "burst 5"); }), "a burst of five arrives for both");
        for (User* u : {&bob, &carol}) {
            auto msgs = u->engine->group_messages(hiking);
            std::vector<std::string> order;
            for (auto& msg : msgs) if (has(msg.text, "burst")) order.push_back(msg.text);
            bool sorted = order.size() == 5;
            for (size_t i = 0; i < order.size() && sorted; i++) sorted = order[i] == "burst " + std::to_string(i + 1);
            bool gaps = false;
            for (auto& msg : msgs) gaps |= msg.gap;
            CHECK(sorted && !gaps, u->name + " sees the burst in order, and the chain of previous-entry hashes shows no gaps");
        }
    }

    std::cout << "4. Receipts: per member, and only to the author\n";
    {
        std::string err;
        CHECK(wait_for([&] { return overall(bob, hiking, "Bob here") == 2; }), "Bob's message is Delivered once both Alice and Carol have it");
        CHECK(member_status(bob, hiking, "Bob here", alice.fp) == 2 && member_status(bob, hiking, "Bob here", carol.fp) == 2, "...each of them delivered");

        alice.engine->mark_group_read(hiking);
        CHECK(alice.engine->groups()[0].unread == 0, "Alice reading the group clears her unread count");
        CHECK(wait_for([&] { return member_status(bob, hiking, "Bob here", alice.fp) == 3; }), "Bob sees that Alice read his message");
        CHECK(member_status(bob, hiking, "Bob here", carol.fp) == 2 && overall(bob, hiking, "Bob here") == 2, "Carol hasn't, so as a whole it is still only Delivered");
        CHECK(wait_for([&] { return member_status(carol, hiking, "Carol here", alice.fp) == 3; }), "Carol hears from Alice about her own message too (each author is told about their own)");
        CHECK(member_status(carol, hiking, "Carol here", bob.fp) == 2, "(Bob hasn't read hers)");

        carol.engine->mark_group_read(hiking);
        CHECK(wait_for([&] { return overall(bob, hiking, "Bob here") == 3; }), "once Carol has read it too, Bob's message is Read");
        bob.engine->mark_group_read(hiking);
        CHECK(wait_for([&] { return overall(carol, hiking, "Carol here") == 3; }), "and Carol's, after Bob and Alice have");
        CHECK(wait_for([&] { return overall(alice, hiking, "burst 5") == 3; }), "Alice's own messages become Read once both have read them");

        bool delivery = true, read = true;
        CHECK(alice.engine->group_receipts_enabled(hiking, &delivery, &read) && delivery && read, "receipts are on by default");
        alice.engine->set_group_receipts(hiking, false, false);
        CHECK(alice.engine->group_receipts_enabled(hiking, &delivery, &read) && !delivery && !read, "they can be turned off for one group");
        bob.engine->send_group_text(hiking, "quiet please", err);
        CHECK(wait_for([&] { return got(alice, hiking, "quiet please") && got(carol, hiking, "quiet please"); }) && wait_for([&] { return member_status(bob, hiking, "quiet please", carol.fp) == 2; }), "Carol (receipts on) still confirms delivery");
        run_for(500);
        CHECK(member_status(bob, hiking, "quiet please", alice.fp) == 1 && overall(bob, hiking, "quiet please") == 1, "Alice (receipts off) doesn't, so as a whole it stays at Sent");
        alice.engine->set_group_receipts(hiking, true, true);
    }

    std::cout << "5. An offline member\n";
    {
        std::string err;
        carol.engine.reset();  // Carol's app is closed
        alice.engine->send_group_text(hiking, "while Carol is away", err);
        CHECK(wait_for([&] { return got(bob, hiking, "while Carol is away"); }), "the others get it as usual");
        CHECK(wait_for([&] { return member_status(alice, hiking, "while Carol is away", carol.fp) == 1; }), "the relay holds Carol's copy: her state is Sent");
        CHECK(wait_for([&] { return member_status(alice, hiking, "while Carol is away", bob.fp) >= 2; }), "Bob's copy becomes Delivered");
        CHECK(overall(alice, hiking, "while Carol is away") == 1, "so as a whole it is only Sent, held back by the one member who hasn't got it");
        restart_engine(carol);
        CHECK(wait_for([&] { return got(carol, hiking, "while Carol is away"); }), "when Carol's app starts, it arrives");
        CHECK(wait_for([&] { return overall(alice, hiking, "while Carol is away") == 2; }), "...and then the message as a whole is Delivered");
        CHECK(!file_contains(alice.history(), "while Carol is away") && !file_contains(fs::path(alice.history().string() + "-wal"), "while Carol is away") &&
                  !file_contains(carol.history(), "while Carol is away") && !file_contains(fs::path(carol.history().string() + "-wal"), "while Carol is away"),
              "neither history file contains the text");
    }

    std::cout << "6. Declining\n";
    {
        std::string err, plan;
        CHECK(alice.engine->create_group("Surprise party", {carol.fp}, plan, err), "Alice makes a group with only Carol");
        CHECK(wait_for([&] { return find_invite(carol, plan).has_value(); }), "Carol is invited");
        carol.engine->decline_group_invite(plan);
        CHECK(!find_invite(carol, plan) && !find_group(carol, plan), "she declines: the invitation is gone and there is no group");
        alice.engine->send_group_text(plan, "Carol, are you there?", err);
        run_for(1500);
        CHECK(!find_invite(carol, plan) && !find_group(carol, plan) && carol.engine->requests().empty(), "later messages for it don't bring it back");
        CHECK(alice.engine->group_messages(plan).size() == 1, "(Alice's side is unaffected: she isn't told)");
    }

    std::cout << "7. A group whose members don't all know each other\n";
    std::string mixed;  // Alice, Bob and Dave; Dave knows only Alice
    {
        std::string err;
        CHECK(alice.engine->create_group("Mixed", {bob.fp, dave.fp}, mixed, err), "Alice makes a group with Bob and Dave, who have never met");
        CHECK(wait_for([&] { return find_invite(bob, mixed) && find_invite(dave, mixed); }), "both are invited");
        auto invite = find_invite(bob, mixed);
        bool dave_known = false;
        if (invite) for (auto& mem : invite->members) if (mem.fp == dave.fp && mem.name == "dave" && !mem.is_contact && !mem.can_send) dave_known = true;
        CHECK(dave_known, "Bob's invitation names Dave from the bundle Alice passed on, as someone Bob can't write to yet");
        bool dave_introduced = false;
        if (invite) for (auto& mem : invite->members)
            if (mem.fp == dave.fp && mem.trust == MessagingEngine::Trust::Introduced && mem.introduced_by == "Alice" && mem.label == "Introduced by Alice") dave_introduced = true;
        CHECK(dave_introduced, "...and labels him \"Introduced by Alice\": the keys came from the creator, nobody has checked them");
        CHECK(bob.engine->accept_group_invite(mixed, err) && dave.engine->accept_group_invite(mixed, err), "both accept");
        CHECK(find_group(alice, mixed) && find_group(alice, mixed)->ready, "for Alice it is ready from the start (they are both her contacts)");

        // Bob and Dave have never met. Each sent the other a send token, sealed so Alice (who passed
        // it on) can't read it. Until those arrive the group is "setting up".
        bool both_ready = wait_for([&] {
            auto bv = find_group(bob, mixed), dv = find_group(dave, mixed);
            return bv && bv->ready && dv && dv->ready;
        }, 30000);
        CHECK(both_ready, "Bob and Dave each end up able to write to the other: the group is ready for both");
        auto bob_view = find_group(bob, mixed);
        bool dave_is_stranger = false;
        if (bob_view) for (auto& mem : bob_view->members) if (mem.fp == dave.fp && !mem.is_contact && mem.can_send) dave_is_stranger = true;
        CHECK(dave_is_stranger, "...even though Dave is still not Bob's contact");
        CHECK(bob.engine->requests().empty() && dave.engine->requests().empty(), "(and nobody became a message request)");

        bob.engine->send_group_text(mixed, "Bob to the mixed group", err);
        dave.engine->send_group_text(mixed, "Dave to the mixed group", err);
        alice.engine->send_group_text(mixed, "Alice to the mixed group", err);
        CHECK(wait_for([&] {
            return got(alice, mixed, "Bob to the mixed group") && got(alice, mixed, "Dave to the mixed group") && got(dave, mixed, "Bob to the mixed group") &&
                   got(bob, mixed, "Dave to the mixed group") && got(bob, mixed, "Alice to the mixed group") && got(dave, mixed, "Alice to the mixed group");
        }, 30000), "everyone's messages reach everyone, including between Bob and Dave");
        bool right_name = false;
        for (auto& msg : bob.engine->group_messages(mixed)) if (msg.text == "Dave to the mixed group" && msg.sender_name == "dave" && msg.sender_fp == dave.fp) right_name = true;
        CHECK(right_name, "Bob sees Dave's message as Dave's");
        CHECK(wait_for([&] { return overall(bob, mixed, "Bob to the mixed group") == 2 && overall(dave, mixed, "Dave to the mixed group") == 2; }, 30000),
              "delivery receipts work between them too: both messages become Delivered");
        bob.engine->mark_group_read(mixed);
        CHECK(wait_for([&] { return member_status(dave, mixed, "Dave to the mixed group", bob.fp) == 3; }, 30000), "and Bob's read receipt reaches Dave directly");
        CHECK(any_notice(bob, "passed on") == false, "no token was reported as passed on (the creator's forwarding doesn't look like misuse)");

        // Trust: Bob compares Dave's fingerprint with him.
        auto label_of = [&](User& viewer, const std::string& group, const std::string& fp) {
            auto g = find_group(viewer, group);
            if (g) for (auto& mem : g->members) if (mem.fp == fp) return std::make_pair(mem.trust, mem.label);
            return std::make_pair(MessagingEngine::Trust::Unknown, std::string("(not found)"));
        };
        CHECK(label_of(bob, mixed, dave.fp).second == "Introduced by Alice" && !bob.engine->is_verified(dave.fp), "after the group is working Dave is still just introduced");
        CHECK(!bob.engine->set_verified(std::string(64, 'a'), true), "someone Bob knows nothing about can't be marked verified");
        CHECK(bob.engine->set_verified(dave.fp, true) && bob.engine->is_verified(dave.fp), "Bob marks Dave verified (he compared fingerprints)");
        CHECK(label_of(bob, mixed, dave.fp).first == MessagingEngine::Trust::Verified && label_of(bob, mixed, dave.fp).second == "Verified by you", "Dave now reads \"Verified by you\"");
        bob.engine->set_verified(dave.fp, false);
        CHECK(label_of(bob, mixed, dave.fp).second == "Introduced by Alice", "taking it back returns him to \"Introduced by Alice\"");
        bob.engine->set_verified(dave.fp, true);
        CHECK(label_of(alice, mixed, bob.fp).second == "Contact" && label_of(dave, mixed, bob.fp).second == "Introduced by Alice", "each person's labels are their own: Alice sees Bob as a contact, Dave sees him as introduced");
    }

    std::cout << "8. Hostile input\n";
    {
        const Bytes hiking_id = *hex_to_bytes(hiking);
        const size_t bob_before = bob.engine->group_messages(hiking).size();
        std::string err;

        // A contact of Bob's who isn't in the group.
        chat::Inner from_mallory;
        from_mallory.records = {group_text(mallory, hiking_id, {a, b, c}, "I am not in this group")};
        CHECK(send_envelope(bob, token_for(mallory, bob), from_mallory), "(setup) Mallory, Bob's contact, writes to Bob");
        run_for(1200);
        CHECK(bob.engine->group_messages(hiking).size() == bob_before && !got(bob, hiking, "I am not in this group"), "a contact who isn't a member can't write into the group");

        // A genuine member, but the record is bound to different people.
        chat::Inner redirected;
        redirected.records = {group_text(alice, hiking_id, {a, b, m}, "meant for another group")};
        CHECK(send_envelope(bob, token_for(alice, bob), redirected), "(setup) Alice's key signs a record bound to a different set of people");
        run_for(1200);
        CHECK(!got(bob, hiking, "meant for another group"), "a record bound to the wrong recipients is dropped");

        // A forged sender: Mallory signs, claiming to be Alice.
        chat::Record lie = base_record(hiking_id, chat::recipients_hash_for({a, b, c}), chat::RecordType::Text);
        lie.sender = a;
        lie.payload = Bytes{'f', 'a', 'k', 'e'};
        as(mallory);
        chat::Inner forged;
        forged.records = {chat::sign_record(lie, mallory.keys->load_private_dsa())};
        send_envelope(bob, token_for(mallory, bob), forged);
        run_for(1200);
        CHECK(!got(bob, hiking, "fake"), "a record claiming to be Alice but signed by Mallory is dropped");

        // A replayed creation record, and one trying to rewrite the group.
        const size_t invites_before = bob.engine->group_invites().size();
        chat::Inner replay;
        replay.records = {creation_record(alice, hiking_id, "Hiking", {a, b, c})};
        chat::Inner rewrite;
        rewrite.records = {creation_record(alice, hiking_id, "Renamed by an attacker", {a, b, m})};
        send_envelope(bob, token_for(alice, bob), replay);
        send_envelope(bob, token_for(alice, bob), rewrite);
        run_for(1500);
        auto g = find_group(bob, hiking);
        CHECK(g && g->title == "Hiking" && g->members.size() == 2 && g->members[0].fp == alice.fp && g->members[1].fp == carol.fp && bob.engine->group_invites().size() == invites_before,
              "a creation record for a group that exists changes nothing: same title, same members, no new invitation");

        // An invitation that doesn't name Bob, and one whose creator isn't a member.
        const Bytes outsiders_id = CryptoEngine::random_bytes(16);
        chat::Inner not_me;
        not_me.records = {creation_record(alice, outsiders_id, "Not for Bob", {a, c, d})};
        chat::Inner not_creator;
        not_creator.records = {creation_record(alice, CryptoEngine::random_bytes(16), "Alice is not in it", {b, c, d})};
        chat::Inner wrong_hash;
        wrong_hash.records = {creation_record(alice, CryptoEngine::random_bytes(16), "Wrong hash", {a, b, c}, chat::recipients_hash_for({a, b}))};
        send_envelope(bob, token_for(alice, bob), not_me);
        send_envelope(bob, token_for(alice, bob), not_creator);
        send_envelope(bob, token_for(alice, bob), wrong_hash);
        run_for(1500);
        CHECK(bob.engine->group_invites().size() == invites_before, "invitations that don't name Bob, whose creator isn't a member, or whose recipients hash is wrong are dropped");

        // A creator who passes on bundles that don't check out. Frank and Gina are new to everyone,
        // so a bundle is the only way Bob can learn their names.
        User& frank = make_user("frank");
        User& gina = make_user("gina");
        CHECK(setup_user_patiently(srv, frank) && setup_user_patiently(srv, gina), "(setup) two more people nobody has met");
        const Bytes f = fp_raw(frank), gi = fp_raw(gina);
        Bytes bad_bundle = bundle_of(frank);
        bad_bundle[bad_bundle.size() / 2] ^= 0x01;
        const Bytes tricky_id = CryptoEngine::random_bytes(16);
        chat::Inner liar;
        liar.records = {creation_record(alice, tricky_id, "Tricky", {a, b, f, gi})};
        liar.introduced = {bad_bundle, bundle_of(gina), bundle_of(mallory)};
        send_envelope(bob, token_for(alice, bob), liar);
        const std::string tricky = bytes_to_hex(tricky_id);
        CHECK(wait_for([&] { return find_invite(bob, tricky).has_value(); }), "(setup) an invitation arrives with a damaged bundle for Frank, a good one for Gina, and one for someone it doesn't name");
        auto tricky_view = find_invite(bob, tricky);
        std::string frank_name, gina_name;
        bool mallory_listed = false;
        if (tricky_view)
            for (auto& mem : tricky_view->members) {
                if (mem.fp == frank.fp) frank_name = mem.name;
                if (mem.fp == gina.fp) gina_name = mem.name;
                if (mem.fp == mallory.fp) mallory_listed = true;
            }
        CHECK(gina_name == "gina", "the good bundle names Gina");
        CHECK(!frank_name.empty() && frank_name != "frank" && has(frank_name, "..."), "the damaged one is ignored: Frank is shown only by a short fingerprint");
        CHECK(tricky_view && tricky_view->members.size() == 3 && !mallory_listed, "and the bundle for someone the record doesn't name changes nothing");
        bob.engine->decline_group_invite(tricky);
        CHECK(!find_invite(bob, tricky), "(declined)");
        users.erase("frank");
        users.erase("gina");
    }

    std::cout << "9. Someone who isn't a contact creates a group\n";
    {
        User& erin = make_user("erin");
        std::string err, from_erin;
        CHECK(setup_user_patiently(srv, erin) && give_card(alice, erin, "Alice"), "(setup) Erin knows Alice (Alice doesn't know Erin)");
        CHECK(erin.engine->create_group("Erin's group", {alice.fp}, from_erin, err), "Erin invites Alice to a group (" + err + ")");
        CHECK(wait_for([&] { return !alice.engine->requests().empty(); }), "to Alice it arrives as a message request from a stranger");
        CHECK(alice.engine->group_invites().empty() && !find_group(alice, from_erin), "not yet as a group invitation");
        auto reqs = alice.engine->requests();
        std::string accept_err;
        CHECK(reqs.size() == 1 && reqs[0].sender_fp == erin.fp && alice.engine->accept_request(erin.fp, "Erin", accept_err), "Alice accepts Erin as a contact (" + accept_err + ")");
        auto invite = find_invite(alice, from_erin);
        CHECK(invite && invite->title == "Erin's group" && invite->creator_name == "Erin", "then the invitation appears, from a contact");
        bool erin_verified = false;
        for (auto& chat : alice.engine->chats()) if (chat.contact_fp == erin.fp && chat.verified) erin_verified = true;
        CHECK(erin_verified && alice.engine->is_verified(erin.fp), "accepting the request counted as checking Erin's fingerprint: she is verified");
        CHECK(alice.engine->accept_group_invite(from_erin, err), "she accepts it (" + err + ")");
        erin.engine->send_group_text(from_erin, "Hello from Erin", err);
        alice.engine->send_group_text(from_erin, "Hello Erin", err);
        CHECK(wait_for([&] { return got(alice, from_erin, "Hello from Erin") && got(erin, from_erin, "Hello Erin"); }), "a group of two works both ways");
        users.erase("erin");
    }

    std::cout << "10. Things survive a restart\n";
    {
        std::string err, later;
        carol.engine->create_group("Pending across restart", {bob.fp}, later, err);  // Carol invites Bob...
        CHECK(wait_for([&] { return find_invite(bob, later).has_value(); }), "Bob has a pending invitation");
        const size_t before = bob.engine->group_messages(hiking).size();
        restart_engine(bob);
        CHECK(find_invite(bob, later).has_value() && find_group(bob, hiking) && bob.engine->group_messages(hiking).size() == before, "after Bob's app restarts the invitation, the group and its messages are still there");
        CHECK(overall(bob, hiking, "Bob here") == 3 && member_status(bob, hiking, "Bob here", alice.fp) == 3, "...with the delivery state of what he sent");
        CHECK(bob.engine->accept_group_invite(later, err), "he can still accept it afterwards");
        run_for(600);
        CHECK(bob.engine->group_messages(hiking).size() == before, "restarting doesn't duplicate anything");
    }

    std::cout << "11. A big group: introductions are split across envelopes\n";
    {
        // Free up the relay's attention: only Alice and the newcomers need to run now.
        for (const char* quiet : {"bob", "carol", "dave", "mallory"}) users[quiet]->engine.reset();
        std::vector<User*> crowd;
        for (int i = 1; i <= 8; i++) {
            User& u = make_user("e" + std::to_string(i));
            if (!setup_user_patiently(srv, u) || !give_card(alice, u, "Alice")) { std::cout << "FAIL could not set up " << u.name << "\n"; return 1; }
            // Alice needs a card from each of them too (to write to them).
            if (!give_card(u, alice, cap(u.name))) { std::cout << "FAIL no card from " << u.name << "\n"; return 1; }
            crowd.push_back(&u);
        }
        std::vector<std::string> everyone;
        for (User* u : crowd) everyone.push_back(u->fp);
        std::string err, big;
        CHECK(alice.engine->create_group("Everyone", everyone, big, err), "Alice invites eight people who are all her contacts and strangers to each other (" + err + ")");
        bool all_invited = wait_for([&] { for (User* u : crowd) if (!find_invite(*u, big)) return false; return true; }, 30000);
        CHECK(all_invited, "all eight are invited");
        // Each one's invitation lists Alice and seven strangers. Strangers are named only if their bundles
        // arrived, which takes two envelopes (6 per envelope) when 7 must be passed on.
        CHECK(wait_for([&] {
            for (User* u : crowd) {
                auto invite = find_invite(*u, big);
                if (!invite) return false;
                size_t named = 0;
                for (auto& mem : invite->members) if (mem.fp != alice.fp && !mem.is_contact && mem.name.size() == 2 && mem.name[0] == 'e') named++;
                if (invite->members.size() != 8 || named != 7) return false;
            }
            return true;
        }, 30000), "every invitation names all seven strangers: their bundles all arrived, split over two envelopes");
        for (User* u : crowd) u->engine->accept_group_invite(big, err);
        alice.engine->send_group_text(big, "hello all nine", err);
        CHECK(wait_for([&] { for (User* u : crowd) if (!got(*u, big, "hello all nine")) return false; return true; }, 30000), "a message from Alice reaches all eight");
        CHECK(wait_for([&] { return overall(alice, big, "hello all nine") == 2; }, 30000), "and becomes Delivered once every one of them has stored it");
        auto ds = alice.engine->group_delivery(big, outgoing_message(alice, big, "hello all nine")->message_id);
        CHECK(ds.size() == 8, "per-member delivery covers all eight");
        CHECK(wait_for([&] { for (User* u : crowd) { auto g = find_group(*u, big); if (!g || !g->ready) return false; } return true; }, 120000),
              "every one of the eight ends up able to write to all the others (56 tokens, each passed on through Alice)");
        crowd[0]->engine->send_group_text(big, "from e1 to everyone", err);
        CHECK(wait_for([&] { for (size_t i = 1; i < crowd.size(); i++) if (!got(*crowd[i], big, "from e1 to everyone")) return false; return got(alice, big, "from e1 to everyone"); }, 60000),
              "a message from one stranger reaches the other seven and Alice");
    }

    std::cout << "12. Groups don't disturb one-to-one chats\n";
    {
        for (const char* back : {"bob", "carol"}) restart_engine(*users[back]);
        std::string err;
        CHECK(bob.engine->send_text(alice.fp, "a private word", err), "Bob writes to Alice directly");
        CHECK(wait_for([&] {
            for (auto& msg : alice.engine->messages(bob.fp)) if (!msg.outgoing && msg.text == "a private word") return true;
            return false;
        }), "it arrives in their one-to-one chat");
        CHECK(!got(alice, hiking, "a private word") && !got(carol, hiking, "a private word"), "and in no group");
        CHECK(alice.engine->chats().size() >= 3, "the contact list of chats is unaffected by groups");
    }


    std::cout << "13. Passing things on through the creator: what it can see, and who may ask\n";
    {
        // Three strangers to each other, all Alice's contacts: e1 joins, e2 is offline, e3 is not in the group.
        User& frank = *users["e1"];
        User& gina = *users["e2"];
        User& outsider = *users["e3"];
        gina.engine.reset();
        outsider.engine.reset();
        std::string err, gid;
        CHECK(alice.engine->create_group("Forwarding", {frank.fp, gina.fp}, gid, err), "Alice makes a group with e1 and e2, who don't know each other (e2's app is closed)");
        const Bytes group_id = *hex_to_bytes(gid);
        const Bytes f = fp_raw(frank), g = fp_raw(gina);
        CHECK(wait_for([&] { return find_invite(frank, gid).has_value(); }, 30000) && frank.engine->accept_group_invite(gid, err), "e1 joins");

        // e1 now makes a token for e2 and sends it, sealed, to Alice. Alice deposits it in e2's mailbox. (Alice also
        // makes the group's archive and sends e2 its grant, so wait for both of those, not for a number of envelopes.)
        as(alice);
        const Bytes alice_kem = alice.keys->load_private_kem();
        as(gina);
        const Bytes gina_kem = gina.keys->load_private_kem();
        auto classify = [&](int& alice_can_open, int& gina_can_open, int& grants_from_frank, int& archive_grants, size_t& total) {
            auto envelopes = mailbox_envelopes(gina);
            total = envelopes.size();
            alice_can_open = gina_can_open = grants_from_frank = archive_grants = 0;
            for (auto& env : envelopes) {
                if (chat::open_envelope(env, alice_kem)) alice_can_open++;
                if (auto inner = chat::open_envelope(env, gina_kem)) {
                    gina_can_open++;
                    for (auto& raw : inner->records)
                        if (auto sr = chat::parse_record(raw)) {
                            if (sr->record.type == chat::RecordType::TokenGrant && sr->record.sender == f && sr->record.payload.size() == 32 && sr->record.conversation_id == group_id) grants_from_frank++;
                            if (sr->record.type == chat::RecordType::ArchiveGrant && sr->record.sender == a) archive_grants++;
                        }
                }
            }
        };
        int alice_can_open = 0, gina_can_open = 0, grants_from_frank = 0, archive_grants = 0;
        size_t total = 0;
        bool arrived = wait_for([&] { classify(alice_can_open, gina_can_open, grants_from_frank, archive_grants, total); return grants_from_frank == 1 && archive_grants == 1; }, 60000);
        CHECK(arrived, "e2's mailbox ends up holding Alice's invitation, the token e1 made for her, and the archive grant");
        classify(alice_can_open, gina_can_open, grants_from_frank, archive_grants, total);
        CHECK(alice_can_open == 0, "Alice, who passed it on, cannot open any of what is in e2's mailbox: everything is sealed to e2 alone");
        CHECK(gina_can_open == static_cast<int>(total) && grants_from_frank == 1, "e2 can open all of it, and one is a 32-byte send token signed by e1 for this group");

        // Who may ask Alice to deposit something? Only a member, for another member, in a group Alice made.
        auto forward = [&](User& signer, const Bytes& target, const Bytes& group, const std::vector<Bytes>& members, const Bytes& sealed) {
            chat::Record r = base_record(group, chat::recipients_hash_for(members), chat::RecordType::Forward);
            r.payload = chat::forward_payload(target, sealed);
            chat::Inner in;
            in.records = {sign_as(signer, r)};
            return in;
        };
        as(gina);
        chat::Inner junk;
        junk.records = {Bytes(10, 1)};
        const Bytes sealed = chat::seal_envelope(junk, gina.keys->load_public_kem());  // content doesn't matter: Alice deposits it unread
        const std::vector<Bytes> trio = {a, f, g};

        const size_t gina_before = mailbox_envelopes(gina).size();
        const size_t outsider_before = mailbox_envelopes(outsider).size();
        CHECK(send_envelope(alice, token_for(frank, alice), forward(frank, g, group_id, trio, sealed)), "(setup) e1 asks Alice to pass an envelope to e2");
        CHECK(wait_for([&] { return mailbox_envelopes(gina).size() == gina_before + 1; }, 30000), "a member asking for another member: Alice deposits it in e2's mailbox");
        const size_t gina_after = mailbox_envelopes(gina).size();

        send_envelope(alice, token_for(frank, alice), forward(frank, fp_raw(outsider), group_id, trio, sealed));
        run_for(2500);
        CHECK(mailbox_envelopes(outsider).size() == outsider_before, "asking for someone who is not in the group: nothing is deposited for them");

        // Only the group's creator passes things on. Bob can write to Carol (they are contacts), so if he
        // obeyed a Forward from Alice, an envelope would show up in Carol's mailbox.
        carol.engine.reset();
        as(carol);
        chat::Inner for_carol;
        for_carol.records = {Bytes(10, 1)};
        const Bytes sealed_for_carol = chat::seal_envelope(for_carol, carol.keys->load_public_kem());
        const size_t carol_before = mailbox_envelopes(carol).size();
        send_envelope(bob, token_for(alice, bob), forward(alice, c, *hex_to_bytes(hiking), {a, b, c}, sealed_for_carol));
        run_for(2500);
        CHECK(mailbox_envelopes(carol).size() == carol_before, "asking a member who did not make the group to pass something on does nothing, even though he could reach the target");
        restart_engine(carol);

        send_envelope(alice, token_for(frank, alice), forward(frank, f, group_id, trio, sealed));
        run_for(2500);
        CHECK(mailbox_envelopes(gina).size() == gina_after && mailbox_envelopes(outsider).size() == outsider_before, "a member asking Alice to deposit something for themselves does nothing either");
    }

    std::cout << "14. A flood of invitations is bounded\n";
    {
        for (auto& inv : bob.engine->group_invites()) bob.engine->decline_group_invite(inv.id);
        const Bytes ids_for_bob_hash = chat::recipients_hash_for({a, b, c});
        for (int i = 0; i < 55; i++) {
            chat::Inner in;
            in.records = {creation_record(alice, CryptoEngine::random_bytes(16), "Flood " + std::to_string(i), {a, b, c}, ids_for_bob_hash)};
            send_envelope(bob, token_for(alice, bob), in);
        }
        CHECK(wait_for([&] { return bob.engine->group_invites().size() == 50; }, 60000), "55 invitations from one contact: Bob keeps 50");
        run_for(2000);
        CHECK(bob.engine->group_invites().size() == 50, "and the rest are dropped, not queued up behind them");
        for (auto& inv : bob.engine->group_invites()) bob.engine->decline_group_invite(inv.id);
        CHECK(bob.engine->group_invites().empty(), "(cleaned up)");
    }


    std::cout << "15. A member vouches for a friend from the app\n";
    {
        std::string text, err;
        CHECK(alice.engine->create_relay_invite(text, err), "Alice makes an invite for a friend (" + err + ")");
        auto invite = parse_relay_invite(text);
        CHECK(invite && invite->relay_id == RELAY_ID && invite->server.port == PORT && invite->invite.size() == 16, "it names this relay: its pinned identity and address");
        User& newbie = make_user("newbie");
        bool joined = false;
        for (int attempt = 0; attempt < 40 && invite && !joined; attempt++) {
            joined = newbie.engine->setup(*invite, err);
            if (!joined) run_for(2000);  // the relay limits registrations per minute; a refused try doesn't burn the invite
        }
        CHECK(joined && newbie.engine->is_set_up(), "the friend sets up messaging with it");
        User& late = make_user("late");
        std::string reuse_err;
        CHECK(!late.engine->setup(*invite, reuse_err) && has(reuse_err, "used"), "and nobody else can use the same invite: " + reuse_err);
        MessagingEngine::RelayInviteStatus status;
        CHECK(alice.engine->relay_invite_status(status, err) && status.max_unused == 3 && status.max_total == 10 && status.unused.empty() && status.joined.size() == 1 &&
                  status.joined[0].mailbox.size() == 8,
              "Alice sees the relay's limits, no unused invites, and that one person joined through her");
        std::string spare;
        CHECK(alice.engine->create_relay_invite(spare, err) && alice.engine->relay_invite_status(status, err) && status.unused.size() == 1, "a new invite shows up as unused");
        auto spare_invite = parse_relay_invite(spare);
        const std::string spare_id = status.unused.empty() ? std::string() : status.unused[0].id;
        CHECK(alice.engine->cancel_relay_invite(spare_id, err) && alice.engine->relay_invite_status(status, err) && status.unused.empty(), "cancelling it removes it");
        CHECK(!alice.engine->cancel_relay_invite(spare_id, err) && has(err, "isn't one of your"), "cancelling it again says so: " + err);
        CHECK(!alice.engine->cancel_relay_invite("not hex", err), "a nonsense ID is refused before asking the relay");
        User& cancelled = make_user("cancelled");
        std::string cancel_err;
        CHECK(spare_invite && !cancelled.engine->setup(*spare_invite, cancel_err) && has(cancel_err, "used"), "the cancelled invite can't be used: " + cancel_err);
        users.erase("cancelled");
        int made = 0;
        std::string last_err;
        for (int i = 0; i < 5; i++) {
            std::string t;
            if (alice.engine->create_relay_invite(t, last_err)) made++;
            else break;
        }
        CHECK(made == 3 && has(last_err, "3 unused"), "by default a member may have 3 unused invites at once (made " + std::to_string(made) + "): " + last_err);
        users.erase("newbie");
        users.erase("late");
    }


    std::cout << "16. Chat archives made by hand, and hostile grants\n";
    {
        std::string err;
        const std::string relay_address = "127.0.0.1:" + std::to_string(PORT);
        auto text_record = [&](User& signer, const Bytes& conv, const std::vector<Bytes>& everyone, const std::string& body) {
            chat::Record r = base_record(conv, chat::recipients_hash_for(everyone), chat::RecordType::Text);
            r.payload.assign(body.begin(), body.end());
            return sign_as(signer, r);
        };
        auto grant_inner = [&](User& signer, const Bytes& conv, const std::vector<Bytes>& everyone, const Bytes& key, const Bytes& token) {
            chat::ArchiveGrantInfo info;
            info.relay_address = relay_address;
            info.relay_id = RELAY_ID;
            info.archive_key = key;
            info.join_token = token;
            chat::Record r = base_record(conv, chat::recipients_hash_for(everyone), chat::RecordType::ArchiveGrant);
            r.payload = chat::archive_grant_payload(info);
            chat::Inner in;
            in.records = {sign_as(signer, r)};
            return in;
        };

        // --- A one-to-one chat. Its archive was made automatically (the smaller fingerprint's job); here we use it by hand. ---
        User& maker = alice.fp < bob.fp ? alice : bob;
        User& other = alice.fp < bob.fp ? bob : alice;
        const std::string direct = *maker.engine->direct_conversation_id(other.fp);
        const Bytes direct_id = *hex_to_bytes(direct);
        CHECK(direct == *other.engine->direct_conversation_id(maker.fp), "both sides agree on the chat's ID");
        CHECK(wait_for([&] { return maker.engine->archive_status(direct).joined && other.engine->archive_status(direct).joined; }, 30000),
              "the chat already has an archive, made by the smaller fingerprint, and both have joined");
        auto made = maker.engine->archive_status(direct);
        CHECK(made.exists && made.is_creator && made.relay == relay_address && !other.engine->archive_status(direct).is_creator, "one is its maker and the other a member, on the maker's relay");
        CHECK(!other.engine->create_archive(direct, err) && has(err, "Someone else"), "the person with the larger fingerprint can't make it: " + err);
        CHECK(!maker.engine->create_archive(direct, err) && has(err, "already has"), "making it again is refused: " + err);
        CHECK(!maker.engine->create_archive(std::string(32, 'a'), err) && has(err, "isn't in your list"), "nor can one be made for a chat that doesn't exist: " + err);

        // Settle: catch both up, so what follows is exactly what this test adds.
        std::vector<MessagingEngine::ArchivedRecord> fresh, others;
        maker.engine->archive_sync(direct, fresh, err);
        other.engine->archive_sync(direct, fresh, err);
        const uint64_t base = maker.engine->archive_status(direct).entries;
        const std::vector<Bytes> pair = {a, b};
        uint64_t n = 0;
        Bytes r1 = text_record(maker, direct_id, pair, "first, in the archive");
        CHECK(maker.engine->archive_append(direct, r1, n, others, err) && n == base + 1 && others.empty(), "the maker appends an entry (" + err + ")");
        CHECK(other.engine->archive_sync(direct, fresh, err) && fresh.size() == 1 && fresh[0].number == base + 1 && fresh[0].record == r1, "the other person fetches it: checked, decrypted, and the same record");
        Bytes r2 = text_record(other, direct_id, pair, "second, from the other person");
        CHECK(other.engine->archive_append(direct, r2, n, others, err) && n == base + 2 && others.empty(), "they append the next");
        CHECK(maker.engine->archive_sync(direct, fresh, err) && fresh.size() == 1 && fresh[0].number == base + 2 && fresh[0].record == r2, "the maker sees it");

        // Both write without looking first: the later one finds out, catches up, and goes on top.
        Bytes r3 = text_record(maker, direct_id, pair, "third, from the maker");
        Bytes r4 = text_record(other, direct_id, pair, "fourth, written without seeing the third");
        CHECK(maker.engine->archive_append(direct, r3, n, others, err) && n == base + 3, "the maker appends another");
        CHECK(other.engine->archive_append(direct, r4, n, others, err) && n == base + 4 && others.size() == 1 && others[0].number == base + 3 && others[0].record == r3,
              "the other person's append was behind: it caught up on the maker's, handed it over, and landed on top");
        CHECK(maker.engine->archive_sync(direct, fresh, err) && fresh.size() == 1 && fresh[0].record == r4, "and the maker's view is one chain");
        CHECK(maker.engine->archive_sync(direct, fresh, err) && fresh.empty() && other.engine->archive_sync(direct, fresh, err) && fresh.empty(), "when nothing is new, nothing comes back");
        CHECK(maker.engine->archive_status(direct).entries == base + 4 && other.engine->archive_status(direct).entries == base + 4, "both devices agree on how long the chat is");
        CHECK(!maker.engine->archive_append(std::string(32, 'b'), r1, n, others, err) && has(err, "no archive"), "appending to a chat with no archive is refused: " + err);
        CHECK(!maker.engine->archive_append(direct, Bytes(), n, others, err), "an empty record is refused");

        // --- A group whose archive is made by hand: Alice's automatic creation is held off while it is set up ---
        g_archive_check_seconds = 3600;
        restart_engine(alice);
        std::string manual;
        CHECK(alice.engine->create_group("Archive test", {bob.fp, carol.fp}, manual, err), "(Alice makes a group, with her own archive creation paused)");
        CHECK(wait_for([&] { return find_invite(bob, manual) && find_invite(carol, manual); }), "(Bob and Carol are invited)");
        CHECK(bob.engine->accept_group_invite(manual, err) && carol.engine->accept_group_invite(manual, err), "(and join)");
        const Bytes group_id = *hex_to_bytes(manual);
        const std::vector<Bytes> trio = {a, b, c};

        // A member who is not the creator tries to hand Bob an archive of their own.
        send_envelope(bob, token_for(carol, bob), grant_inner(carol, group_id, trio, CryptoEngine::random_bytes(32), CryptoEngine::random_bytes(32)));
        run_for(1500);
        CHECK(!bob.engine->archive_status(manual).exists, "a grant from a member who didn't make the group is ignored");
        send_envelope(bob, token_for(alice, bob), grant_inner(alice, *hex_to_bytes(std::string(32, 'c')), trio, CryptoEngine::random_bytes(32), CryptoEngine::random_bytes(32)));
        run_for(1000);
        CHECK(!bob.engine->archive_status(std::string(32, 'c')).exists, "a grant for a chat Bob has never heard of is ignored");

        CHECK(!bob.engine->create_archive(manual, err) && has(err, "Someone else"), "a member who didn't make the group can't make its archive: " + err);
        CHECK(alice.engine->create_archive(manual, err), "the group's creator makes it (" + err + ")");
        CHECK(wait_for([&] { return bob.engine->archive_status(manual).joined && carol.engine->archive_status(manual).joined; }, 30000), "Bob and Carol each receive their own grant and join");

        Bytes g1 = text_record(alice, group_id, trio, "welcome, archived");
        CHECK(alice.engine->archive_append(manual, g1, n, others, err) && n == 1, "Alice appends");
        CHECK(bob.engine->archive_sync(manual, fresh, err) && fresh.size() == 1 && fresh[0].record == g1 && carol.engine->archive_sync(manual, fresh, err) && fresh.size() == 1 && fresh[0].record == g1,
              "Bob and Carol both read it");
        // A second grant, from the real creator, with a different key: a replay must not change what Bob holds.
        send_envelope(bob, token_for(alice, bob), grant_inner(alice, group_id, trio, CryptoEngine::random_bytes(32), CryptoEngine::random_bytes(32)));
        run_for(1500);
        Bytes g2 = text_record(carol, group_id, trio, "from Carol, after a replayed grant");
        CHECK(carol.engine->archive_append(manual, g2, n, others, err) && n == 2, "Carol appends");
        CHECK(bob.engine->archive_sync(manual, fresh, err) && fresh.size() == 1 && fresh[0].record == g2, "Bob still reads it: the replayed grant did not replace his archive key");
        Bytes g3 = text_record(bob, group_id, trio, "Bob, at the same time as Carol");
        Bytes g4 = text_record(carol, group_id, trio, "Carol, at the same time as Bob");
        CHECK(bob.engine->archive_append(manual, g3, n, others, err) && n == 3 && carol.engine->archive_append(manual, g4, n, others, err) && n == 4 && others.size() == 1 && others[0].record == g3,
              "two members writing at once end up in one order, the second catching up on the first");
        CHECK(alice.engine->archive_sync(manual, fresh, err) && fresh.size() == 3 && fresh[0].number == 2 && fresh[2].number == 4 && alice.engine->archive_status(manual).entries == 4,
              "Alice, who was away, catches up on all three in order");
        CHECK(!file_contains(alice.history(), "welcome, archived") && !file_contains(fs::path(alice.history().string() + "-wal"), "welcome, archived"), "(an archived record's text is not readable in the history file)");

        g_archive_check_seconds = 1;
        restart_engine(alice);
    }

    std::cout << "17. Archives in everyday use\n";
    {
        std::string err;
        // The Hiking group was made long ago, with no special care: its archive was made automatically.
        CHECK(wait_for([&] { return alice.engine->archive_status(hiking).joined && bob.engine->archive_status(hiking).joined && carol.engine->archive_status(hiking).joined; }, 30000),
              "a group's archive is made by its creator without being asked, and every member joins");
        auto status = alice.engine->archive_status(hiking);
        CHECK(status.is_creator && !bob.engine->archive_status(hiking).is_creator && status.warning.empty(), "(Alice made it, nobody has a warning)");
        CHECK(wait_for([&] { return alice.engine->archive_status(hiking).entries >= 1 && bob.engine->archive_status(hiking).entries >= 1 && carol.engine->archive_status(hiking).entries >= 1; }, 30000),
              "its first entry is the group's creation record, and every member has checked it");

        const uint64_t before = alice.engine->archive_status(hiking).entries;
        CHECK(alice.engine->send_group_text(hiking, "this one is archived too", err), "Alice sends a message in the group");
        CHECK(wait_for([&] { return got(bob, hiking, "this one is archived too") && got(carol, hiking, "this one is archived too"); }), "it is delivered as always, by envelope");
        CHECK(wait_for([&] { return alice.engine->archive_status(hiking).entries >= before + 1; }, 30000), "and it is added to the archive");
        CHECK(wait_for([&] { return bob.engine->archive_status(hiking).entries >= before + 1; }, 30000), "where the others' devices see the chain grow");
        CHECK(incoming_count(bob, hiking, "this one is archived too") == 1, "(and reading it from the archive did not add it a second time)");

        // A message that never arrives by envelope still turns up, from the archive.
        carol.engine.reset();
        CHECK(alice.engine->send_group_text(hiking, "only the archive will bring this one", err), "Alice writes while Carol's app is closed");
        CHECK(wait_for([&] { return got(bob, hiking, "only the archive will bring this one") && alice.engine->archive_status(hiking).entries >= before + 2; }, 30000), "Bob gets it, and it reaches the archive");
        CHECK(empty_mailbox(carol) >= 1, "(Carol's copy is lost on the way: everything waiting in her mailbox is thrown away)");
        restart_engine(carol);
        CHECK(wait_for([&] { return got(carol, hiking, "only the archive will bring this one"); }, 30000), "when Carol's app starts it finds the message in the archive");
        CHECK(incoming_count(carol, hiking, "only the archive will bring this one") == 1, "exactly once");
        bool genuine = false;
        for (auto& m : carol.engine->group_messages(hiking)) if (m.text == "only the archive will bring this one" && m.sender_fp == alice.fp && m.sender_name == "Alice") genuine = true;
        CHECK(genuine, "and as Alice's: it carried her signature, checked as for any message");

        // Checkpoints: after a few entries each member signs where they have got to.
        for (int i = 1; i <= 7; i++) alice.engine->send_group_text(hiking, "filler " + std::to_string(i), err);
        CHECK(wait_for([&] { return bob.engine->archive_status(hiking).checkpoint_seen > 0 && carol.engine->archive_status(hiking).checkpoint_seen > 0; }, 60000),
              "after enough entries, other members' signed checkpoints appear in the archive and are seen");
        CHECK(bob.engine->archive_status(hiking).warning.empty() && carol.engine->archive_status(hiking).warning.empty() && alice.engine->archive_status(hiking).warning.empty(), "all of which agree with the relay's copy: no warnings");

        // The relay drops the end of the log.
        wait_for([&] { return alice.engine->archive_status(hiking).entries == bob.engine->archive_status(hiking).entries && bob.engine->archive_status(hiking).entries == carol.engine->archive_status(hiking).entries; }, 30000);
        const uint64_t head = bob.engine->archive_status(hiking).entries;
        const std::string id_hex = hiking;
        const std::string literal = hex_literal(*hex_to_bytes(id_hex));
        const uint64_t keep = head - 3;
        sql_exec(ROOT / "relay-data/s/v3/relay.db",
                 "DELETE FROM archive_entries WHERE archive_id = " + literal + " AND number > " + std::to_string(keep) + ";"
                 "UPDATE archives SET head_number = " + std::to_string(keep) + ", head_hash = (SELECT hash FROM archive_entries WHERE archive_id = " + literal + " AND number = " + std::to_string(keep) + ") WHERE id = " + literal + ";");
        CHECK(wait_for([&] { return !bob.engine->archive_status(hiking).warning.empty() && !carol.engine->archive_status(hiking).warning.empty() && !alice.engine->archive_status(hiking).warning.empty(); }, 60000),
              "a relay that drops the end of the log is caught by the next catch-up: every member is warned");
        CHECK(has(bob.engine->archive_status(hiking).warning, "different end"), "(" + bob.engine->archive_status(hiking).warning + ")");
        CHECK(any_notice(bob, "Warning about a chat's archive"), "Bob is told in words");
        std::string e2;
        CHECK(bob.engine->send_group_text(hiking, "chatting still works", e2) && wait_for([&] { return got(alice, hiking, "chatting still works") && got(carol, hiking, "chatting still works"); }, 30000),
              "and messages still flow by envelope: a damaged archive never stops the chat");
    }

    srv.stop();
    std::error_code ec;
    fs::remove_all(ROOT, ec);
    std::cout << (failures ? "\nFAILURES: " : "\nAll checks passed. ") << failures << "\n";
    return failures ? 1 : 0;
}
