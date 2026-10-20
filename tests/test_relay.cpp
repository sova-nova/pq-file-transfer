// Integration tests for the v3 mailbox relay: a real pq-server process, the real RelayClient,
// and a scripted hostile relay. POSIX only (fork/exec, popen).
// Usage: test_relay /path/to/pq-server
#include "crypto_engine.h"
#include "messages.h"
#include "platform.h"
#include "protocol.h"
#include "relay_client.h"
#include "relay_protocol.h"
#include "sharing.h"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <set>
#include <thread>
#include <tuple>

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

static bool has(const std::string& s, const std::string& needle) { return s.find(needle) != std::string::npos; }
static void sleep_ms(int ms) { std::this_thread::sleep_for(std::chrono::milliseconds(ms)); }

static std::string SERVER_BIN;
static fs::path ROOT;

// --- A relay process under test ---

struct Server {
    int port = 0;
    fs::path storage;
    std::vector<std::string> extra;
    pid_t pid = -1;

    bool start() {
        pid = fork();
        if (pid == 0) {
            int log = open((storage.parent_path() / (storage.filename().string() + ".log")).c_str(), O_WRONLY | O_CREAT | O_APPEND, 0600);
            if (log >= 0) { dup2(log, 1); dup2(log, 2); }
            std::vector<std::string> args = {SERVER_BIN, "--port", std::to_string(port), "--bind", "127.0.0.1", "--storage", storage.string(), "--sweep-seconds", "1"};
            args.insert(args.end(), extra.begin(), extra.end());
            std::vector<char*> argv;
            for (auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
            argv.push_back(nullptr);
            execv(SERVER_BIN.c_str(), argv.data());
            _exit(127);
        }
        for (int i = 0; i < 100; i++) {
            addrinfo hints{}, *ai = nullptr;
            hints.ai_socktype = SOCK_STREAM;
            getaddrinfo("127.0.0.1", std::to_string(port).c_str(), &hints, &ai);
            int s = socket(ai->ai_family, ai->ai_socktype, 0);
            bool ok = s >= 0 && connect(s, ai->ai_addr, ai->ai_addrlen) == 0;
            if (s >= 0) close(s);
            freeaddrinfo(ai);
            if (ok) return true;
            sleep_ms(50);
        }
        return false;
    }
    void stop() {
        if (pid > 0) { kill(pid, SIGTERM); waitpid(pid, nullptr, 0); pid = -1; }
    }
    // Asks the relay's own CLI for a fresh single-use invite.
    std::optional<RelayInvite> invite() {
        std::string cmd = "\"" + SERVER_BIN + "\" --storage \"" + storage.string() + "\" --create-invite --public-address 127.0.0.1:" +
                          std::to_string(port) + " 2>&1";
        FILE* p = popen(cmd.c_str(), "r");
        if (!p) return std::nullopt;
        std::string out;
        char buf[512];
        while (fgets(buf, sizeof(buf), p)) out += buf;
        pclose(p);
        size_t at = out.find("pqft-relay://");
        if (at == std::string::npos) return std::nullopt;
        return parse_relay_invite(out.substr(at, out.find('\n', at) - at));
    }
    ~Server() { stop(); }
};

// --- A mailbox as a client holds it ---

struct Box {
    Bytes id, token;
    CryptoEngine::SigKeyPair access;
};

static std::string host() { return "127.0.0.1"; }

static bool connect_to(RelayClient& c, const Server& s, const Bytes& pin, std::string& err) {
    return c.connect(host(), static_cast<uint16_t>(s.port), pin, 5, err);
}

static std::optional<Box> make_box(Server& s, const Bytes& pin) {
    auto invite = s.invite();
    if (!invite) return std::nullopt;
    Box b{CryptoEngine::random_bytes(16), CryptoEngine::random_bytes(32), CryptoEngine::generate_sig_keypair()};
    RelayClient c;
    std::string err;
    if (!connect_to(c, s, pin, err) || !c.register_mailbox(invite->invite, b.id, b.access, b.token, err)) {
        std::cout << "  (make_box failed: " << err << ")\n";
        return std::nullopt;
    }
    return b;
}

static bool sign_in(RelayClient& c, const Server& s, const Bytes& pin, const Box& b, std::string& err) {
    return connect_to(c, s, pin, err) && c.authenticate(b.id, b.access.private_key, err);
}

static Bytes payload_of(uint8_t fill, size_t size = 200) { return Bytes(size, fill); }

// Collects until the end of the backlog; returns the envelopes seen.
static std::vector<relay::StoredEnvelope> drain(RelayClient& c, int timeout_ms = 3000) {
    std::vector<relay::StoredEnvelope> out;
    std::string err;
    if (!c.collect(err)) return out;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        auto e = c.next_event(200);
        if (e.kind == RelayClient::Event::Kind::Envelope) out.push_back(e.envelope);
        else if (e.kind == RelayClient::Event::Kind::CollectEnd || e.kind == RelayClient::Event::Kind::Closed) break;
    }
    return out;
}

// --- Raw access, for sending things a well-behaved client never would ---

struct Raw {
    socket_t s = INVALID_SOCKET_VAL;
    Bytes challenge;
    ~Raw() { if (s != INVALID_SOCKET_VAL) close_socket(s); }

    bool open(const Server& srv) {
        addrinfo hints{}, *ai = nullptr;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo("127.0.0.1", std::to_string(srv.port).c_str(), &hints, &ai) != 0) return false;
        s = socket(ai->ai_family, ai->ai_socktype, 0);
        bool ok = s != INVALID_SOCKET_VAL && connect(s, ai->ai_addr, ai->ai_addrlen) == 0;
        freeaddrinfo(ai);
        if (ok) set_socket_timeouts(s, 5);
        return ok;
    }
    bool hello() {
        relay::Hello h;
        h.client_nonce = CryptoEngine::random_bytes(relay::NONCE_BYTES);
        if (!send_message(s, MessageType::RELAY_HELLO, relay::encode(h))) return false;
        auto m = recv_message(s, relay::MAX_MESSAGE_PAYLOAD);
        if (!m || m->type != MessageType::RELAY_HELLO_REPLY) return false;
        auto r = relay::decode_hello_reply(m->payload);
        if (!r) return false;
        challenge = r->auth_challenge;
        return true;
    }
    // The relay's next answer as text ("" if it hung up).
    std::string answer() {
        auto m = recv_message(s, relay::MAX_MESSAGE_PAYLOAD);
        if (!m) return "";
        if (m->type == MessageType::ERROR_MSG) return std::string(m->payload.begin(), m->payload.end());
        return "type " + std::to_string(static_cast<int>(m->type));
    }
};

static bool server_alive(Server& s, const Bytes& pin) {
    RelayClient c;
    std::string err;
    return connect_to(c, s, pin, err);
}

// =====================================================================================
// Part 1: the real relay
// =====================================================================================

static void test_real_relay() {
    Server main_srv{20100 + static_cast<int>(getpid() % 5000) * 2, ROOT / "relay-main", {"--mailbox-quota-kib", "256", "--rate-limit", "10000"}};
    if (!main_srv.start()) { std::cout << "FAIL could not start the relay\n"; failures++; return; }

    auto first_invite = main_srv.invite();
    CHECK(first_invite && first_invite->relay_id.size() == 32 && first_invite->invite.size() == 16, "the relay prints a parseable invite string");
    if (!first_invite) return;
    Bytes pin = first_invite->relay_id;
    std::string err;

    std::cout << "0. A relay that isn't running\n";
    {
        // Find a port nothing is listening on.
        int probe = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        bind(probe, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        socklen_t len = sizeof(addr);
        getsockname(probe, reinterpret_cast<sockaddr*>(&addr), &len);
        uint16_t closed_port = ntohs(addr.sin_port);
        close(probe);

        RelayClient c;
        std::string e;
        bool ok = c.connect("127.0.0.1", closed_port, {}, 3, e);
        CHECK(!ok && has(e, "127.0.0.1:" + std::to_string(closed_port)), "the message names the address that was tried: " + e);
        CHECK(has(e, "nothing is listening") && has(e, "Is the relay running"), "a refused connection says so and suggests the likely cause");
        CHECK(has(e, "address and port"), "and what else to check");
    }

    std::cout << "1. Relay identity\n";
    {
        RelayClient c;
        CHECK(connect_to(c, main_srv, pin, err) && c.relay_id() == pin, "connecting with the right pinned relay ID works (" + err + ")");
        RelayClient wrong;
        Bytes other = pin; other[0] ^= 1;
        CHECK(!connect_to(wrong, main_srv, other, err) && has(err, "does not match"), "a different pinned ID is refused: " + err);
        RelayClient first_contact;
        CHECK(connect_to(first_contact, main_srv, {}, err) && first_contact.relay_id() == pin, "with no pin the relay is accepted and reports its ID for the user to compare");
    }

    std::cout << "2. Registration and invites\n";
    {
        RelayClient c;
        Box b{CryptoEngine::random_bytes(16), CryptoEngine::random_bytes(32), CryptoEngine::generate_sig_keypair()};
        connect_to(c, main_srv, pin, err);
        CHECK(!c.register_mailbox(CryptoEngine::random_bytes(16), b.id, b.access, b.token, err) && has(err, "invite"), "a made-up invite is refused: " + err);

        RelayClient c2;
        connect_to(c2, main_srv, pin, err);
        CHECK(c2.register_mailbox(first_invite->invite, b.id, b.access, b.token, err), "a real invite creates a mailbox (" + err + ")");

        RelayClient c3;
        Box b2{CryptoEngine::random_bytes(16), CryptoEngine::random_bytes(32), CryptoEngine::generate_sig_keypair()};
        connect_to(c3, main_srv, pin, err);
        CHECK(!c3.register_mailbox(first_invite->invite, b2.id, b2.access, b2.token, err) && has(err, "invite"), "the same invite can't be used twice: " + err);

        auto second = main_srv.invite();
        RelayClient c4;
        connect_to(c4, main_srv, pin, err);
        CHECK(!c4.register_mailbox(second->invite, b.id, b2.access, b2.token, err) && has(err, "already exists"), "an existing mailbox ID is refused: " + err);
        RelayClient c5;
        connect_to(c5, main_srv, pin, err);
        CHECK(c5.register_mailbox(second->invite, b2.id, b2.access, b2.token, err), "...and that failed attempt did not use up the invite (" + err + ")");

        // Registering someone else's access key without holding its private half.
        auto third = main_srv.invite();
        auto victim = CryptoEngine::generate_sig_keypair();
        auto attacker = CryptoEngine::generate_sig_keypair();
        Box fake{CryptoEngine::random_bytes(16), CryptoEngine::random_bytes(32), {victim.public_key, attacker.private_key}};
        RelayClient c6;
        connect_to(c6, main_srv, pin, err);
        CHECK(!c6.register_mailbox(third->invite, fake.id, fake.access, fake.token, err) && has(err, "proof"), "registering a key you don't hold is refused: " + err);
    }

    auto alice = make_box(main_srv, pin);
    auto bob = make_box(main_srv, pin);
    auto mallory = make_box(main_srv, pin);
    if (!alice || !bob || !mallory) { std::cout << "FAIL test setup\n"; failures++; return; }

    std::cout << "3. Authentication\n";
    {
        RelayClient c;
        CHECK(sign_in(c, main_srv, pin, *alice, err), "the owner signs in (" + err + ")");

        RelayClient wrong_key;
        connect_to(wrong_key, main_srv, pin, err);
        CHECK(!wrong_key.authenticate(alice->id, mallory->access.private_key, err) && has(err, "Authentication failed"), "signing in as Alice with Mallory's key fails: " + err);
        CHECK(!wrong_key.connected(), "...and the connection is dropped");

        RelayClient unknown;
        connect_to(unknown, main_srv, pin, err);
        CHECK(!unknown.authenticate(CryptoEngine::random_bytes(16), alice->access.private_key, err) && has(err, "Authentication failed"), "an unknown mailbox can't sign in: " + err);

        // A signature made for another relay's ID must not work here.
        Raw r;
        r.open(main_srv); r.hello();
        Bytes other_relay = pin; other_relay[5] ^= 0x40;
        relay::Auth a{alice->id, CryptoEngine::sign(relay::auth_signing_input(r.challenge, other_relay, alice->id), alice->access.private_key)};
        send_message(r.s, MessageType::RELAY_AUTH, relay::encode(a));
        CHECK(has(r.answer(), "Authentication failed"), "a signature bound to a different relay ID is rejected");

        // Replaying a genuine signature from an earlier session must not work either.
        Raw first;
        first.open(main_srv); first.hello();
        relay::Auth good{alice->id, CryptoEngine::sign(relay::auth_signing_input(first.challenge, pin, alice->id), alice->access.private_key)};
        send_message(first.s, MessageType::RELAY_AUTH, relay::encode(good));
        CHECK(first.answer() == "type " + std::to_string(static_cast<int>(MessageType::RELAY_AUTH_OK)), "(sanity) the genuine signature is accepted in its own session");
        Raw second;
        second.open(main_srv); second.hello();
        send_message(second.s, MessageType::RELAY_AUTH, relay::encode(good));
        CHECK(has(second.answer(), "Authentication failed"), "the same signature replayed in a new session is rejected (fresh challenge each time)");

        Raw twice;
        twice.open(main_srv); twice.hello();
        relay::Auth bad{alice->id, CryptoEngine::random_bytes(3309)};
        send_message(twice.s, MessageType::RELAY_AUTH, relay::encode(bad));
        twice.answer();
        CHECK(twice.answer().empty(), "after one failed attempt the connection is closed, so signatures can't be ground through");
    }

    std::cout << "4. Depositing\n";
    {
        RelayClient sender;
        connect_to(sender, main_srv, pin, err);
        Bytes id1;
        CHECK(sender.deposit(alice->id, alice->token, payload_of(1), 3600, &id1, err) && id1.size() == 16, "a valid send token deposits (" + err + ")");

        std::string wrong_token_err, unknown_box_err;
        RelayClient s2; connect_to(s2, main_srv, pin, err);
        CHECK(!s2.deposit(alice->id, CryptoEngine::random_bytes(32), payload_of(2), 3600, nullptr, wrong_token_err) && has(wrong_token_err, "Unknown mailbox or token"), "a wrong token is refused: " + wrong_token_err);
        RelayClient s3; connect_to(s3, main_srv, pin, err);
        s3.deposit(CryptoEngine::random_bytes(16), alice->token, payload_of(2), 3600, nullptr, unknown_box_err);
        CHECK(wrong_token_err == unknown_box_err, "a missing mailbox gives exactly the same answer, so mailbox IDs can't be probed");

        RelayClient s4; connect_to(s4, main_srv, pin, err);
        CHECK(!s4.deposit(alice->id, alice->token, payload_of(3), 0, nullptr, err) && has(err, "lifetime"), "a zero lifetime is refused: " + err);
        RelayClient s5; connect_to(s5, main_srv, pin, err);
        CHECK(!s5.deposit(alice->id, alice->token, Bytes(relay::MAX_ENVELOPE_BYTES + 1), 3600, nullptr, err), "an oversized envelope is refused by the client: " + err);

        Raw big;
        big.open(main_srv); big.hello();
        relay::Deposit d{alice->id, alice->token, Bytes(relay::MAX_ENVELOPE_BYTES + 1, 9), 3600};
        send_message(big.s, MessageType::RELAY_DEPOSIT, relay::encode(d));
        CHECK(has(big.answer(), "Malformed"), "...and by the relay if a hostile client sends one anyway");
        CHECK(server_alive(main_srv, pin), "the relay is unaffected");

        // Fill Bob's mailbox to its 256 KiB quota with 60 KiB envelopes.
        std::string full_err;
        int stored = 0;
        for (int i = 0; i < 6; i++) {
            RelayClient s; connect_to(s, main_srv, pin, err);
            if (s.deposit(bob->id, bob->token, payload_of(static_cast<uint8_t>(i), 60 * 1024), 3600, nullptr, full_err)) stored++;
            else break;
        }
        CHECK(stored == 4 && has(full_err, "full"), "a mailbox accepts deposits up to its quota, then says it is full (" + std::to_string(stored) + " stored)");
        RelayClient owner;
        sign_in(owner, main_srv, pin, *bob, err);
        auto all = drain(owner);
        std::vector<Bytes> ids;
        for (auto& e : all) ids.push_back(e.id);
        size_t deleted = 0;
        owner.acknowledge(ids, &deleted, err);
        RelayClient s6; connect_to(s6, main_srv, pin, err);
        CHECK(deleted == 4 && s6.deposit(bob->id, bob->token, payload_of(7, 60 * 1024), 3600, nullptr, err), "acknowledging frees the space (" + err + ")");
        RelayClient owner2; sign_in(owner2, main_srv, pin, *bob, err);
        auto leftover = drain(owner2);
        std::vector<Bytes> ids2; for (auto& e : leftover) ids2.push_back(e.id);
        owner2.acknowledge(ids2, nullptr, err);
        // Clear Alice's test deposit too.
        RelayClient al; sign_in(al, main_srv, pin, *alice, err);
        auto aenv = drain(al);
        std::vector<Bytes> aids; for (auto& e : aenv) aids.push_back(e.id);
        al.acknowledge(aids, nullptr, err);
    }

    std::cout << "5. Offline delivery, ordering and acknowledgement\n";
    {
        for (uint8_t i = 1; i <= 3; i++) {
            RelayClient s; connect_to(s, main_srv, pin, err);
            s.deposit(alice->id, alice->token, payload_of(i, 100 + i), 3600, nullptr, err);
        }
        RelayClient a; sign_in(a, main_srv, pin, *alice, err);
        auto got = drain(a);
        CHECK(got.size() == 3 && got[0].envelope == payload_of(1, 101) && got[1].envelope == payload_of(2, 102) && got[2].envelope == payload_of(3, 103),
              "three envelopes deposited while the owner was offline arrive in order");
        CHECK(!got.empty() && got[0].deposited_at > 1600000000, "each carries the relay's deposit time");

        size_t deleted = 0;
        CHECK(a.acknowledge({got[0].id, got[1].id}, &deleted, err) && deleted == 2, "acknowledging two deletes two (" + err + ")");
        a.close();
        RelayClient again; sign_in(again, main_srv, pin, *alice, err);
        auto rest = drain(again);
        CHECK(rest.size() == 1 && rest[0].id == got[2].id, "the unacknowledged one is delivered again after reconnecting");
        again.acknowledge({rest[0].id}, &deleted, err);
        again.close();
        RelayClient empty; sign_in(empty, main_srv, pin, *alice, err);
        CHECK(drain(empty).empty(), "once acknowledged, nothing is delivered again");
    }

    std::cout << "6. Push delivery to a connected owner\n";
    {
        RelayClient owner; sign_in(owner, main_srv, pin, *alice, err);
        drain(owner);  // backlog (empty), now waiting for news
        RelayClient sender; connect_to(sender, main_srv, pin, err);
        auto t0 = std::chrono::steady_clock::now();
        sender.deposit(alice->id, alice->token, payload_of(42, 64), 3600, nullptr, err);
        RelayClient::Event e;
        for (int i = 0; i < 20; i++) { e = owner.next_event(250); if (e.kind == RelayClient::Event::Kind::Envelope) break; }
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        CHECK(e.kind == RelayClient::Event::Kind::Envelope && e.envelope.envelope == payload_of(42, 64), "a deposit reaches an already-connected owner (" + std::to_string(ms) + " ms)");
        owner.acknowledge({e.envelope.id}, nullptr, err);
        std::string ping_err;
        CHECK(owner.ping(ping_err), "ping and pong keep a connection alive (" + ping_err + ")");
    }

    std::cout << "7. Hijack attempts\n";
    {
        RelayClient s; connect_to(s, main_srv, pin, err);
        s.deposit(alice->id, alice->token, payload_of(77, 80), 3600, nullptr, err);
        RelayClient a; sign_in(a, main_srv, pin, *alice, err);
        auto mine = drain(a);

        RelayClient m; sign_in(m, main_srv, pin, *mallory, err);
        size_t stolen = 99;  // overwritten by acknowledge()
        bool acked = mine.empty() ? false : m.acknowledge({mine[0].id}, &stolen, err);
        CHECK(acked && stolen == 0, "Mallory, signed in to her own mailbox, can't acknowledge (delete) Alice's envelope");
        RelayClient a2; sign_in(a2, main_srv, pin, *alice, err);
        CHECK(drain(a2).size() == 1, "...it is still waiting for Alice");

        RelayClient nobody; connect_to(nobody, main_srv, pin, err);
        CHECK(!nobody.collect(err) || nobody.next_event(2000).kind == RelayClient::Event::Kind::Closed, "someone who never signed in can't collect");
        RelayClient nobody2; connect_to(nobody2, main_srv, pin, err);
        CHECK(!nobody2.acknowledge({mine.empty() ? Bytes(16, 0) : mine[0].id}, nullptr, err) && has(err, "Sign in"), "...or acknowledge: " + err);
        RelayClient nobody3; connect_to(nobody3, main_srv, pin, err);
        CHECK(!nobody3.add_token(CryptoEngine::random_bytes(32), err) && has(err, "Sign in"), "...or add send tokens: " + err);

        // Authentication belongs to the connection: a newer sign-in by the owner replaces the old one.
        RelayClient first; sign_in(first, main_srv, pin, *alice, err);
        drain(first, 500);  // first is now the connection receiving deliveries
        RelayClient helper; sign_in(helper, main_srv, pin, *alice, err);
        std::string helper_err;
        CHECK(helper.add_token(CryptoEngine::sha256(CryptoEngine::random_bytes(8)), helper_err),
              "a second signed-in connection that is not collecting can work alongside it (" + helper_err + ")");
        RelayClient::Event still = first.next_event(300);
        CHECK(still.kind == RelayClient::Event::Kind::Timeout, "...and does not disturb the collecting one");
        RelayClient newer; sign_in(newer, main_srv, pin, *alice, err);
        newer.collect(err);  // a newer connection that also collects replaces the first
        RelayClient::Event ev;
        for (int i = 0; i < 20; i++) { ev = first.next_event(250); if (ev.kind == RelayClient::Event::Kind::Closed) break; }
        CHECK(ev.kind == RelayClient::Event::Kind::Closed && has(ev.text, "Another client"), "a newer collecting connection replaces the first one: " + ev.text);
        RelayClient cleanup; sign_in(cleanup, main_srv, pin, *alice, err);
        auto left = drain(cleanup);
        std::vector<Bytes> lids; for (auto& e : left) lids.push_back(e.id);
        cleanup.acknowledge(lids, nullptr, err);
    }

    std::cout << "8. Send tokens\n";
    {
        Bytes second_token = CryptoEngine::random_bytes(32);
        RelayClient owner; sign_in(owner, main_srv, pin, *alice, err);
        CHECK(owner.add_token(CryptoEngine::sha256(second_token), err), "the owner adds a second token (" + err + ")");
        RelayClient s; connect_to(s, main_srv, pin, err);
        CHECK(s.deposit(alice->id, second_token, payload_of(5), 3600, nullptr, err), "the new token deposits (" + err + ")");
        CHECK(owner.revoke_token(CryptoEngine::sha256(second_token), err), "the owner revokes it (" + err + ")");
        RelayClient s2; connect_to(s2, main_srv, pin, err);
        CHECK(!s2.deposit(alice->id, second_token, payload_of(6), 3600, nullptr, err) && has(err, "Unknown"), "the revoked token no longer works: " + err);
        RelayClient s3; connect_to(s3, main_srv, pin, err);
        CHECK(s3.deposit(alice->id, alice->token, payload_of(7), 3600, nullptr, err), "the original token is unaffected (" + err + ")");
        auto got = drain(owner);
        std::vector<Bytes> gids; for (auto& e : got) gids.push_back(e.id);
        owner.acknowledge(gids, nullptr, err);
    }

    std::cout << "9. Expiry\n";
    {
        RelayClient s; connect_to(s, main_srv, pin, err);
        s.deposit(alice->id, alice->token, payload_of(1, 50), 1, nullptr, err);
        sleep_ms(3500);
        RelayClient a; sign_in(a, main_srv, pin, *alice, err);
        CHECK(drain(a).empty(), "an envelope with a 1-second lifetime is gone a few seconds later");
        RelayClient s2; connect_to(s2, main_srv, pin, err);
        s2.deposit(alice->id, alice->token, payload_of(2, 50), 3600, nullptr, err);
        sleep_ms(1500);
        RelayClient a2; sign_in(a2, main_srv, pin, *alice, err);
        auto live = drain(a2);
        CHECK(live.size() == 1, "an envelope with a long lifetime is still there");
        std::vector<Bytes> ids; for (auto& e : live) ids.push_back(e.id);
        a2.acknowledge(ids, nullptr, err);
    }

    std::cout << "10. Hostile and malformed input\n";
    {
        Raw bad_version;
        bad_version.open(main_srv);
        relay::Hello h; h.version = 2; h.client_nonce = CryptoEngine::random_bytes(32);
        send_message(bad_version.s, MessageType::RELAY_HELLO, relay::encode(h));
        CHECK(has(bad_version.answer(), "version 3"), "a hello with the wrong version is refused with a clear message");

        Raw truncated;
        truncated.open(main_srv); truncated.hello();
        send_message(truncated.s, MessageType::RELAY_DEPOSIT, Bytes(10, 1));
        CHECK(has(truncated.answer(), "Malformed"), "a truncated deposit is refused");

        Raw unknown;
        unknown.open(main_srv); unknown.hello();
        send_message(unknown.s, static_cast<MessageType>(0x77), {});
        CHECK(has(unknown.answer(), "Unexpected"), "an unknown message type is refused");

        Raw huge;
        huge.open(main_srv); huge.hello();
        uint8_t frame[5] = {0xFF, 0xFF, 0xFF, 0xF0, static_cast<uint8_t>(MessageType::RELAY_DEPOSIT)};
        send_exact(huge.s, frame, sizeof(frame));
        CHECK(huge.answer().empty(), "a frame declaring 4 GiB is dropped without allocating it");

        Raw junk;
        junk.open(main_srv);
        Bytes noise = CryptoEngine::random_bytes(2000);
        send_exact(junk.s, noise.data(), noise.size());
        junk.answer();
        CHECK(server_alive(main_srv, pin), "after all of that, the relay still serves normal clients");

        Raw v2;
        v2.open(main_srv);
        send_text_message(v2.s, MessageType::DOWNLOAD_REQUEST, std::string(32, 'a'));
        CHECK(has(v2.answer(), "not found"), "the same port still answers protocol v2 file-transfer requests");
    }

    std::cout << "10b. Many senders at once\n";
    {
        const int threads = 20, per_thread = 20, total = threads * per_thread;
        std::atomic<int> deposit_failures{0};
        std::vector<std::thread> senders;
        RelayClient owner;
        std::string owner_err;
        sign_in(owner, main_srv, pin, *alice, owner_err);
        owner.collect(owner_err);  // already connected and listening while the senders work

        for (int t = 0; t < threads; t++)
            senders.emplace_back([&, t] {
                RelayClient c;
                std::string e;
                if (!connect_to(c, main_srv, pin, e)) { deposit_failures += per_thread; return; }
                for (int i = 0; i < per_thread; i++) {
                    Bytes payload(16, 0);
                    payload[0] = static_cast<uint8_t>(t);
                    payload[1] = static_cast<uint8_t>(i);
                    if (!c.deposit(alice->id, alice->token, payload, 3600, nullptr, e)) deposit_failures++;
                }
            });

        std::set<Bytes> contents, ids;
        int received = 0;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
        while (received < total && std::chrono::steady_clock::now() < deadline) {
            auto e = owner.next_event(250);
            if (e.kind == RelayClient::Event::Kind::Envelope) { received++; contents.insert(e.envelope.envelope); ids.insert(e.envelope.id); }
            else if (e.kind == RelayClient::Event::Kind::Closed) break;
        }
        for (auto& th : senders) th.join();
        CHECK(deposit_failures == 0, std::to_string(threads) + " senders made " + std::to_string(total) + " deposits with no failures");
        CHECK(received == total && contents.size() == static_cast<size_t>(total) && ids.size() == static_cast<size_t>(total),
              "the owner received every envelope exactly once (" + std::to_string(received) + " of " + std::to_string(total) + ")");
        std::vector<Bytes> all_ids(ids.begin(), ids.end());
        size_t deleted = 0;
        owner.acknowledge(all_ids, &deleted, owner_err);
        CHECK(deleted == static_cast<size_t>(total), "all of them are acknowledged and deleted in batches");
        CHECK(server_alive(main_srv, pin), "the relay is still healthy afterwards");
    }

    std::cout << "11. Restart: nothing is lost, the identity stays\n";
    {
        RelayClient s; connect_to(s, main_srv, pin, err);
        s.deposit(alice->id, alice->token, payload_of(99, 123), 3600, nullptr, err);
        main_srv.stop();
        CHECK(main_srv.start(), "the relay restarts");
        err.clear();
        RelayClient a;
        CHECK(sign_in(a, main_srv, pin, *alice, err), "the pinned relay ID still matches after a restart (" + err + ")");
        auto got = drain(a);
        CHECK(got.size() == 1 && got[0].envelope == payload_of(99, 123), "the queued envelope survived the restart");
        a.acknowledge({got[0].id}, nullptr, err);
        auto fresh = main_srv.invite();
        CHECK(fresh && fresh->relay_id == pin, "the relay ID is the same as before");
    }
    main_srv.stop();

    std::cout << "12b. Members vouching for friends\n";
    {
        const int base = 30000 + static_cast<int>(getpid() % 5000) * 2;
        Server vouch{base, ROOT / "relay-vouch", {"--member-invites", "2", "--member-invites-total", "3"}};
        if (!vouch.start()) { std::cout << "FAIL could not start the vouching relay\n"; failures++; return; }
        auto op_invite = vouch.invite();
        const Bytes vpin = op_invite->relay_id;
        auto alice_box = make_box(vouch, vpin);
        if (!alice_box) { std::cout << "FAIL setup\n"; failures++; return; }
        auto cli = [&](const std::string& args) {
            std::string cmd = "\"" + SERVER_BIN + "\" --storage \"" + vouch.storage.string() + "\" " + args + " 2>&1";
            FILE* p = popen(cmd.c_str(), "r");
            std::string out;
            char buf[512];
            while (p && fgets(buf, sizeof(buf), p)) out += buf;
            if (p) pclose(p);
            return out;
        };
        auto invitee = [&](const Bytes& code) -> std::optional<Box> {
            Box b{CryptoEngine::random_bytes(16), CryptoEngine::random_bytes(32), CryptoEngine::generate_sig_keypair()};
            RelayClient c;
            std::string e;
            if (!connect_to(c, vouch, vpin, e) || !c.register_mailbox(code, b.id, b.access, b.token, e)) return std::nullopt;
            return b;
        };
        auto make_invite = [&](const Box& who, std::string& why) -> std::optional<Bytes> {
            RelayClient c;
            Bytes code;
            if (!sign_in(c, vouch, vpin, who, why) || !c.create_invite(code, why)) return std::nullopt;
            return code;
        };
        auto status_of = [&](const Box& who, relay::InviteStatus& st, std::string& e) {
            RelayClient c;
            return sign_in(c, vouch, vpin, who, e) && c.list_invites(st, e);
        };
        auto cancel_for = [&](const Box& who, const Bytes& invite_hash, std::string& e) {
            RelayClient c;
            return sign_in(c, vouch, vpin, who, e) && c.cancel_invite(invite_hash, e);
        };
        std::string why;

        RelayClient anon;
        std::string anon_err;
        connect_to(anon, vouch, vpin, anon_err);
        Bytes ignored;
        CHECK(!anon.create_invite(ignored, anon_err) && has(anon_err, "Sign in"), "someone who hasn't signed in to a mailbox can't make invites: " + anon_err);

        {
            relay::InviteStatus st;
            CHECK(!anon.list_invites(st, anon_err) && has(anon_err, "Sign in"), "nor can they list invites: " + anon_err);
            CHECK(status_of(*alice_box, st, why) && st.max_unused == 2 && st.max_total == 3 && st.unused.empty() && st.joined.empty(), "a member with no invites sees the limits and nothing else");
        }
        auto c1 = make_invite(*alice_box, why);
        CHECK(c1 && c1->size() == 16, "a member can make an invite");
        auto bob = c1 ? invitee(*c1) : std::nullopt;
        CHECK(bob.has_value(), "a friend registers a mailbox with it");
        CHECK(!(c1 && invitee(*c1)), "and it works only once");

        auto c2 = make_invite(*alice_box, why);
        auto c3 = make_invite(*alice_box, why);
        CHECK(c2 && c3, "she can have 2 unused invites at once");
        {
            relay::InviteStatus st;
            Bytes h2 = c2 ? CryptoEngine::sha256(*c2) : Bytes(), h3 = c3 ? CryptoEngine::sha256(*c3) : Bytes();
            bool has_both = status_of(*alice_box, st, why) && st.unused.size() == 2;
            if (has_both) has_both = (st.unused[0].hash == h2 || st.unused[1].hash == h2) && (st.unused[0].hash == h3 || st.unused[1].hash == h3);
            CHECK(has_both && st.joined.size() == 1 && st.joined[0].mailbox_id == bob->id, "she sees her two unused invites (by hash) and that Bob joined through her");
            CHECK(!cancel_for(*bob, h2, why) && has(why, "isn't one of your unused invites"), "Bob can't cancel her invite: " + why);
            CHECK(cancel_for(*alice_box, h3, why) && !(c3 && invitee(*c3)), "she cancels one, and it no longer works");
            CHECK(!cancel_for(*alice_box, h3, why) && has(why, "isn't one of your unused invites"), "cancelling it again says so: " + why);
            c3 = make_invite(*alice_box, why);
            CHECK(c3.has_value(), "and she can make another in its place");
        }
        auto c4 = make_invite(*alice_box, why);
        CHECK(!c4 && has(why, "2 unused"), "a third unused one is refused: " + why);
        auto carol = c2 ? invitee(*c2) : std::nullopt;
        auto dave = c3 ? invitee(*c3) : std::nullopt;
        CHECK(carol && dave, "two more friends join");
        {
            relay::InviteStatus st;
            CHECK(status_of(*alice_box, st, why) && st.unused.empty() && st.joined.size() == 3, "afterwards she has no unused invites and three people have joined through her");
        }
        auto c5 = make_invite(*alice_box, why);
        CHECK(!c5 && has(why, "limit of people"), "after inviting 3 people in all, she can invite no more: " + why);

        auto chain = bob ? make_invite(*bob, why) : std::nullopt;
        auto erin = chain ? invitee(*chain) : std::nullopt;
        CHECK(chain && erin, "a member who was invited can vouch for someone too (Bob invites Erin)");

        std::string alice_id = bytes_to_hex(alice_box->id).substr(0, 12), bob_id = bytes_to_hex(bob->id).substr(0, 12);
        std::string listing = cli("--list-mailboxes");
        CHECK(has(listing, "Mailboxes on this relay: 5") && has(listing, alice_id + "  ") && has(listing, "operator"), "the operator sees all five mailboxes, and which one came from an operator invite");
        size_t by_alice = 0, at = 0;
        while ((at = listing.find(alice_id, at)) != std::string::npos) { by_alice++; at += 12; }
        size_t by_bob = 0;
        at = 0;
        while ((at = listing.find(bob_id, at)) != std::string::npos) { by_bob++; at += 12; }
        CHECK(by_alice == 4 && by_bob == 2, "...with Alice named as the one who vouched for Bob, Carol and Dave, and Bob for Erin");

        CHECK(has(cli("--remove-mailbox abc"), "at least 8") && has(cli("--remove-mailbox ffffffffffffffff"), "No mailbox"), "removal needs a clear ID, and says when nothing matches");
        std::string removed = cli("--remove-mailbox " + alice_id);
        CHECK(has(removed, "Removed 1 mailbox") && has(removed, "3 mailbox(es) it invited were left alone"), "removing Alice alone leaves the three she invited, and says so");
        RelayClient gone;
        std::string gone_err;
        CHECK(!sign_in(gone, vouch, vpin, *alice_box, gone_err) && has(gone_err, "Authentication"), "Alice can no longer sign in");
        RelayClient still;
        CHECK(sign_in(still, vouch, vpin, *bob, why), "Bob, whom she invited, still can");
        CHECK(has(cli("--list-mailboxes"), "*"), "the listing marks mailboxes whose voucher is gone");
        std::string cascade = cli("--remove-mailbox " + bob_id + " --with-invitees");
        CHECK(has(cascade, "Removed 2 mailbox"), "removing Bob with --with-invitees takes Erin too");
        CHECK(has(cli("--list-mailboxes"), "Mailboxes on this relay: 2"), "Carol and Dave remain");
        vouch.stop();

        Server closed{base + 1, ROOT / "relay-closed", {"--member-invites", "0"}};
        if (!closed.start()) { std::cout << "FAIL could not start the closed relay\n"; failures++; return; }
        auto closed_invite = closed.invite();
        auto member = make_box(closed, closed_invite->relay_id);
        RelayClient cc;
        std::string closed_err;
        Bytes none;
        CHECK(member && sign_in(cc, closed, closed_invite->relay_id, *member, closed_err) && !cc.create_invite(none, closed_err) && has(closed_err, "doesn't let members"),
              "with --member-invites 0 members can't make invites: " + closed_err);
        closed.stop();
    }

    std::cout << "12. Rate limiting\n";
    {
        Server limited{20101 + static_cast<int>(getpid() % 5000) * 2, ROOT / "relay-limited", {"--rate-limit", "5"}};
        if (!limited.start()) { std::cout << "FAIL could not start the limited relay\n"; failures++; return; }
        auto inv = limited.invite();
        auto box = make_box(limited, inv->relay_id);
        int ok = 0;
        std::string last;
        for (int i = 0; i < 8; i++) {
            RelayClient s; connect_to(s, limited, inv->relay_id, err);
            if (s.deposit(box->id, box->token, payload_of(1, 10), 3600, nullptr, last)) ok++;
        }
        CHECK(ok == 5 && has(last, "Too many"), "deposits beyond the per-minute limit are refused (" + std::to_string(ok) + " accepted)");
        limited.stop();
    }
}

// =====================================================================================
// Part 2: a hostile relay, scripted, attacking the client
// =====================================================================================

enum class Behavior {
    HonestKey,              // control: a correct relay
    WrongKey,               // a different key than the pinned one
    StaleNonce,             // signs a different client nonce (a replayed answer)
    WrongRelayIdSigned,     // signs over a different relay ID
    ShortChallenge,         // malformed hello reply
    Silent,                 // never answers
    ErrorWithControlChars,  // answers with an escape-sequence-laden error
    DuplicateEnvelopes,     // sends the same envelope twice, then junk, then a valid one
    OversizedFrame,         // declares a 4 GiB message
    UnexpectedType          // answers the sign-in with something else
};

struct FakeRelay {
    int listen_fd = -1;
    uint16_t port = 0;
    CryptoEngine::SigKeyPair key;
    Bytes id;
    Behavior behavior;
    std::thread thread;

    FakeRelay(Behavior b, const CryptoEngine::SigKeyPair& k) : key(k), id(CryptoEngine::sha256(k.public_key)), behavior(b) {
        listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        listen(listen_fd, 4);
        socklen_t len = sizeof(addr);
        getsockname(listen_fd, reinterpret_cast<sockaddr*>(&addr), &len);
        port = ntohs(addr.sin_port);
        thread = std::thread([this] { serve(); });
    }
    ~FakeRelay() {
        close(listen_fd);
        if (thread.joinable()) thread.join();
    }

    void serve() {
        int c = accept(listen_fd, nullptr, nullptr);
        if (c < 0) return;
        set_socket_timeouts(c, 6);
        auto hello_msg = recv_message(c, relay::MAX_MESSAGE_PAYLOAD);
        auto hello = hello_msg ? relay::decode_hello(hello_msg->payload) : std::nullopt;
        if (!hello || behavior == Behavior::Silent) {
            if (behavior == Behavior::Silent) sleep_ms(2500);
            close(c);
            return;
        }

        if (behavior == Behavior::ErrorWithControlChars) {
            std::string nasty = std::string("denied \x1b[31mRED\x1b[0m\x07\n") + std::string(500, 'x');
            send_text_message(c, MessageType::ERROR_MSG, nasty);
            close(c);
            return;
        }

        relay::HelloReply reply;
        reply.relay_public_key = key.public_key;
        reply.auth_challenge = CryptoEngine::random_bytes(relay::NONCE_BYTES);
        Bytes sign_id = id, sign_nonce = hello->client_nonce;
        if (behavior == Behavior::WrongRelayIdSigned) sign_id[0] ^= 1;
        if (behavior == Behavior::StaleNonce) sign_nonce = CryptoEngine::random_bytes(relay::NONCE_BYTES);
        reply.signature = CryptoEngine::sign(relay::hello_signing_input(sign_nonce, sign_id, relay::WIRE_VERSION, reply.auth_challenge), key.private_key);
        if (behavior == Behavior::ShortChallenge) reply.auth_challenge.resize(5);
        send_message(c, MessageType::RELAY_HELLO_REPLY, relay::encode(reply));

        // Then answer whatever the client asks, according to the script.
        while (true) {
            auto m = recv_message(c, relay::MAX_MESSAGE_PAYLOAD);
            if (!m) break;
            if (m->type == MessageType::RELAY_AUTH) {
                if (behavior == Behavior::UnexpectedType) { send_message(c, static_cast<MessageType>(0x77), {}); continue; }
                send_message(c, MessageType::RELAY_AUTH_OK, {});
            } else if (m->type == MessageType::RELAY_COLLECT) {
                if (behavior == Behavior::OversizedFrame) {
                    uint8_t frame[5] = {0xFF, 0xFF, 0xFF, 0xF0, static_cast<uint8_t>(MessageType::RELAY_ENVELOPE)};
                    send_exact(c, frame, sizeof(frame));
                    break;
                }
                relay::StoredEnvelope e{Bytes(16, 0x11), 1700000000, Bytes(32, 0x33), Bytes(50, 0xAB)};
                send_message(c, MessageType::RELAY_ENVELOPE, relay::encode(e));
                if (behavior == Behavior::DuplicateEnvelopes) {
                    send_message(c, MessageType::RELAY_ENVELOPE, relay::encode(e));      // the same one again
                    send_message(c, MessageType::RELAY_ENVELOPE, Bytes(7, 0xEE));        // junk
                    relay::StoredEnvelope e2{Bytes(16, 0x22), 1700000001, Bytes(32, 0x33), Bytes(60, 0xCD)};
                    send_message(c, MessageType::RELAY_ENVELOPE, relay::encode(e2));
                    send_message(c, MessageType::RELAY_ENVELOPE, relay::encode(e));      // and the first, once more
                }
                send_message(c, MessageType::RELAY_COLLECT_END, {});
            }
        }
        close(c);
    }
};

static void test_hostile_relay() {
    std::cout << "13. A hostile relay attacking the client\n";
    auto real_key = CryptoEngine::generate_sig_keypair();
    Bytes pin = CryptoEngine::sha256(real_key.public_key);
    std::string err;

    auto attempt = [&](Behavior b, const Bytes& pinned, int timeout_s = 3) {
        auto key = b == Behavior::WrongKey ? CryptoEngine::generate_sig_keypair() : real_key;
        auto relay = std::make_unique<FakeRelay>(b, key);
        auto client = std::make_unique<RelayClient>();
        bool ok = client->connect("127.0.0.1", relay->port, pinned, timeout_s, err);
        return std::make_tuple(std::move(client), std::move(relay), ok);
    };

    {
        auto [c, r, ok] = attempt(Behavior::HonestKey, pin);
        CHECK(ok, "(control) an honest scripted relay is accepted (" + err + ")");
    }
    {
        auto [c, r, ok] = attempt(Behavior::WrongKey, pin);
        CHECK(!ok && has(err, "does not match"), "a relay with a different key than the pinned one is refused: " + err);
    }
    {
        auto [c, r, ok] = attempt(Behavior::StaleNonce, pin);
        CHECK(!ok && has(err, "prove its identity"), "a replayed answer (signed for another nonce) is refused: " + err);
    }
    {
        auto [c, r, ok] = attempt(Behavior::WrongRelayIdSigned, pin);
        CHECK(!ok && has(err, "prove its identity"), "a signature over a different relay ID is refused: " + err);
    }
    {
        auto [c, r, ok] = attempt(Behavior::ShortChallenge, pin);
        CHECK(!ok, "a malformed hello reply is refused: " + err);
    }
    {
        auto start = std::chrono::steady_clock::now();
        auto [c, r, ok] = attempt(Behavior::Silent, pin, 1);
        auto secs = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start).count();
        CHECK(!ok && secs < 5, "a relay that never answers is given up on after the timeout instead of hanging (" + std::to_string(secs) + " s)");
    }
    {
        auto [c, r, ok] = attempt(Behavior::ErrorWithControlChars, pin);
        CHECK(!ok && err.find('\x1b') == std::string::npos && err.find('\x07') == std::string::npos && err.size() < 300,
              "an error message full of escape sequences is shown clean and short");
    }
    {
        auto [c, r, ok] = attempt(Behavior::DuplicateEnvelopes, pin);
        c->authenticate(Bytes(16, 1), real_key.private_key, err);
        c->collect(err);
        int envelopes = 0; bool end = false;
        std::set<Bytes> ids;
        for (int i = 0; i < 40 && !end; i++) {
            auto e = c->next_event(300);
            if (e.kind == RelayClient::Event::Kind::Envelope) { envelopes++; ids.insert(e.envelope.id); }
            else if (e.kind == RelayClient::Event::Kind::CollectEnd) end = true;
            else if (e.kind == RelayClient::Event::Kind::Closed) break;
        }
        CHECK(envelopes == 2 && ids.size() == 2 && end, "duplicated envelopes are delivered once each, and malformed ones are ignored (" + std::to_string(envelopes) + " delivered)");
    }
    {
        auto [c, r, ok] = attempt(Behavior::OversizedFrame, pin);
        c->authenticate(Bytes(16, 1), real_key.private_key, err);
        c->collect(err);
        RelayClient::Event e;
        for (int i = 0; i < 20; i++) { e = c->next_event(300); if (e.kind == RelayClient::Event::Kind::Closed) break; }
        CHECK(e.kind == RelayClient::Event::Kind::Closed && !c->connected(), "a frame declaring 4 GiB ends the connection without allocating it");
    }
    {
        auto [c, r, ok] = attempt(Behavior::UnexpectedType, pin);
        bool signed_in = c->authenticate(Bytes(16, 1), real_key.private_key, err);
        CHECK(!signed_in && has(err, "unexpected"), "an unexpected answer to a request is an error, not a hang: " + err);
    }
}

int main(int argc, char** argv) {
    if (argc < 2) { std::cerr << "usage: test_relay /path/to/pq-server\n"; return 2; }
    SERVER_BIN = argv[1];
    ROOT = fs::temp_directory_path() / ("pqft-relay-" + std::to_string(getpid()));
    fs::remove_all(ROOT);
    fs::create_directories(ROOT);
    platform_init();

    test_real_relay();
    test_hostile_relay();

    std::error_code ec;
    fs::remove_all(ROOT, ec);
    std::cout << (failures ? "\nFAILURES: " : "\nAll checks passed. ") << failures << "\n";
    return failures ? 1 : 0;
}
