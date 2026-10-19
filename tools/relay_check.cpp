// pq-relay-check: checks a mailbox relay from the outside. Meant for the person who runs a
// relay (or is about to use one) to confirm it is reachable and genuine, through whatever
// network, VPN or firewall sits in between.
//
//   pq-relay-check HOST[:PORT] [RELAY_ID]    reachability and identity only (uses nothing up)
//   pq-relay-check pqft-relay://...          the full round trip with one invite (uses it up)
#include "crypto_engine.h"
#include "platform.h"
#include "protocol.h"
#include "relay_client.h"
#include "sharing.h"

#include <iostream>
#include <string>

static int failed = 0;

static bool step(const std::string& what, bool ok, const std::string& detail = "") {
    std::cout << (ok ? "[ ok ]  " : "[FAIL]  ") << what;
    if (!detail.empty()) std::cout << "  " << detail;
    std::cout << std::endl;
    if (!ok) failed++;
    return ok;
}

static void usage() {
    std::cout << "Usage:\n"
              << "  pq-relay-check HOST[:PORT] [RELAY_ID]   check reachability and the relay's identity\n"
              << "  pq-relay-check pqft-relay://...         full round trip using one invite (the invite is used up)\n";
}

static int identity_only(const std::string& address, const std::vector<uint8_t>& pin) {
    auto server = parse_server_address(address);
    if (!server) { std::cerr << "That is not a valid address: " << address << std::endl; return 2; }
    RelayClient client;
    std::string err;
    if (!step("connect to " + format_server_address(*server) + " and verify the relay's signature",
              client.connect(server->host, server->port, pin, 8, err), err)) return 1;
    std::cout << "        Relay ID: " << bytes_to_hex(client.relay_id()) << "\n";
    if (pin.empty())
        std::cout << "        Compare this with the Relay ID the operator gave you before you trust this relay.\n";
    else
        step("the relay's ID matches the one you gave", true);
    return failed ? 1 : 0;
}

static int full_check(const RelayInvite& invite) {
    std::string err;
    std::cout << "Relay " << format_server_address(invite.server) << ", expected ID " << bytes_to_hex(invite.relay_id).substr(0, 16) << "...\n";

    auto connect_to = [&](RelayClient& c, std::string& e) {
        return c.connect(invite.server.host, invite.server.port, invite.relay_id, 8, e);
    };

    RelayClient registrar;
    if (!step("connect and verify the relay's identity (pinned from the invite)", connect_to(registrar, err), err)) return 1;

    auto access = CryptoEngine::generate_sig_keypair();
    auto mailbox = CryptoEngine::random_bytes(relay::MAILBOX_ID_BYTES);
    auto token = CryptoEngine::random_bytes(relay::SEND_TOKEN_BYTES);
    if (!step("register a throwaway mailbox with the invite", registrar.register_mailbox(invite.invite, mailbox, access, token, err), err)) return 1;
    registrar.close();

    RelayClient owner;
    if (!step("connect again and sign in as the mailbox owner", connect_to(owner, err) && owner.authenticate(mailbox, access.private_key, err), err)) return 1;

    auto message = CryptoEngine::random_bytes(64);
    RelayClient sender;
    std::vector<uint8_t> envelope_id;
    if (!step("deposit an envelope using the send token (no sign-in needed)",
              connect_to(sender, err) && sender.deposit(mailbox, token, message, 60, &envelope_id, err), err)) return 1;

    std::vector<std::vector<uint8_t>> got;
    bool received = false;
    if (owner.collect(err)) {
        for (int i = 0; i < 20; i++) {
            auto e = owner.next_event(250);
            if (e.kind == RelayClient::Event::Kind::Envelope) { received = e.envelope.envelope == message; got.push_back(e.envelope.id); break; }
            if (e.kind == RelayClient::Event::Kind::Closed) { err = e.text; break; }
        }
    }
    if (!step("collect it, byte for byte", received, err)) return 1;

    size_t deleted = 0;
    step("acknowledge it so the relay deletes it", owner.acknowledge(got, &deleted, err) && deleted == 1, err);

    RelayClient again;
    bool empty = false;
    if (connect_to(again, err) && again.authenticate(mailbox, access.private_key, err) && again.collect(err)) {
        auto e = again.next_event(2000);
        empty = e.kind == RelayClient::Event::Kind::CollectEnd;
    }
    step("collect again: the acknowledged envelope is gone", empty, err);

    std::cout << (failed ? "\nSomething is wrong with this relay (see above).\n"
                         : "\nThe relay works. (The throwaway mailbox stays on the relay; it is tiny.)\n");
    return failed ? 1 : 0;
}

int main(int argc, char** argv) {
    if (argc < 2 || std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h") { usage(); return argc < 2 ? 2 : 0; }
    platform_init();
    std::string arg = argv[1];
    int rc;
    if (auto invite = parse_relay_invite(arg)) {
        rc = full_check(*invite);
    } else if (arg.rfind("pqft-relay://", 0) == 0) {
        std::cerr << "That invite string looks damaged. Paste it exactly as the relay printed it." << std::endl;
        rc = 2;
    } else {
        std::vector<uint8_t> pin;
        if (argc >= 3) {
            auto id = hex_to_bytes(argv[2]);
            if (!id || id->size() != 32) { std::cerr << "RELAY_ID must be 64 hex characters." << std::endl; platform_cleanup(); return 2; }
            pin = *id;
        }
        rc = identity_only(arg, pin);
    }
    platform_cleanup();
    return rc;
}
