// Unit tests for server addresses, contact cards and share links.
#include "crypto_engine.h"
#include "key_store.h"
#include "sharing.h"

#include <iostream>
#include <string>

static int failures = 0;
#define CHECK(cond, msg)                                              \
    do {                                                              \
        if (cond) std::cout << "  PASS " << (msg) << "\n";            \
        else { std::cout << "  FAIL " << (msg) << "\n"; failures++; } \
    } while (0)

static std::string id32(char c = 'a') { return std::string(32, c); }

static void test_server_addresses() {
    std::cout << "Server addresses\n";
    auto a = parse_server_address("10.8.0.1");
    CHECK(a && a->host == "10.8.0.1" && a->port == 9000, "plain host gets default port");
    a = parse_server_address("  relay.example.org:9100 ");
    CHECK(a && a->host == "relay.example.org" && a->port == 9100, "host:port, whitespace trimmed");
    a = parse_server_address("[::1]:9001");
    CHECK(a && a->host == "::1" && a->port == 9001, "[ipv6]:port");
    a = parse_server_address("fd00::1");
    CHECK(a && a->host == "fd00::1" && a->port == 9000, "bare IPv6 without port");
    for (std::string bad : std::vector<std::string>{"", "host:", "host:0", "host:70000", "host:12a", "ho st", "a/b", "[::1", "[::1]x", "-bad",
                            "user@host", "host?x=1", "host#frag"})
        CHECK(!parse_server_address(bad), "rejects '" + bad + "'");

    CHECK(format_server_address({"10.8.0.1", 9000}) == "10.8.0.1", "default port omitted");
    CHECK(format_server_address({"10.8.0.1", 9100}) == "10.8.0.1:9100", "custom port shown");
    CHECK(format_server_address({"::1", 9100}) == "[::1]:9100", "IPv6 bracketed");
    CHECK(same_server({"Relay.Example.org", 9000}, {"relay.example.org", 9000}), "host comparison ignores case");
    CHECK(!same_server({"a", 9000}, {"a", 9001}), "different port is a different server");
}

static void test_share_links() {
    std::cout << "Share links\n";
    ServerAddress srv{"10.8.0.1", 9000};
    std::string link = build_share_link(srv, id32());
    CHECK(link == "pqft://10.8.0.1/" + id32(), "link format: " + link);
    auto p = parse_share_link(link);
    CHECK(p && same_server(p->server, srv) && p->transfer_id == id32(), "round trip");

    p = parse_share_link(build_share_link({"fd00::1", 9100}, id32('b')));
    CHECK(p && p->server.host == "fd00::1" && p->server.port == 9100 && p->transfer_id == id32('b'), "IPv6 + port round trip");

    p = parse_share_link("<PQFT://Relay.Example.org:9100/" + std::string(32, 'A') + ">.");
    CHECK(p && p->server.host == "Relay.Example.org" && p->transfer_id == id32('a'), "tolerates case, <>, trailing dot");

    for (std::string bad : std::vector<std::string>{"", "pqft://", "pqft://host", "pqft://host/", "pqft://host/abc", "http://host/" + id32(),
                            "pqft://ho st/" + id32(), "pqft://host/" + id32() + "00", "pqft:///" + id32(),
                            "pqft://host/" + std::string(32, 'g'), id32()})
        CHECK(!parse_share_link(bad), "rejects '" + bad.substr(0, 40) + "'");
}

static ContactCard make_card(const std::string& name = "Alice", const std::string& server = "10.8.0.1") {
    ContactCard c;
    c.name = name;
    c.pub_kem = CryptoEngine::random_bytes(CryptoEngine::kem_public_key_size());
    c.pub_dsa = CryptoEngine::random_bytes(CryptoEngine::sig_public_key_size());
    c.server = server;
    return c;
}

static std::string wrap(const std::string& s, size_t width, const std::string& sep) {
    std::string out;
    for (size_t i = 0; i < s.size(); i += width) out += s.substr(i, width) + sep;
    return out;
}

static void test_contact_cards() {
    std::cout << "Contact cards\n";
    ContactCard c = make_card();
    std::string text = encode_contact_card(c);
    CHECK(text.rfind("pqft-contact-1:", 0) == 0, "starts with the card prefix");
    CHECK(text.find_first_of(" \n\t") == std::string::npos, "single line, no whitespace");
    CHECK(text.size() < 5000, "reasonable size (" + std::to_string(text.size()) + " chars)");

    std::string err;
    auto d = decode_contact_card(text, &err);
    CHECK(d && d->name == "Alice" && d->pub_kem == c.pub_kem && d->pub_dsa == c.pub_dsa && d->server == "10.8.0.1",
          "round trip " + err);

    d = decode_contact_card(wrap(text, 70, "\r\n   "), &err);
    CHECK(d && d->pub_kem == c.pub_kem, "survives line wrapping and indentation");
    d = decode_contact_card("  \"" + text + "\"\n", &err);
    CHECK(d && d->pub_dsa == c.pub_dsa, "survives surrounding quotes");

    ContactCard u = make_card("Zo\xC3\xAB", "");
    d = decode_contact_card(encode_contact_card(u), &err);
    CHECK(d && d->name == "Zo\xC3\xAB" && d->server.empty(), "UTF-8 name and empty server");

    // Corruption of any single character must be caught by the checksum.
    int undetected = 0;
    for (size_t pos : {20u, 100u, 1000u, 3000u, (unsigned)text.size() - 1}) {
        std::string bad = text;
        bad[pos] = bad[pos] == 'A' ? 'B' : 'A';
        if (decode_contact_card(bad)) undetected++;
    }
    CHECK(undetected == 0, "single-character corruption detected");
    CHECK(!decode_contact_card(text.substr(0, text.size() / 2)), "truncated card rejected");
    CHECK(!decode_contact_card(text + "AAAA"), "extra data rejected");
    CHECK(!decode_contact_card("hello world"), "non-card text rejected");
    d = decode_contact_card("", &err);
    CHECK(!d && !err.empty(), "empty input gives an error message");

    ContactCard badsrv = make_card("Bob", "not a server!");
    CHECK(!decode_contact_card(encode_contact_card(badsrv), &err) && err.find("relay") != std::string::npos,
          "invalid server address rejected: " + err);
    ContactCard badkey = make_card();
    badkey.pub_kem.resize(100);
    CHECK(!decode_contact_card(encode_contact_card(badkey), &err) && err.find("ML-KEM") != std::string::npos,
          "wrong key size rejected: " + err);
    ContactCard longname = make_card(std::string(65, 'x'));
    CHECK(!decode_contact_card(encode_contact_card(longname)), "over-long name rejected");

    CHECK(looks_like_contact_card("see " + text), "looks_like_contact_card finds a card in text");
    CHECK(!looks_like_contact_card("pqft://host/" + id32()), "a share link is not a card");
}

static void test_names() {
    std::cout << "Contact name sanitising\n";
    for (std::string raw : std::vector<std::string>{"Alice", "../keys", "..", ".hidden", "CON", "self", "Zo\xC3\xAB",
                                                    std::string(200, 'a'), "   ", "", "a/b\\c:d", "\x01\xff\xfe"}) {
        std::string clean = sanitize_contact_name(raw);
        CHECK(KeyStore::is_valid_contact_name(clean), "'" + raw.substr(0, 20) + "' -> '" + clean.substr(0, 20) + "' is valid");
    }
    CHECK(sanitize_contact_name("Alice Smith") == "Alice Smith", "ordinary names unchanged");
    CHECK(sanitize_contact_name("../keys") == "_keys", "path characters neutralised");
    CHECK(sanitize_contact_name("CON") == "contact" && sanitize_contact_name("self") == "contact",
          "reserved names replaced");
}

int main() {
    test_server_addresses();
    test_share_links();
    test_contact_cards();
    test_names();
    std::cout << (failures ? "\nFAILURES: " : "\nAll checks passed. ") << failures << "\n";
    return failures ? 1 : 0;
}
