// Unit tests for server addresses, contact cards and share links.
#include "crypto_engine.h"
#include "identity_bundle.h"
#include "protocol.h"
#include "key_store.h"
#include "sharing.h"

#include <algorithm>
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


// --- Identity bundles and contact cards, version 2 ---

struct Identity {
    CryptoEngine::SigKeyPair sig;
    CryptoEngine::KEMKeyPair kem;
};
static Identity make_identity() { return {CryptoEngine::generate_sig_keypair(), CryptoEngine::generate_kem_keypair()}; }

static std::vector<uint8_t> bundle_of(const Identity& id, const std::string& name = "Alice",
                                      const std::string& hint = "10.8.0.1", uint64_t issued = 1700000000) {
    return create_identity_bundle(id.sig.public_key, id.kem.public_key, name, hint, issued, id.sig.private_key);
}

// Replaces the first occurrence of `from` inside `buf` by `to` (same length).
static bool overwrite(std::vector<uint8_t>& buf, const std::vector<uint8_t>& from, const std::vector<uint8_t>& to) {
    auto it = std::search(buf.begin(), buf.end(), from.begin(), from.end());
    if (it == buf.end()) return false;
    std::copy(to.begin(), to.end(), it);
    return true;
}

// Rebuilds a bundle by hand (as an attacker or a newer version might), signing the body.
static std::vector<uint8_t> hand_made_bundle(const Identity& id, const std::vector<std::pair<uint32_t, std::vector<uint8_t>>>& fields,
                                             uint32_t magic = 0x50514942, uint32_t version = 1) {
    std::vector<uint8_t> body;
    write_u32(body, magic);
    write_u32(body, version);
    write_u64(body, 1700000000);
    write_u32(body, static_cast<uint32_t>(fields.size()));
    for (auto& f : fields) { write_u32(body, f.first); write_blob(body, f.second); }
    std::vector<uint8_t> input;
    write_string(input, "pq-suite v3 identity bundle");
    write_bytes(input, body.data(), body.size());
    auto signature = CryptoEngine::sign(input, id.sig.private_key);
    std::vector<uint8_t> raw;
    write_blob(raw, body);
    write_blob(raw, signature);
    return raw;
}

static void test_identity_bundle() {
    std::cout << "Identity bundles\n";
    Identity alice = make_identity(), mallory = make_identity();
    auto raw = bundle_of(alice);

    std::string err;
    auto b = parse_identity_bundle(raw, &err);
    CHECK(b && b->signing_key == alice.sig.public_key && b->encryption_key == alice.kem.public_key &&
              b->display_name == "Alice" && b->relay_hint == "10.8.0.1" && b->issued_at == 1700000000 && b->raw == raw,
          "round trip " + err);
    CHECK(b && b->fingerprint() == CryptoEngine::fingerprint(alice.sig.public_key), "fingerprint is still the SHA-256 of the signing key");

    auto minimal = parse_identity_bundle(bundle_of(alice, "", ""));
    CHECK(minimal && minimal->display_name.empty() && minimal->relay_hint.empty(), "name and relay hint are optional");

    // The attack from the design review: keep the signing key, swap in the attacker's encryption key.
    auto swapped = raw;
    CHECK(overwrite(swapped, alice.kem.public_key, mallory.kem.public_key), "(test setup) located the encryption key in the bundle");
    CHECK(!parse_identity_bundle(swapped, &err) && err.find("signature") != std::string::npos,
          "swapping the encryption key breaks the signature: " + err);
    auto replaced_sig_key = raw;
    overwrite(replaced_sig_key, alice.sig.public_key, mallory.sig.public_key);
    CHECK(!parse_identity_bundle(replaced_sig_key), "swapping the signing key is rejected too");
    CHECK(parse_identity_bundle(raw).has_value(), "(sanity) the untouched bundle still verifies");

    // Flip one bit in every byte of the signed body: nothing may still verify.
    size_t body_len = (static_cast<size_t>(raw[0]) << 24) | (static_cast<size_t>(raw[1]) << 16) |
                      (static_cast<size_t>(raw[2]) << 8) | raw[3];
    int accepted = 0;
    for (size_t i = 4; i < 4 + body_len; i++) {
        auto bad = raw;
        bad[i] ^= 0x01;
        if (parse_identity_bundle(bad)) accepted++;
    }
    CHECK(accepted == 0, "a one-bit change anywhere in the signed body is rejected (" + std::to_string(body_len) + " positions)");
    auto bad_sig = raw; bad_sig[4 + body_len + 4] ^= 0x01;
    CHECK(!parse_identity_bundle(bad_sig), "a changed signature is rejected");

    auto trailing = raw; trailing.push_back(0);
    CHECK(!parse_identity_bundle(trailing), "trailing bytes are rejected");
    CHECK(!parse_identity_bundle(std::vector<uint8_t>(raw.begin(), raw.begin() + 100)), "a truncated bundle is rejected");
    CHECK(!parse_identity_bundle({}), "an empty bundle is rejected");

    bool threw = false;
    try { create_identity_bundle(alice.sig.public_key, alice.kem.public_key, std::string(65, 'x'), "", 1, alice.sig.private_key); } catch (...) { threw = true; }
    CHECK(threw, "an over-long display name is refused at creation");
    threw = false;
    try { create_identity_bundle({1, 2, 3}, alice.kem.public_key, "A", "", 1, alice.sig.private_key); } catch (...) { threw = true; }
    CHECK(threw, "a wrong-sized key is refused at creation");

    // Forward compatibility and strictness, with bundles made by hand.
    std::vector<std::pair<uint32_t, std::vector<uint8_t>>> base = {{1, alice.sig.public_key}, {2, alice.kem.public_key}};
    auto with_unknown = base; with_unknown.push_back({99, {1, 2, 3}});
    CHECK(parse_identity_bundle(hand_made_bundle(alice, with_unknown)).has_value(), "an unknown field from a newer version is ignored");
    auto duplicate_kem = base; duplicate_kem.push_back({2, mallory.kem.public_key});
    CHECK(!parse_identity_bundle(hand_made_bundle(alice, duplicate_kem)), "a duplicated encryption key field is rejected");
    CHECK(!parse_identity_bundle(hand_made_bundle(alice, {{1, alice.sig.public_key}})), "a bundle without an encryption key is rejected");
    CHECK(!parse_identity_bundle(hand_made_bundle(alice, base, 0x12345678)), "the wrong magic is rejected");
    CHECK(!parse_identity_bundle(hand_made_bundle(alice, base, 0x50514942, 2)), "an unknown version is rejected");
    auto short_key = base; short_key[1].second.resize(100);
    CHECK(!parse_identity_bundle(hand_made_bundle(alice, short_key)), "a wrong-sized encryption key is rejected even when correctly signed");
}

static void test_contact_cards_v2() {
    std::cout << "Contact cards, version 2\n";
    Identity alice = make_identity(), mallory = make_identity();
    auto raw = bundle_of(alice);
    std::string card = encode_contact_card_v2(raw);

    CHECK(card.rfind("pqft-contact-2:", 0) == 0 && card.find_first_of(" \n\t") == std::string::npos, "v2 prefix, single line");
    CHECK(looks_like_contact_card(card), "recognised as a card");

    std::string err;
    auto d = decode_any_contact_card(card, &err);
    CHECK(d && d->bundle && d->pub_kem == alice.kem.public_key && d->pub_dsa == alice.sig.public_key &&
              d->name == "Alice" && d->server == "10.8.0.1",
          "round trip " + err);

    std::string wrapped;
    for (size_t i = 0; i < card.size(); i += 64) wrapped += card.substr(i, 64) + "\r\n  ";
    CHECK(decode_any_contact_card("  \"" + wrapped + "\"", &err).has_value(), "survives wrapping and quotes");

    int undetected = 0;
    for (size_t pos : {20u, 300u, 1500u, 3000u, (unsigned)card.size() - 1}) {
        std::string bad = card;
        bad[pos] = bad[pos] == 'A' ? 'B' : 'A';
        if (decode_any_contact_card(bad)) undetected++;
    }
    CHECK(undetected == 0, "single-character corruption is detected");
    CHECK(!decode_any_contact_card(card.substr(0, card.size() / 2)), "a truncated card is rejected");

    // THE ATTACK: an attacker swaps the encryption key and also recomputes the checksum.
    auto swapped = raw;
    overwrite(swapped, alice.kem.public_key, mallory.kem.public_key);
    auto forged = decode_any_contact_card(encode_contact_card_v2(swapped), &err);
    CHECK(!forged && err.find("signature") != std::string::npos, "a card with a swapped encryption key is rejected: " + err);

    // The same attack on an old v1 card still goes through: that is the gap M0 closes.
    ContactCard v1{"Alice", alice.kem.public_key, alice.sig.public_key, ""};
    ContactCard v1_swapped = v1;
    v1_swapped.pub_kem = mallory.kem.public_key;
    auto old_card = decode_any_contact_card(encode_contact_card(v1_swapped), &err);
    CHECK(old_card && !old_card->bundle && CryptoEngine::fingerprint(old_card->pub_dsa) == CryptoEngine::fingerprint(alice.sig.public_key),
          "a v1 card with a swapped key still imports, with the SAME fingerprint, but with no bundle to prove the key");
    auto old_ok = decode_any_contact_card(encode_contact_card(v1), &err);
    CHECK(old_ok && !old_ok->bundle && old_ok->name == "Alice", "v1 cards still import, flagged by having no bundle");

    auto bad_hint = decode_any_contact_card(encode_contact_card_v2(bundle_of(alice, "Alice", "not a server!")), &err);
    CHECK(!bad_hint && err.find("relay") != std::string::npos, "an invalid relay hint is rejected: " + err);
    CHECK(!decode_any_contact_card("hello world", &err) && !err.empty(), "non-card text is rejected with a message");
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
    test_identity_bundle();
    test_contact_cards_v2();
    test_names();
    std::cout << (failures ? "\nFAILURES: " : "\nAll checks passed. ") << failures << "\n";
    return failures ? 1 : 0;
}
