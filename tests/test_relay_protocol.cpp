// Unit tests for the v3 payload codecs and signing inputs: round trips, truncation, trailing
// bytes, and random mutation (decoders must never crash or accept garbage as something else).
#include "relay_protocol.h"

#include "protocol.h"
#include "sharing.h"

#include <functional>
#include <iostream>
#include <random>
#include <string>

using namespace relay;
using Bytes = std::vector<uint8_t>;

static int failures = 0;
#define CHECK(c, msg)                                                  \
    do {                                                               \
        if (c) std::cout << "  PASS " << (msg) << "\n";                \
        else { std::cout << "  FAIL " << (msg) << "\n"; failures++; } \
    } while (0)

static Bytes fill(uint8_t v, size_t n) { return Bytes(n, v); }

// Every strict prefix of `good` must be rejected, and so must `good` plus a trailing byte.
template <typename Decode>
static void check_framing(const std::string& name, const Bytes& good, Decode decode) {
    bool prefixes_rejected = true;
    for (size_t n = 0; n < good.size(); n++)
        if (decode(Bytes(good.begin(), good.begin() + static_cast<std::ptrdiff_t>(n)))) prefixes_rejected = false;
    CHECK(prefixes_rejected, name + ": every truncation is rejected (" + std::to_string(good.size()) + " lengths)");
    Bytes longer = good;
    longer.push_back(0);
    CHECK(!decode(longer), name + ": a trailing byte is rejected");
}

// Random single-byte and multi-byte corruption must never crash. (Whether a mutated message is
// still valid is its decoder's business; this checks robustness.)
template <typename Decode>
static void fuzz(const std::string& name, const Bytes& good, Decode decode) {
    std::mt19937 rng(12345);
    int survived = 0;
    for (int i = 0; i < 3000; i++) {
        Bytes m = good;
        int flips = 1 + static_cast<int>(rng() % 4);
        for (int f = 0; f < flips && !m.empty(); f++) m[rng() % m.size()] = static_cast<uint8_t>(rng());
        if (rng() % 5 == 0 && !m.empty()) m.resize(rng() % m.size());
        decode(m);
        survived++;
    }
    CHECK(survived == 3000, name + ": 3000 random mutations decoded without crashing");
}

int main() {
    std::cout << "Round trips and framing\n";
    {
        Hello h; h.client_nonce = fill(1, NONCE_BYTES);
        auto e = encode(h);
        auto d = decode_hello(e);
        CHECK(d && d->version == WIRE_VERSION && d->client_nonce == h.client_nonce, "hello round trip");
        check_framing("hello", e, decode_hello);
        fuzz("hello", e, decode_hello);
        Hello shortnonce; shortnonce.client_nonce = fill(1, 5);
        CHECK(!decode_hello(encode(shortnonce)), "hello: a nonce of the wrong length is rejected");
    }
    {
        HelloReply r{fill(2, 100), fill(3, 200), fill(4, NONCE_BYTES)};
        auto e = encode(r);
        auto d = decode_hello_reply(e);
        CHECK(d && d->relay_public_key == r.relay_public_key && d->signature == r.signature && d->auth_challenge == r.auth_challenge, "hello reply round trip");
        check_framing("hello reply", e, decode_hello_reply);
        fuzz("hello reply", e, decode_hello_reply);
        HelloReply bad = r; bad.auth_challenge = fill(4, 31);
        CHECK(!decode_hello_reply(encode(bad)), "hello reply: a challenge of the wrong length is rejected");
    }
    {
        Register r{fill(1, INVITE_BYTES), fill(2, MAILBOX_ID_BYTES), fill(3, 300), fill(4, HASH_BYTES), fill(5, 400)};
        auto e = encode(r);
        auto d = decode_register(e);
        CHECK(d && d->invite == r.invite && d->mailbox_id == r.mailbox_id && d->access_public_key == r.access_public_key &&
                  d->send_token_hash == r.send_token_hash && d->signature == r.signature, "register round trip");
        check_framing("register", e, decode_register);
        fuzz("register", e, decode_register);
        Register wrong = r; wrong.mailbox_id = fill(2, 15);
        CHECK(!decode_register(encode(wrong)), "register: a mailbox ID of the wrong length is rejected");
    }
    {
        Auth a{fill(1, MAILBOX_ID_BYTES), fill(2, 500)};
        auto e = encode(a);
        auto d = decode_auth(e);
        CHECK(d && d->mailbox_id == a.mailbox_id && d->signature == a.signature, "auth round trip");
        check_framing("auth", e, decode_auth);
        fuzz("auth", e, decode_auth);
    }
    {
        Deposit dep{fill(1, MAILBOX_ID_BYTES), fill(2, SEND_TOKEN_BYTES), fill(3, 1000), 3600};
        auto e = encode(dep);
        auto d = decode_deposit(e);
        CHECK(d && d->mailbox_id == dep.mailbox_id && d->send_token == dep.send_token && d->envelope == dep.envelope && d->ttl_seconds == 3600, "deposit round trip");
        check_framing("deposit", encode(Deposit{fill(1, MAILBOX_ID_BYTES), fill(2, SEND_TOKEN_BYTES), fill(3, 20), 5}), decode_deposit);
        fuzz("deposit", e, decode_deposit);
        Deposit max{fill(1, MAILBOX_ID_BYTES), fill(2, SEND_TOKEN_BYTES), fill(3, MAX_ENVELOPE_BYTES), 1};
        Deposit over{fill(1, MAILBOX_ID_BYTES), fill(2, SEND_TOKEN_BYTES), fill(3, MAX_ENVELOPE_BYTES + 1), 1};
        CHECK(decode_deposit(encode(max)).has_value() && !decode_deposit(encode(over)), "deposit: the envelope size limit is exact");
        CHECK(encode(max).size() <= MAX_MESSAGE_PAYLOAD, "a maximum-size deposit fits in a maximum-size message");
    }
    {
        StoredEnvelope s{fill(1, ENVELOPE_ID_BYTES), 1700000000, fill(3, HASH_BYTES), fill(2, 300)};
        auto e = encode(s);
        auto d = decode_stored_envelope(e);
        CHECK(d && d->id == s.id && d->deposited_at == s.deposited_at && d->token_hash == s.token_hash && d->envelope == s.envelope, "stored envelope round trip");
        StoredEnvelope short_hash = s; short_hash.token_hash = fill(3, 5);
        CHECK(!decode_stored_envelope(encode(short_hash)), "stored envelope: a token hash of the wrong length is rejected");
        check_framing("stored envelope", e, decode_stored_envelope);
        fuzz("stored envelope", e, decode_stored_envelope);
    }
    {
        IdList l{{fill(1, ENVELOPE_ID_BYTES), fill(2, ENVELOPE_ID_BYTES)}};
        auto e = encode(l);
        auto d = decode_id_list(e);
        CHECK(d && d->ids == l.ids, "id list round trip");
        check_framing("id list", e, decode_id_list);
        fuzz("id list", e, decode_id_list);
        IdList many; for (size_t i = 0; i <= MAX_ACK_IDS; i++) many.ids.push_back(fill(1, ENVELOPE_ID_BYTES));
        CHECK(!decode_id_list(encode(many)), "id list: more than the maximum is rejected");
        Bytes lying; write_u32(lying, 0xFFFFFFFF);
        CHECK(!decode_id_list(lying), "id list: a huge declared count doesn't allocate or hang");
        CHECK(decode_id_list(encode(IdList{})).has_value(), "id list: an empty list is valid");
    }
    {
        HashOp h{fill(9, HASH_BYTES)};
        auto e = encode(h);
        CHECK(decode_hash_op(e) && decode_hash_op(e)->token_hash == h.token_hash, "hash op round trip");
        check_framing("hash op", e, decode_hash_op);
        fuzz("hash op", e, decode_hash_op);
    }
    {
        InviteStatus st;
        st.max_unused = 3;
        st.max_total = 10;
        st.unused = {{fill(1, HASH_BYTES), 1700000000}, {fill(2, HASH_BYTES), 1700000100}};
        st.joined = {{fill(3, MAILBOX_ID_BYTES), 1699999000}};
        auto e = encode(st);
        auto back = decode_invite_status(e);
        CHECK(back && back->max_unused == 3 && back->max_total == 10 && back->unused.size() == 2 && back->unused[1].hash == fill(2, HASH_BYTES) &&
                  back->unused[1].expires_at == 1700000100 && back->joined.size() == 1 && back->joined[0].mailbox_id == fill(3, MAILBOX_ID_BYTES) && back->joined[0].joined_at == 1699999000,
              "invite status round trip");
        check_framing("invite status", e, decode_invite_status);
        fuzz("invite status", e, decode_invite_status);
        CHECK(decode_invite_status(encode(InviteStatus{})).has_value(), "invite status: nothing unused and nobody joined is valid");
        InviteStatus huge;
        for (size_t i = 0; i <= MAX_INVITE_STATUS_ENTRIES; i++) huge.unused.push_back({fill(1, HASH_BYTES), 1});
        CHECK(!decode_invite_status(encode(huge)), "invite status: more entries than the limit is rejected");
        InviteStatus bad_hash;
        bad_hash.unused = {{fill(1, 7), 1}};
        InviteStatus bad_id;
        bad_id.joined = {{fill(1, 5), 1}};
        CHECK(!decode_invite_status(encode(bad_hash)) && !decode_invite_status(encode(bad_id)), "invite status: a hash or mailbox ID of the wrong size is rejected");
        std::vector<uint8_t> lying;
        write_u32(lying, 3); write_u32(lying, 10); write_u32(lying, 0xFFFFFFFF);
        CHECK(!decode_invite_status(lying), "invite status: a declared count of four billion is rejected without allocating");
    }

    std::cout << "Chat archives\n";
    {
        ArchiveCreate c{fill(1, ARCHIVE_ID_BYTES), {fill(2, HASH_BYTES), fill(3, HASH_BYTES), fill(4, HASH_BYTES)}};
        auto e = encode(c);
        auto back = decode_archive_create(e);
        CHECK(back && back->archive_id == c.archive_id && back->join_token_hashes == c.join_token_hashes, "archive create round trip");
        check_framing("archive create", e, decode_archive_create);
        fuzz("archive create", e, decode_archive_create);
        ArchiveCreate none{fill(1, ARCHIVE_ID_BYTES), {}};
        ArchiveCreate many{fill(1, ARCHIVE_ID_BYTES), std::vector<Bytes>(MAX_ARCHIVE_MEMBERS + 1, fill(2, HASH_BYTES))};
        ArchiveCreate full{fill(1, ARCHIVE_ID_BYTES), std::vector<Bytes>(MAX_ARCHIVE_MEMBERS, fill(2, HASH_BYTES))};
        ArchiveCreate bad_id{fill(1, 5), {fill(2, HASH_BYTES)}};
        ArchiveCreate bad_hash{fill(1, ARCHIVE_ID_BYTES), {fill(2, 7)}};
        CHECK(!decode_archive_create(encode(none)) && !decode_archive_create(encode(many)) && decode_archive_create(encode(full)) &&
                  !decode_archive_create(encode(bad_id)) && !decode_archive_create(encode(bad_hash)),
              "archive create: 1 to 16 members, and every ID and hash the right size");
        Bytes lying;
        write_blob(lying, fill(1, ARCHIVE_ID_BYTES)); write_u32(lying, 0xFFFFFFFF);
        CHECK(!decode_archive_create(lying), "archive create: a declared count of four billion is rejected without allocating");

        ArchiveJoin j{fill(1, ARCHIVE_ID_BYTES), fill(2, JOIN_TOKEN_BYTES), fill(3, 100), fill(4, 100)};
        auto je = encode(j);
        auto jb = decode_archive_join(je);
        CHECK(jb && jb->join_token == j.join_token && jb->public_key == j.public_key && jb->signature == j.signature, "archive join round trip");
        check_framing("archive join", je, decode_archive_join);
        fuzz("archive join", je, decode_archive_join);
        CHECK(!decode_archive_join(encode(ArchiveJoin{fill(1, ARCHIVE_ID_BYTES), fill(2, 5), fill(3, 10), fill(4, 10)})), "archive join: a short token is rejected");

        ArchiveAuth a{fill(1, ARCHIVE_ID_BYTES), fill(2, HASH_BYTES), fill(3, 100)};
        auto ae = encode(a);
        CHECK(decode_archive_auth(ae) && decode_archive_auth(ae)->key_hash == a.key_hash, "archive auth round trip");
        check_framing("archive auth", ae, decode_archive_auth);
        fuzz("archive auth", ae, decode_archive_auth);

        ArchiveAppend ap{7, fill(2, HASH_BYTES), fill(9, 500)};
        auto ape = encode(ap);
        auto apb = decode_archive_append(ape);
        CHECK(apb && apb->expected_number == 7 && apb->expected_hash == ap.expected_hash && apb->ciphertext == ap.ciphertext, "archive append round trip");
        check_framing("archive append", ape, decode_archive_append);
        fuzz("archive append", ape, decode_archive_append);
        CHECK(!decode_archive_append(encode(ArchiveAppend{1, fill(2, HASH_BYTES), Bytes()})) && !decode_archive_append(encode(ArchiveAppend{1, fill(2, HASH_BYTES), fill(1, MAX_ARCHIVE_ENTRY_BYTES + 1)})) &&
                  decode_archive_append(encode(ArchiveAppend{1, fill(2, HASH_BYTES), fill(1, MAX_ARCHIVE_ENTRY_BYTES)})) && !decode_archive_append(encode(ArchiveAppend{1, fill(2, 5), fill(1, 10)})),
              "archive append: an entry is 1 byte to 64 KiB, and the head hash is a full hash");

        ArchiveHead h{42, fill(5, HASH_BYTES)};
        auto he = encode(h);
        CHECK(decode_archive_head(he) && decode_archive_head(he)->number == 42, "archive head round trip");
        check_framing("archive head", he, decode_archive_head);
        fuzz("archive head", he, decode_archive_head);

        ArchiveFetch f{3, 100};
        auto fe = encode(f);
        CHECK(decode_archive_fetch(fe) && decode_archive_fetch(fe)->from_number == 3 && decode_archive_fetch(fe)->limit == 100, "archive fetch round trip");
        check_framing("archive fetch", fe, decode_archive_fetch);
        fuzz("archive fetch", fe, decode_archive_fetch);
        CHECK(!decode_archive_fetch(encode(ArchiveFetch{0, 10})) && !decode_archive_fetch(encode(ArchiveFetch{1, 0})) && !decode_archive_fetch(encode(ArchiveFetch{1, MAX_FETCH_ENTRIES + 1})) &&
                  decode_archive_fetch(encode(ArchiveFetch{1, MAX_FETCH_ENTRIES})), "archive fetch: numbers start at 1 and a request is for 1 to 256 entries");

        ArchiveEntry en{5, fill(6, HASH_BYTES), fill(7, 300)};
        auto ee = encode(en);
        CHECK(decode_archive_entry(ee) && decode_archive_entry(ee)->ciphertext == en.ciphertext && decode_archive_entry(ee)->number == 5, "archive entry round trip");
        check_framing("archive entry", ee, decode_archive_entry);
        fuzz("archive entry", ee, decode_archive_entry);
    }

    std::cout << "Archive signing and chain inputs\n";
    {
        Bytes relay_id = fill(1, 32), arch = fill(2, ARCHIVE_ID_BYTES), key = fill(3, 50), token_hash = fill(4, 32), challenge = fill(5, 32), key_hash = fill(6, 32);
        auto join = archive_join_signing_input(relay_id, arch, key, token_hash);
        CHECK(join != archive_join_signing_input(fill(9, 32), arch, key, token_hash) && join != archive_join_signing_input(relay_id, fill(9, ARCHIVE_ID_BYTES), key, token_hash) &&
                  join != archive_join_signing_input(relay_id, arch, fill(9, 50), token_hash) && join != archive_join_signing_input(relay_id, arch, key, fill(9, 32)),
              "a join signature covers the relay, the archive, the key and the token");
        auto auth = archive_auth_signing_input(challenge, relay_id, arch, key_hash);
        CHECK(auth != archive_auth_signing_input(fill(9, 32), relay_id, arch, key_hash) && auth != archive_auth_signing_input(challenge, fill(9, 32), arch, key_hash) &&
                  auth != archive_auth_signing_input(challenge, relay_id, fill(9, ARCHIVE_ID_BYTES), key_hash) && auth != archive_auth_signing_input(challenge, relay_id, arch, fill(9, 32)),
              "an archive sign-in covers the challenge, the relay, the archive and the key");
        CHECK(archive_join_signing_input(relay_id, arch, key, token_hash) != auth && auth != auth_signing_input(challenge, relay_id, arch),
              "each signed message has its own label, so one can't be passed off as another");
        Bytes prev = fill(7, 32), ct = fill(8, 100);
        auto entry = archive_entry_hash_input(arch, 5, prev, ct);
        CHECK(entry != archive_entry_hash_input(fill(9, ARCHIVE_ID_BYTES), 5, prev, ct) && entry != archive_entry_hash_input(arch, 6, prev, ct) &&
                  entry != archive_entry_hash_input(arch, 5, fill(9, 32), ct) && entry != archive_entry_hash_input(arch, 5, prev, fill(9, 100)),
              "an entry's hash covers the archive, its number, the previous head and its ciphertext");
        CHECK(archive_genesis_input(arch) != archive_genesis_input(fill(9, ARCHIVE_ID_BYTES)) && archive_genesis_input(arch) != entry, "each archive has its own genesis");
    }

    std::cout << "Signing inputs\n";
    {
        Bytes nonce = fill(1, 32), relay_id = fill(2, 32), chal = fill(3, 32), mailbox = fill(4, 16), key = fill(5, 100), th = fill(6, 32);
        auto hello = hello_signing_input(nonce, relay_id, 3, chal);
        auto reg = register_signing_input(relay_id, mailbox, key, th);
        auto auth = auth_signing_input(chal, relay_id, mailbox);
        CHECK(hello != reg && hello != auth && reg != auth, "each purpose has its own signing input");
        CHECK(hello_signing_input(fill(9, 32), relay_id, 3, chal) != hello, "the client nonce is covered");
        CHECK(hello_signing_input(nonce, fill(9, 32), 3, chal) != hello, "the relay ID is covered");
        CHECK(hello_signing_input(nonce, relay_id, 4, chal) != hello, "the version is covered");
        CHECK(hello_signing_input(nonce, relay_id, 3, fill(9, 32)) != hello, "the auth challenge is covered");
        CHECK(auth_signing_input(fill(9, 32), relay_id, mailbox) != auth && auth_signing_input(chal, fill(9, 32), mailbox) != auth &&
                  auth_signing_input(chal, relay_id, fill(9, 16)) != auth, "auth covers the challenge, the relay and the mailbox");
        CHECK(register_signing_input(fill(9, 32), mailbox, key, th) != reg && register_signing_input(relay_id, fill(9, 16), key, th) != reg &&
                  register_signing_input(relay_id, mailbox, fill(9, 100), th) != reg && register_signing_input(relay_id, mailbox, key, fill(9, 32)) != reg,
              "register covers the relay, mailbox, access key and token hash");
        // Field boundaries are unambiguous: moving a byte between adjacent fields changes the input.
        CHECK(auth_signing_input(fill(3, 31), relay_id, mailbox) != auth_signing_input(fill(3, 32), relay_id, mailbox), "fields are length-prefixed");
    }

    std::cout << "Relay invite strings\n";
    {
        RelayInvite inv{{"10.8.0.1", 9000}, fill(0xAB, 32), fill(0xCD, 16)};
        std::string text = build_relay_invite(inv);
        auto p = parse_relay_invite(text);
        CHECK(p && p->server.host == "10.8.0.1" && p->server.port == 9000 && p->relay_id == inv.relay_id && p->invite == inv.invite, "round trip: " + text.substr(0, 40) + "...");
        RelayInvite v6{{"fd00::1", 9100}, fill(0x01, 32), fill(0x02, 16)};
        auto p6 = parse_relay_invite(build_relay_invite(v6));
        CHECK(p6 && p6->server.host == "fd00::1" && p6->server.port == 9100, "IPv6 and a custom port");

        std::string dashed = "pqft-relay://10.8.0.1:9000/" + bytes_to_hex(inv.relay_id) + "/cdcd-cdcd-cdcd-cdcd-cdcd-cdcd-cdcd-cdcd";
        CHECK(parse_relay_invite("  <" + dashed + ">. ").has_value(), "tolerates the grouped code the server prints, plus whitespace and <>");
        for (std::string bad : std::vector<std::string>{"", "pqft-relay://", "pqft-relay://10.8.0.1/abc/def", "http://10.8.0.1/x/y",
                 "pqft-relay://ho st/" + bytes_to_hex(inv.relay_id) + "/" + bytes_to_hex(inv.invite),
                 "pqft-relay://10.8.0.1/" + bytes_to_hex(fill(1, 31)) + "/" + bytes_to_hex(inv.invite),
                 "pqft-relay://10.8.0.1/" + bytes_to_hex(inv.relay_id) + "/" + bytes_to_hex(fill(1, 15)),
                 "pqft-relay://10.8.0.1/" + bytes_to_hex(inv.relay_id)})
            CHECK(!parse_relay_invite(bad), "rejects '" + bad.substr(0, 36) + "'");
        auto hex = hex_to_bytes("00ffAb");
        CHECK(hex && *hex == (Bytes{0x00, 0xFF, 0xAB}) && !hex_to_bytes("abc") && !hex_to_bytes("zz"), "hex_to_bytes accepts both cases and rejects bad input");
    }

    std::cout << (failures ? "\nFAILURES: " : "\nAll checks passed. ") << failures << "\n";
    return failures ? 1 : 0;
}
