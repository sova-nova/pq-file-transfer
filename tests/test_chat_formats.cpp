// Tests for signed message records and sealed envelopes.
#include "archive.h"
#include "attachment.h"
#include "crypto_engine.h"
#include "keyring.h"
#include "envelope.h"
#include "message_record.h"
#include "protocol.h"
#include "relay_protocol.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <functional>
#include <set>
#include <iostream>
#include <string>
#include <unistd.h>

using namespace chat;

static int failures = 0;
#define CHECK(c, msg)                                                  \
    do {                                                               \
        if (c) std::cout << "  PASS " << (msg) << "\n";                \
        else { std::cout << "  FAIL " << (msg) << "\n"; failures++; } \
    } while (0)

static bool has(const std::string& s, const char* needle) { return s.find(needle) != std::string::npos; }
template <typename F> static bool throws(F f) { try { f(); } catch (const std::exception&) { return true; } return false; }

struct Person {
    CryptoEngine::SigKeyPair sig;
    CryptoEngine::KEMKeyPair kem;
    Bytes fingerprint;  // raw SHA-256 of the signing key
    Person() : sig(CryptoEngine::generate_sig_keypair()), kem(CryptoEngine::generate_kem_keypair()), fingerprint(CryptoEngine::sha256(sig.public_key)) {}
};

static Record make_record(const Person& from, const Person& to, const std::string& text, RecordType type = RecordType::Text) {
    Record r;
    r.conversation_id = conversation_id_for(from.fingerprint, to.fingerprint);
    r.message_id = CryptoEngine::random_bytes(ID_BYTES);
    r.sender = from.fingerprint;
    r.recipients_hash = recipients_hash_for({from.fingerprint, to.fingerprint});
    r.sent_at = 1700000000;
    r.type = type;
    r.payload = Bytes(text.begin(), text.end());
    return r;
}

static bool contains(const Bytes& haystack, const std::string& needle) {
    return std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end()) != haystack.end();
}


// A record body written by hand, so tests can produce what other versions (or an attacker) would send.
static Bytes hand_record(const Person& signer, uint32_t version, uint32_t type, const Bytes& sender, const Bytes& recipients,
                         const Bytes& payload, const Bytes& own_prev, const std::function<void(Bytes&)>& seen_field) {
    Bytes body;
    write_u32(body, 0x50514D52);  // "PQMR"
    write_u32(body, version);
    write_blob(body, CryptoEngine::random_bytes(ID_BYTES));  // conversation
    write_blob(body, CryptoEngine::random_bytes(ID_BYTES));  // message
    write_blob(body, sender);
    write_blob(body, recipients);
    write_u64(body, 1700000000);
    write_u32(body, type);
    write_blob(body, payload);
    write_blob(body, own_prev);
    seen_field(body);
    Bytes input;
    write_string(input, "pq-suite v3 message");
    write_bytes(input, body.data(), body.size());
    Bytes raw;
    write_blob(raw, body);
    write_blob(raw, CryptoEngine::sign(input, signer.sig.private_key));
    return raw;
}

// A group payload written by hand, with every field under the test's control.
static Bytes hand_payload(uint32_t version, const std::string& title, uint32_t mode, uint64_t timer, const Bytes& previous,
                          const std::vector<Bytes>& members, uint32_t declared_count) {
    Bytes p;
    write_u32(p, version);
    write_blob(p, Bytes(title.begin(), title.end()));
    write_u32(p, mode);
    write_u64(p, timer);
    write_blob(p, previous);
    write_u32(p, declared_count);
    for (const auto& m : members) write_blob(p, m);
    return p;
}

// How many one-bit changes to the signed body still parse AND verify. Must be 0.
static int accepted_after_bit_flips(const Bytes& raw, const Bytes& signing_public_key) {
    size_t body_len = (static_cast<size_t>(raw[0]) << 24) | (static_cast<size_t>(raw[1]) << 16) | (static_cast<size_t>(raw[2]) << 8) | raw[3];
    int accepted = 0;
    for (size_t i = 4; i < 4 + body_len; i++) {
        Bytes bad = raw;
        bad[i] ^= 0x01;
        auto p = parse_record(bad);
        if (p && verify_record(*p, signing_public_key)) accepted++;
    }
    return accepted;
}

static bool every_prefix_rejected(const Bytes& raw) {
    for (size_t n = 0; n < raw.size(); n++)
        if (parse_record(Bytes(raw.begin(), raw.begin() + static_cast<std::ptrdiff_t>(n)))) return false;
    return true;
}

int main() {
    Person alice, bob, mallory;

    std::cout << "Conversation and recipient identifiers\n";
    {
        CHECK(conversation_id_for(alice.fingerprint, bob.fingerprint) == conversation_id_for(bob.fingerprint, alice.fingerprint), "the one-to-one conversation ID is the same from both sides");
        CHECK(conversation_id_for(alice.fingerprint, bob.fingerprint) != conversation_id_for(alice.fingerprint, mallory.fingerprint), "...and different for every other pair");
        CHECK(conversation_id_for(alice.fingerprint, bob.fingerprint).size() == ID_BYTES, "it is 16 bytes");
        CHECK(recipients_hash_for({alice.fingerprint, bob.fingerprint}) == recipients_hash_for({bob.fingerprint, alice.fingerprint}), "the recipients hash doesn't depend on order");
        CHECK(recipients_hash_for({alice.fingerprint, bob.fingerprint}) != recipients_hash_for({alice.fingerprint, mallory.fingerprint}), "it changes with the people");
        CHECK(recipients_hash_for({alice.fingerprint, bob.fingerprint}) != recipients_hash_for({alice.fingerprint, bob.fingerprint, mallory.fingerprint}), "...and with their number");
    }

    std::cout << "Signed records\n";
    {
        Record r = make_record(alice, bob, "hello Bob");
        r.own_prev = CryptoEngine::random_bytes(HASH_BYTES);
        r.seen = {CryptoEngine::random_bytes(HASH_BYTES)};
        Bytes raw = sign_record(r, alice.sig.private_key);
        auto parsed = parse_record(raw);
        CHECK(parsed && parsed->record.payload == r.payload && parsed->record.message_id == r.message_id && parsed->record.own_prev == r.own_prev &&
                  parsed->record.seen == r.seen && parsed->record.sent_at == r.sent_at && parsed->record.type == RecordType::Text, "a record round-trips with every field");
        CHECK(parsed && parsed->entry_hash == CryptoEngine::sha256(raw), "its entry hash is the SHA-256 of the signed bytes");
        CHECK(parsed && verify_record(*parsed, alice.sig.public_key), "it verifies under the sender's key");
        CHECK(parsed && !verify_record(*parsed, bob.sig.public_key), "...and not under anyone else's");

        // Every byte of the signed body is covered: change any one and it must no longer verify.
        size_t body_len = (static_cast<size_t>(raw[0]) << 24) | (static_cast<size_t>(raw[1]) << 16) | (static_cast<size_t>(raw[2]) << 8) | raw[3];
        int accepted = 0;
        for (size_t i = 4; i < 4 + body_len; i++) {
            Bytes bad = raw;
            bad[i] ^= 0x01;
            auto p = parse_record(bad);
            if (p && verify_record(*p, alice.sig.public_key)) accepted++;
        }
        CHECK(accepted == 0, "a one-bit change anywhere in the signed body is detected (" + std::to_string(body_len) + " positions)");
        Bytes bad_sig = raw; bad_sig[4 + body_len + 4] ^= 1;
        auto ps = parse_record(bad_sig);
        CHECK(ps && !verify_record(*ps, alice.sig.public_key), "a changed signature is detected");

        bool all_prefixes_rejected = true;
        for (size_t n = 0; n < raw.size(); n++)
            if (parse_record(Bytes(raw.begin(), raw.begin() + static_cast<std::ptrdiff_t>(n)))) all_prefixes_rejected = false;
        CHECK(all_prefixes_rejected, "every truncation is rejected");
        Bytes longer = raw; longer.push_back(0);
        CHECK(!parse_record(longer) && !parse_record({}) && !parse_record(Bytes(100, 0xFF)), "trailing bytes, empty input and garbage are rejected");

        // A valid signature isn't enough: the record must claim to be from the key that signed it.
        Record lie = make_record(alice, bob, "I am Alice");
        lie.sender = alice.fingerprint;
        Bytes signed_by_mallory = sign_record(lie, mallory.sig.private_key);
        auto lp = parse_record(signed_by_mallory);
        CHECK(lp && !verify_record(*lp, mallory.sig.public_key), "a record claiming to be from Alice but signed by Mallory fails against Mallory's key");
        CHECK(lp && !verify_record(*lp, alice.sig.public_key), "...and against Alice's");
    }

    std::cout << "Record limits\n";
    {
        CHECK(!throws([&] { sign_record(make_record(alice, bob, std::string(MAX_TEXT_BYTES, 'x')), alice.sig.private_key); }), "a 32 KiB message is accepted");
        CHECK(throws([&] { sign_record(make_record(alice, bob, std::string(MAX_TEXT_BYTES + 1, 'x')), alice.sig.private_key); }), "one byte more is refused");
        Record bad_ids = make_record(alice, bob, "x");
        bad_ids.message_id.resize(5);
        CHECK(throws([&] { sign_record(bad_ids, alice.sig.private_key); }), "a message ID of the wrong size is refused");
        Record bad_prev = make_record(alice, bob, "x");
        bad_prev.own_prev = Bytes(7, 1);
        CHECK(throws([&] { sign_record(bad_prev, alice.sig.private_key); }), "a previous-entry hash of the wrong size is refused");
        CHECK(throws([&] { sign_record(make_record(alice, bob, "tiny", RecordType::TokenGrant), alice.sig.private_key); }), "a token grant must carry exactly 32 bytes");
        CHECK(!throws([&] { Record g = make_record(alice, bob, ""); g.type = RecordType::TokenGrant; g.payload = CryptoEngine::random_bytes(32); sign_record(g, alice.sig.private_key); }), "...and 32 is fine");
    }

    std::cout << "Receipts\n";
    {
        std::vector<Bytes> ids = {CryptoEngine::random_bytes(16), CryptoEngine::random_bytes(16)};
        auto payload = receipt_payload(ReceiptKind::Read, ids);
        auto info = parse_receipt_payload(payload);
        CHECK(info && info->kind == ReceiptKind::Read && info->message_ids == ids, "a receipt names the messages it covers");
        CHECK(parse_receipt_payload(receipt_payload(ReceiptKind::Delivered, {})).has_value(), "an empty receipt is valid");
        CHECK(throws([&] { receipt_payload(ReceiptKind::Read, std::vector<Bytes>(257, ids[0])); }), "more than 256 messages in one receipt is refused");
        Bytes wrong_kind = payload; wrong_kind[0] = 9;
        CHECK(!parse_receipt_payload(wrong_kind) && !parse_receipt_payload({}), "an unknown kind or empty payload is rejected");
        Bytes trailing = payload; trailing.push_back(0);
        CHECK(!parse_receipt_payload(trailing), "trailing bytes are rejected");
        bool prefixes = true;
        for (size_t n = 0; n < payload.size(); n++) if (parse_receipt_payload(Bytes(payload.begin(), payload.begin() + static_cast<std::ptrdiff_t>(n)))) prefixes = false;
        CHECK(prefixes, "every truncation is rejected");
        Bytes lying; lying.push_back(1); write_u32(lying, 0xFFFFFFFF);
        CHECK(!parse_receipt_payload(lying), "a huge declared count doesn't allocate or hang");
    }

    std::cout << "Sealed envelopes\n";
    {
        Inner inner;
        inner.sender_bundle = CryptoEngine::random_bytes(3000);
        inner.records = {sign_record(make_record(alice, bob, "the quick brown fox"), alice.sig.private_key),
                         sign_record(make_record(alice, bob, "second record"), alice.sig.private_key)};
        Bytes env = seal_envelope(inner, bob.kem.public_key);
        auto opened = open_envelope(env, bob.kem.private_key);
        CHECK(opened && opened->sender_bundle == inner.sender_bundle && opened->records == inner.records, "an envelope opens to exactly what was sealed");
        CHECK(!contains(env, "the quick brown fox") && !contains(env, "second record"), "the content is not visible in the envelope");
        CHECK(open_envelope(env, mallory.kem.private_key) == std::nullopt, "the wrong recipient cannot open it");
        CHECK(env != seal_envelope(inner, bob.kem.public_key), "sealing the same thing twice gives different envelopes (fresh key each time)");

        int opened_after_tamper = 0;
        for (size_t i = 0; i < env.size(); i++) {
            Bytes bad = env;
            bad[i] ^= 0x01;
            if (open_envelope(bad, bob.kem.private_key)) opened_after_tamper++;
        }
        CHECK(opened_after_tamper == 0, "a one-bit change anywhere in the envelope is refused (" + std::to_string(env.size()) + " positions)");
        bool prefixes = true;
        for (size_t n : {0u, 1u, 4u, 100u, 1000u, 1500u, (unsigned)env.size() - 1}) if (open_envelope(Bytes(env.begin(), env.begin() + static_cast<std::ptrdiff_t>(n)), bob.kem.private_key)) prefixes = false;
        Bytes longer = env; longer.push_back(0);
        CHECK(prefixes && !open_envelope(longer, bob.kem.private_key) && !open_envelope({}, bob.kem.private_key), "truncated, extended and empty envelopes are refused");
    }

    std::cout << "Records: what the sender had seen\n";
    {
        std::vector<Bytes> heads;
        for (int i = 0; i < 3; i++) heads.push_back(CryptoEngine::random_bytes(HASH_BYTES));
        Record r = make_record(alice, bob, "message to a group");
        r.own_prev = CryptoEngine::random_bytes(HASH_BYTES);
        r.seen = heads;
        Bytes raw = sign_record(r, alice.sig.private_key);
        auto parsed = parse_record(raw);
        CHECK(parsed && parsed->record.seen == heads && parsed->record.own_prev == r.own_prev, "a record keeps the list of latest hashes it has seen, in order");
        CHECK(parsed && verify_record(*parsed, alice.sig.public_key), "...and verifies");
        Record swapped = r;
        std::swap(swapped.seen[0], swapped.seen[1]);
        CHECK(sign_record(swapped, alice.sig.private_key) != raw, "the order of the list is part of what is signed");
        Record shorter = r;
        shorter.seen.pop_back();
        CHECK(sign_record(shorter, alice.sig.private_key) != raw, "...and so is its length");
        CHECK(accepted_after_bit_flips(raw, alice.sig.public_key) == 0, "a one-bit change anywhere in a record with a seen list is detected");
        CHECK(every_prefix_rejected(raw), "every truncation of it is rejected");

        Record none = r;
        none.seen.clear();
        auto empty = parse_record(sign_record(none, alice.sig.private_key));
        CHECK(empty && empty->record.seen.empty(), "a record that has seen nothing has an empty list");

        Record fifteen = r;
        fifteen.seen.clear();
        for (size_t i = 0; i < MAX_SEEN; i++) fifteen.seen.push_back(CryptoEngine::random_bytes(HASH_BYTES));
        auto big = parse_record(sign_record(fifteen, alice.sig.private_key));
        CHECK(big && big->record.seen == fifteen.seen, "15 entries (the other members of a 16-person group) are accepted");
        Record sixteen = fifteen;
        sixteen.seen.push_back(CryptoEngine::random_bytes(HASH_BYTES));
        CHECK(throws([&] { sign_record(sixteen, alice.sig.private_key); }), "16 are refused");
        Record wrong_size = r;
        wrong_size.seen[1] = Bytes(7, 1);
        CHECK(throws([&] { sign_record(wrong_size, alice.sig.private_key); }), "an entry of the wrong size is refused");
        Record twice = r;
        twice.seen[2] = twice.seen[0];
        CHECK(throws([&] { sign_record(twice, alice.sig.private_key); }), "naming the same entry twice is refused");

        // What an attacker (or a broken client) could put on the wire.
        Bytes ok_hash = CryptoEngine::random_bytes(HASH_BYTES);
        auto with_seen = [&](const std::function<void(Bytes&)>& field) {
            return parse_record(hand_record(alice, 2, 1, alice.fingerprint, recipients_hash_for({alice.fingerprint, bob.fingerprint}), Bytes{'h', 'i'}, Bytes(), field));
        };
        CHECK(with_seen([&](Bytes& b) { write_u32(b, 1); write_blob(b, ok_hash); }).has_value(), "(control) a hand-written version 2 record with one seen entry parses");
        CHECK(!with_seen([&](Bytes& b) { write_u32(b, 0xFFFFFFFF); }), "a declared count of four billion is rejected without allocating");
        CHECK(!with_seen([&](Bytes& b) { write_u32(b, 16); for (int i = 0; i < 16; i++) write_blob(b, CryptoEngine::random_bytes(HASH_BYTES)); }), "a declared count of 16 is rejected");
        CHECK(!with_seen([&](Bytes& b) { write_u32(b, 3); write_blob(b, ok_hash); }), "a count larger than the entries present is rejected");
        CHECK(!with_seen([&](Bytes& b) { write_u32(b, 1); write_blob(b, ok_hash); write_blob(b, ok_hash); }), "extra bytes after the list are rejected");
        CHECK(!with_seen([&](Bytes& b) { write_u32(b, 2); write_blob(b, ok_hash); write_blob(b, ok_hash); }), "the same hash twice is rejected");
        CHECK(!with_seen([&](Bytes& b) { write_u32(b, 1); write_blob(b, Bytes(5, 1)); }), "an entry that is not 32 bytes is rejected");
    }

    std::cout << "Records made by the first version are still read\n";
    {
        Bytes recipients = recipients_hash_for({alice.fingerprint, bob.fingerprint});
        Bytes seen_hash = CryptoEngine::random_bytes(HASH_BYTES);
        auto old_record = [&](uint32_t version, uint32_t type, const Bytes& seen_blob) {
            return hand_record(alice, version, type, alice.fingerprint, recipients, Bytes{'o', 'l', 'd'}, Bytes(), [&](Bytes& b) { write_blob(b, seen_blob); });
        };
        Bytes raw1 = old_record(1, 1, seen_hash);
        auto p1 = parse_record(raw1);
        CHECK(p1 && p1->record.seen == std::vector<Bytes>{seen_hash} && p1->record.type == RecordType::Text, "a version 1 record parses, its single seen hash becoming a list of one");
        CHECK(p1 && verify_record(*p1, alice.sig.public_key), "its signature still verifies");
        CHECK(p1 && p1->entry_hash == CryptoEngine::sha256(raw1), "its entry hash is still the SHA-256 of its bytes (so old chains stay valid)");
        auto p0 = parse_record(old_record(1, 1, Bytes()));
        CHECK(p0 && p0->record.seen.empty(), "a version 1 record with nothing seen has an empty list");
        CHECK(accepted_after_bit_flips(raw1, alice.sig.public_key) == 0, "a one-bit change anywhere in a version 1 record is still detected");
        CHECK(!parse_record(old_record(1, 1, Bytes(5, 1))), "a version 1 seen field that is neither empty nor 32 bytes is rejected");
        // Same record, same fields, nothing else wrong with it: only the version differs.
        auto creation_type = [&](uint32_t version) {
            return parse_record(hand_record(alice, version, 4, alice.fingerprint, recipients, Bytes{'x'}, Bytes(), [&](Bytes& b) { if (version == 1) write_blob(b, Bytes()); else write_u32(b, 0); }));
        };
        CHECK(creation_type(2).has_value(), "(control) a record of type 4 is accepted as version 2");
        CHECK(!creation_type(1), "...but not as version 1: a group creation record cannot predate version 2");
        CHECK(!parse_record(old_record(0, 1, seen_hash)) && !parse_record(old_record(3, 1, seen_hash)), "versions 0 and 3 are not understood");
        CHECK(parse_record(old_record(1, 3, seen_hash)) == std::nullopt, "(a version 1 token grant needs its 32-byte payload, so this 3-byte one is rejected)");
    }

    std::cout << "Group creation records\n";
    {
        Person carol, dave;
        ConversationInfo info;
        info.title = "Hiking friends";
        info.members = {alice.fingerprint, bob.fingerprint, carol.fingerprint};

        auto creation = [&](const ConversationInfo& i, const Person& signer, const Bytes& claimed_sender, const Bytes& recipients) {
            Record r;
            r.conversation_id = CryptoEngine::random_bytes(ID_BYTES);
            r.message_id = CryptoEngine::random_bytes(ID_BYTES);
            r.sender = claimed_sender;
            r.recipients_hash = recipients;
            r.sent_at = 1700000000;
            r.type = RecordType::Conversation;
            r.payload = conversation_payload(i);
            return sign_record(r, signer.sig.private_key);
        };
        Bytes raw = creation(info, alice, alice.fingerprint, recipients_hash_for(info.members));

        auto payload = conversation_payload(info);
        auto decoded = parse_conversation_payload(payload);
        CHECK(decoded && decoded->title == info.title && decoded->mode == ConversationMode::Saved && decoded->timer_seconds == 0 &&
                  decoded->previous_id.empty() && decoded->members == info.members,
              "a group's details round-trip: title, mode, timer, previous conversation and members in order");
        auto parsed = parse_record(raw);
        auto from_record = parsed ? conversation_from_record(*parsed) : std::nullopt;
        CHECK(parsed && verify_record(*parsed, alice.sig.public_key) && from_record && from_record->members == info.members && from_record->title == info.title,
              "a creation record parses, verifies under the creator's key and yields the group");
        CHECK(parsed && !verify_record(*parsed, bob.sig.public_key), "...and not under anyone else's");

        ConversationInfo linked = info;
        linked.previous_id = CryptoEngine::random_bytes(ID_BYTES);
        auto linked_back = parse_conversation_payload(conversation_payload(linked));
        CHECK(linked_back && linked_back->previous_id == linked.previous_id, "a link to the conversation it replaces is kept");
        ConversationInfo reordered = info;
        std::reverse(reordered.members.begin(), reordered.members.end());
        auto reordered_record = parse_record(creation(reordered, alice, alice.fingerprint, recipients_hash_for(info.members)));
        auto reordered_info = reordered_record ? conversation_from_record(*reordered_record) : std::nullopt;
        CHECK(reordered_info && reordered_info->members == reordered.members, "the member order is the creator's, while the recipients hash doesn't depend on it");
        ConversationInfo untitled = info;
        untitled.title.clear();
        CHECK(parse_conversation_payload(conversation_payload(untitled)).has_value(), "a group may have no title");

        CHECK(accepted_after_bit_flips(raw, alice.sig.public_key) == 0, "a one-bit change anywhere in a creation record is detected (every field is signed)");
        CHECK(every_prefix_rejected(raw), "every truncation of it is rejected");
        Bytes longer = raw; longer.push_back(0);
        CHECK(!parse_record(longer), "trailing bytes are rejected");

        // What may be shown as a title.
        auto with_title = [&](const std::string& title) { ConversationInfo i = info; i.title = title; return i; };
        CHECK(!throws([&] { conversation_payload(with_title(std::string(MAX_TITLE_BYTES, 'x'))); }), "a title of exactly 64 bytes is accepted");
        CHECK(throws([&] { conversation_payload(with_title(std::string(MAX_TITLE_BYTES + 1, 'x'))); }), "65 bytes is refused");
        CHECK(!throws([&] { conversation_payload(with_title("Wanderg\xC3\xBCnge \xE2\x9B\xB0 \xF0\x9F\x8F\x94 \xD0\x93\xD0\xBE\xD1\x80\xD1\x8B")); }), "ordinary Unicode (accents, symbols, an emoji, Cyrillic) is accepted");
        CHECK(throws([&] { conversation_payload(with_title("two\nlines")); }) && throws([&] { conversation_payload(with_title(std::string("nul\0byte", 8))); }) &&
                  throws([&] { conversation_payload(with_title("\x7f")); }) && throws([&] { conversation_payload(with_title("\xC2\x85")); }),
              "control characters are refused (newline, NUL, DEL and the C1 range)");
        CHECK(throws([&] { conversation_payload(with_title("evil \xE2\x80\xAE" "gnp.exe")); }) && throws([&] { conversation_payload(with_title("\xE2\x81\xA7x")); }),
              "characters that reorder how text displays (right-to-left override, isolates) are refused");
        CHECK(throws([&] { conversation_payload(with_title("\xC0\x80")); }) && throws([&] { conversation_payload(with_title("\xFF")); }) &&
                  throws([&] { conversation_payload(with_title("\xE2\x82")); }) && throws([&] { conversation_payload(with_title("\xED\xA0\x80")); }) &&
                  throws([&] { conversation_payload(with_title("\xF4\x90\x80\x80")); }),
              "invalid UTF-8 is refused (overlong, stray byte, truncated, surrogate, beyond U+10FFFF)");

        // What may be in the rest of it.
        ConversationInfo bad = info;
        bad.mode = static_cast<ConversationMode>(2);
        CHECK(throws([&] { conversation_payload(bad); }), "a mode other than Saved is refused for now");
        bad = info; bad.timer_seconds = 3600;
        CHECK(throws([&] { conversation_payload(bad); }), "a timer on a Saved chat is refused");
        bad = info; bad.previous_id = Bytes(5, 1);
        CHECK(throws([&] { conversation_payload(bad); }), "a previous-conversation ID of the wrong size is refused");
        bad = info; bad.members = {alice.fingerprint};
        CHECK(throws([&] { conversation_payload(bad); }), "a group of one is refused");
        bad = info; bad.members = {alice.fingerprint, alice.fingerprint, bob.fingerprint};
        CHECK(throws([&] { conversation_payload(bad); }), "listing someone twice is refused");
        bad = info; bad.members.push_back(Bytes(7, 1));
        CHECK(throws([&] { conversation_payload(bad); }), "a member that is not 32 bytes is refused");
        std::vector<Bytes> many;
        for (size_t i = 0; i < MAX_GROUP_MEMBERS; i++) many.push_back(CryptoEngine::random_bytes(HASH_BYTES));
        bad = info; bad.title = std::string(MAX_TITLE_BYTES, 'x'); bad.members = many;
        Bytes full_payload = conversation_payload(bad);
        CHECK(full_payload.size() <= MAX_CONVERSATION_PAYLOAD && parse_conversation_payload(full_payload).has_value(), "16 members and a full-length title are accepted, within the payload limit (" + std::to_string(full_payload.size()) + " bytes)");
        bad.members.push_back(CryptoEngine::random_bytes(HASH_BYTES));
        CHECK(throws([&] { conversation_payload(bad); }), "17 members are refused");

        // Hostile payloads, written by hand.
        std::vector<Bytes> three = info.members;
        Bytes none_prev;
        CHECK(parse_conversation_payload(hand_payload(1, "ok", 1, 0, none_prev, three, 3)).has_value(), "(control) a hand-written payload parses");
        CHECK(!parse_conversation_payload(hand_payload(2, "ok", 1, 0, none_prev, three, 3)) && !parse_conversation_payload(hand_payload(0, "ok", 1, 0, none_prev, three, 3)), "an unknown payload version is rejected");
        CHECK(!parse_conversation_payload(hand_payload(1, "ok", 2, 0, none_prev, three, 3)) && !parse_conversation_payload(hand_payload(1, "ok", 0, 0, none_prev, three, 3)), "an unknown mode is rejected");
        CHECK(!parse_conversation_payload(hand_payload(1, "ok", 1, 1, none_prev, three, 3)) && !parse_conversation_payload(hand_payload(1, "ok", 1, 0xFFFFFFFFFFFFFFFFull, none_prev, three, 3)), "a timer is rejected");
        CHECK(!parse_conversation_payload(hand_payload(1, "ok", 1, 0, none_prev, three, 0xFFFFFFFF)), "a declared member count of four billion is rejected without allocating");
        CHECK(!parse_conversation_payload(hand_payload(1, "ok", 1, 0, none_prev, three, 17)) && !parse_conversation_payload(hand_payload(1, "ok", 1, 0, none_prev, {three[0]}, 1)) &&
                  !parse_conversation_payload(hand_payload(1, "ok", 1, 0, none_prev, three, 4)), "a member count that is too large, too small or larger than the list is rejected");
        CHECK(!parse_conversation_payload(hand_payload(1, "ok", 1, 0, none_prev, {three[0], three[0], three[1]}, 3)), "a duplicated member is rejected");
        CHECK(!parse_conversation_payload(hand_payload(1, "ok", 1, 0, none_prev, {three[0], Bytes(31, 1), three[2]}, 3)), "a member of the wrong size is rejected");
        CHECK(!parse_conversation_payload(hand_payload(1, "a\nb", 1, 0, none_prev, three, 3)) && !parse_conversation_payload(hand_payload(1, "\xFF", 1, 0, none_prev, three, 3)), "a bad title is rejected on the receiving side too");
        Bytes with_trailing = payload; with_trailing.push_back(0);
        CHECK(!parse_conversation_payload(with_trailing), "trailing bytes are rejected");
        bool payload_prefixes = true;
        for (size_t n = 0; n < payload.size(); n++)
            if (parse_conversation_payload(Bytes(payload.begin(), payload.begin() + static_cast<std::ptrdiff_t>(n)))) payload_prefixes = false;
        CHECK(payload_prefixes && !parse_conversation_payload(Bytes()) && !parse_conversation_payload(Bytes(5000, 0xFF)), "every truncation, an empty payload and garbage are rejected");

        // The record around it.
        auto accepts = [&](const Bytes& record_bytes) {
            auto sr = parse_record(record_bytes);
            return sr && conversation_from_record(*sr).has_value();
        };
        CHECK(accepts(raw), "(control) the genuine creation record is accepted");
        ConversationInfo without_alice = info;
        without_alice.members = {bob.fingerprint, carol.fingerprint, dave.fingerprint};
        CHECK(!accepts(creation(without_alice, alice, alice.fingerprint, recipients_hash_for(without_alice.members))), "a creator who is not one of the members is rejected");
        CHECK(!accepts(creation(info, alice, alice.fingerprint, recipients_hash_for({alice.fingerprint, bob.fingerprint}))), "a recipients hash for fewer people than the list names is rejected");
        CHECK(!accepts(creation(info, alice, alice.fingerprint, recipients_hash_for({alice.fingerprint, bob.fingerprint, mallory.fingerprint}))), "...and one for different people");
        CHECK(!accepts(creation(info, alice, alice.fingerprint, Bytes(HASH_BYTES, 0))), "...and an arbitrary one");
        Record text_record = make_record(alice, bob, "just a message");
        auto text_parsed = parse_record(sign_record(text_record, alice.sig.private_key));
        CHECK(text_parsed && !conversation_from_record(*text_parsed), "an ordinary message is not a creation record");
        Bytes forged = creation(info, mallory, alice.fingerprint, recipients_hash_for(info.members));
        auto forged_parsed = parse_record(forged);
        CHECK(forged_parsed && !verify_record(*forged_parsed, alice.sig.public_key) && !verify_record(*forged_parsed, mallory.sig.public_key),
              "a creation record claiming to be from Alice but signed by Mallory verifies under neither key");

        Record r = make_record(alice, bob, "");
        r.type = RecordType::Conversation;
        r.conversation_id = CryptoEngine::random_bytes(ID_BYTES);
        r.payload = payload;
        r.recipients_hash = recipients_hash_for(info.members);
        Record with_prev = r; with_prev.own_prev = CryptoEngine::random_bytes(HASH_BYTES);
        Record with_seen = r; with_seen.seen = {CryptoEngine::random_bytes(HASH_BYTES)};
        Record oversized = r; oversized.payload = Bytes(MAX_CONVERSATION_PAYLOAD + 1, 0);
        CHECK(throws([&] { sign_record(with_prev, alice.sig.private_key); }) && throws([&] { sign_record(with_seen, alice.sig.private_key); }),
              "a creation record cannot claim an earlier entry or anything seen (nothing came before it)");
        CHECK(throws([&] { sign_record(oversized, alice.sig.private_key); }), "a creation payload over the limit is refused");
        ConversationInfo largest;  // 16 members and a full-length title
        largest.title = std::string(MAX_TITLE_BYTES, 'x');
        largest.members = many;
        Bytes full_record = creation(largest, alice, many[0], recipients_hash_for(many));
        CHECK(largest.members.size() == MAX_GROUP_MEMBERS && full_record.size() < 5000 && full_record.size() <= MAX_RECORD_BYTES,
              "the largest creation record (16 members, full title) is about 4 KB (" + std::to_string(full_record.size()) + " bytes)");
    }

    std::cout << "Envelopes that introduce people\n";
    {
        auto fake_bundle = [](const std::string& marker) {  // the size of a real bundle (6597 bytes), recognisable inside
            Bytes b = CryptoEngine::random_bytes(6597);
            std::copy(marker.begin(), marker.end(), b.begin() + 100);
            return b;
        };
        Record creation_rec;
        {
            ConversationInfo info;
            info.title = "Trio";
            info.members = {alice.fingerprint, bob.fingerprint, mallory.fingerprint};
            creation_rec.conversation_id = CryptoEngine::random_bytes(ID_BYTES);
            creation_rec.message_id = CryptoEngine::random_bytes(ID_BYTES);
            creation_rec.sender = alice.fingerprint;
            creation_rec.recipients_hash = recipients_hash_for(info.members);
            creation_rec.sent_at = 1700000000;
            creation_rec.type = RecordType::Conversation;
            creation_rec.payload = conversation_payload(info);
        }
        Bytes creation_raw = sign_record(creation_rec, alice.sig.private_key);

        Inner inner;
        inner.records = {creation_raw};
        inner.introduced = {fake_bundle("INTRODUCED-ONE-MARKER")};
        Bytes env = seal_envelope(inner, bob.kem.public_key);
        auto opened = open_envelope(env, bob.kem.private_key);
        CHECK(opened && opened->introduced == inner.introduced && opened->records == inner.records && opened->sender_bundle.empty(),
              "an envelope carries introduced bundles beside the records, and opens to exactly that");
        CHECK(!contains(env, "INTRODUCED-ONE-MARKER"), "the introduced bundles are not visible in the envelope");
        CHECK(open_envelope(env, mallory.kem.private_key) == std::nullopt, "the wrong recipient cannot open it");
        int opened_after_tamper = 0;
        for (size_t i = 0; i < env.size(); i++) {
            Bytes bad = env;
            bad[i] ^= 0x01;
            if (open_envelope(bad, bob.kem.private_key)) opened_after_tamper++;
        }
        CHECK(opened_after_tamper == 0, "a one-bit change anywhere in it, including the introduced bundles, is refused (" + std::to_string(env.size()) + " positions)");

        Inner both;
        both.sender_bundle = fake_bundle("SENDER-MARKER");
        both.introduced = {fake_bundle("A-MARKER")};
        both.records = {creation_raw};
        auto both_back = open_envelope(seal_envelope(both, bob.kem.public_key), bob.kem.private_key);
        CHECK(both_back && both_back->sender_bundle == both.sender_bundle && both_back->introduced == both.introduced && both_back->records == both.records,
              "the sender's own bundle and introduced ones can travel together, each kept separate");

        // How many fit.
        auto seals_with = [&](size_t n) {
            Inner x;
            x.records = {creation_raw};
            for (size_t i = 0; i < n; i++) x.introduced.push_back(fake_bundle("B" + std::to_string(i)));
            try { return seal_envelope(x, bob.kem.public_key).size() <= relay::MAX_ENVELOPE_BYTES; } catch (const std::exception&) { return false; }
        };
        size_t fits = 0;
        while (fits < MAX_INTRODUCED_PER_ENVELOPE && seals_with(fits + 1)) fits++;
        CHECK(fits >= 8, "at least 8 real-sized bundles fit in one envelope next to a creation record (the largest that fits: " + std::to_string(fits) + ")");
        CHECK(!seals_with(15), "15 do not, so the sender must split a long list across envelopes");
        Inner too_many;
        for (size_t i = 0; i <= MAX_INTRODUCED_PER_ENVELOPE; i++) too_many.introduced.push_back(Bytes(10, 1));
        CHECK(throws([&] { seal_envelope(too_many, bob.kem.public_key); }), "more than 15 introduced bundles is refused outright");
        Inner huge_bundle;
        huge_bundle.introduced = {Bytes(MAX_BUNDLE_BYTES + 1, 1)};
        CHECK(throws([&] { seal_envelope(huge_bundle, bob.kem.public_key); }), "a single introduced bundle over the size limit is refused");
    }

    std::cout << "Forwarding through the creator\n";
    {
        Bytes target = CryptoEngine::random_bytes(HASH_BYTES), env = CryptoEngine::random_bytes(5000);
        Bytes payload = forward_payload(target, env);
        auto info = parse_forward_payload(payload);
        CHECK(info && info->target == target && info->envelope == env, "a forward names its target and carries the sealed envelope, round-tripping exactly");
        CHECK(throws([&] { forward_payload(Bytes(31, 1), env); }) && throws([&] { forward_payload(target, Bytes()); }) &&
                  throws([&] { forward_payload(target, Bytes(MAX_FORWARD_ENVELOPE_BYTES + 1, 1)); }) && !throws([&] { forward_payload(target, Bytes(MAX_FORWARD_ENVELOPE_BYTES, 1)); }),
              "a target of the wrong size, and an empty or oversized envelope, are refused");
        Bytes trailing = payload; trailing.push_back(0);
        bool prefixes = true;
        for (size_t n = 0; n < payload.size(); n++)
            if (parse_forward_payload(Bytes(payload.begin(), payload.begin() + static_cast<std::ptrdiff_t>(n)))) prefixes = false;
        CHECK(!parse_forward_payload(trailing) && prefixes && !parse_forward_payload(Bytes()), "trailing bytes, every truncation and an empty payload are rejected");
        Bytes lying; write_u32(lying, 0xFFFFFFFF);
        CHECK(!parse_forward_payload(lying) && !parse_forward_payload(hand_payload(1, "", 1, 0, Bytes(), {}, 0)), "a huge declared length doesn't allocate, and other payloads aren't mistaken for a forward");

        Bytes recipients = recipients_hash_for({alice.fingerprint, bob.fingerprint});
        auto as_record = [&](uint32_t version, const Bytes& own_prev, uint32_t seen_count) {
            return parse_record(hand_record(alice, version, 5, alice.fingerprint, recipients, payload, own_prev,
                                            [&](Bytes& b) { if (version == 1) write_blob(b, Bytes()); else { write_u32(b, seen_count); for (uint32_t i = 0; i < seen_count; i++) write_blob(b, CryptoEngine::random_bytes(HASH_BYTES)); } }));
        };
        CHECK(as_record(2, Bytes(), 0).has_value(), "(control) a forward record parses as version 2");
        CHECK(!as_record(1, Bytes(), 0), "...but not as version 1");
        CHECK(!as_record(2, CryptoEngine::random_bytes(HASH_BYTES), 0) && !as_record(2, Bytes(), 1), "it is outside the transcript: it can't claim a previous entry or anything seen");
    }

    std::cout << "Archive grants\n";
    {
        ArchiveGrantInfo info;
        info.relay_address = "10.0.0.248:9000";
        info.relay_id = CryptoEngine::random_bytes(HASH_BYTES);
        info.archive_key = CryptoEngine::random_bytes(32);
        info.join_token = CryptoEngine::random_bytes(32);
        Bytes payload = archive_grant_payload(info);
        auto back = parse_archive_grant_payload(payload);
        CHECK(back && back->relay_address == info.relay_address && back->relay_id == info.relay_id && back->archive_key == info.archive_key && back->join_token == info.join_token,
              "a grant carries the relay's address and identity, the archive key and the member's join token, exactly");
        CHECK(payload.size() <= MAX_ARCHIVE_GRANT_PAYLOAD, "and fits its limit (" + std::to_string(payload.size()) + " bytes)");
        auto changed = [&](const std::function<void(ArchiveGrantInfo&)>& f) { ArchiveGrantInfo c = info; f(c); return c; };
        CHECK(throws([&] { archive_grant_payload(changed([](ArchiveGrantInfo& c) { c.relay_address.clear(); })); }) &&
                  throws([&] { archive_grant_payload(changed([](ArchiveGrantInfo& c) { c.relay_address = std::string(MAX_RELAY_ADDRESS_BYTES + 1, 'a'); })); }) &&
                  throws([&] { archive_grant_payload(changed([](ArchiveGrantInfo& c) { c.relay_address = "host name:9000"; })); }) &&
                  throws([&] { archive_grant_payload(changed([](ArchiveGrantInfo& c) { c.relay_address = std::string("h\nost:1"); })); }) &&
                  throws([&] { archive_grant_payload(changed([](ArchiveGrantInfo& c) { c.relay_address = "h\xC3\xA9st:1"; })); }),
              "an address that is empty, too long, or has spaces, line breaks or non-ASCII characters is refused");
        CHECK(throws([&] { archive_grant_payload(changed([](ArchiveGrantInfo& c) { c.relay_id.pop_back(); })); }) && throws([&] { archive_grant_payload(changed([](ArchiveGrantInfo& c) { c.archive_key.pop_back(); })); }) &&
                  throws([&] { archive_grant_payload(changed([](ArchiveGrantInfo& c) { c.join_token.push_back(0); })); }),
              "a relay ID, key or token of the wrong size is refused");
        Bytes trailing = payload; trailing.push_back(0);
        bool prefixes = true;
        for (size_t n = 0; n < payload.size(); n++)
            if (parse_archive_grant_payload(Bytes(payload.begin(), payload.begin() + static_cast<std::ptrdiff_t>(n)))) prefixes = false;
        Bytes lying; write_u32(lying, 0xFFFFFFFF);
        CHECK(!parse_archive_grant_payload(trailing) && prefixes && !parse_archive_grant_payload(Bytes()) && !parse_archive_grant_payload(lying) && !parse_archive_grant_payload(Bytes(MAX_ARCHIVE_GRANT_PAYLOAD + 1, 1)),
              "trailing bytes, every truncation, an empty payload, a huge declared length and an oversized payload are rejected");
        Bytes bad_address;  // hand-written: a payload whose address has a space in it
        write_blob(bad_address, Bytes{'a', ' ', 'b'}); write_blob(bad_address, info.relay_id); write_blob(bad_address, info.archive_key); write_blob(bad_address, info.join_token);
        CHECK(!parse_archive_grant_payload(bad_address), "a hostile address is rejected on the receiving side too");

        Bytes recipients = recipients_hash_for({alice.fingerprint, bob.fingerprint});
        auto as_record = [&](uint32_t version, const Bytes& own_prev, uint32_t seen_count, const Bytes& body) {
            return parse_record(hand_record(alice, version, 6, alice.fingerprint, recipients, body, own_prev,
                                            [&](Bytes& b) { if (version == 1) write_blob(b, Bytes()); else { write_u32(b, seen_count); for (uint32_t i = 0; i < seen_count; i++) write_blob(b, CryptoEngine::random_bytes(HASH_BYTES)); } }));
        };
        CHECK(as_record(2, Bytes(), 0, payload).has_value(), "(control) a grant record parses as version 2");
        CHECK(!as_record(1, Bytes(), 0, payload), "...but not as version 1");
        CHECK(!as_record(2, CryptoEngine::random_bytes(HASH_BYTES), 0, payload) && !as_record(2, Bytes(), 1, payload), "it is outside the transcript: no previous entry, nothing seen");
        CHECK(!as_record(2, Bytes(), 0, Bytes(MAX_ARCHIVE_GRANT_PAYLOAD + 1, 1)), "and its payload has a limit");
    }

    std::cout << "Checkpoints\n";
    {
        Bytes hash = CryptoEngine::random_bytes(HASH_BYTES);
        Bytes payload = checkpoint_payload(137, hash);
        auto back = parse_checkpoint_payload(payload);
        CHECK(back && back->number == 137 && back->hash == hash, "a checkpoint names an entry number and the chain hash at that entry, exactly");
        CHECK(throws([&] { checkpoint_payload(0, hash); }) && throws([&] { checkpoint_payload(5, Bytes(31, 1)); }) && throws([&] { checkpoint_payload(5, Bytes(33, 1)); }),
              "entry number 0 (there is no entry 0) and a hash of the wrong size are refused");
        Bytes trailing = payload; trailing.push_back(0);
        bool prefixes = true;
        for (size_t n = 0; n < payload.size(); n++)
            if (parse_checkpoint_payload(Bytes(payload.begin(), payload.begin() + static_cast<std::ptrdiff_t>(n)))) prefixes = false;
        Bytes zero; write_u64(zero, 0); write_blob(zero, hash);
        Bytes short_hash; write_u64(short_hash, 9); write_blob(short_hash, Bytes(7, 1));
        CHECK(!parse_checkpoint_payload(trailing) && prefixes && !parse_checkpoint_payload(Bytes()) && !parse_checkpoint_payload(zero) && !parse_checkpoint_payload(short_hash),
              "trailing bytes, every truncation, an empty payload, entry 0 and a short hash are rejected");

        Bytes recipients = recipients_hash_for({alice.fingerprint, bob.fingerprint});
        auto as_record = [&](uint32_t version, const Bytes& own_prev, uint32_t seen_count, const Bytes& body) {
            return parse_record(hand_record(alice, version, 7, alice.fingerprint, recipients, body, own_prev,
                                            [&](Bytes& b) { if (version == 1) write_blob(b, Bytes()); else { write_u32(b, seen_count); for (uint32_t i = 0; i < seen_count; i++) write_blob(b, CryptoEngine::random_bytes(HASH_BYTES)); } }));
        };
        CHECK(as_record(2, Bytes(), 0, payload).has_value(), "(control) a checkpoint record parses as version 2");
        CHECK(!as_record(1, Bytes(), 0, payload), "...but not as version 1");
        CHECK(!as_record(2, CryptoEngine::random_bytes(HASH_BYTES), 0, payload) && !as_record(2, Bytes(), 1, payload), "it is outside the transcript: no previous entry, nothing seen");
        CHECK(!as_record(2, Bytes(), 0, Bytes(100, 1)), "and its payload has a small limit");
    }

    std::cout << "Deletion requests and acceptances\n";
    {
        DeleteRequestInfo whole{1, CryptoEngine::random_bytes(16), 1700000000, {}};
        DeleteRequestInfo some{2, CryptoEngine::random_bytes(16), 1700000000, {CryptoEngine::random_bytes(32), CryptoEngine::random_bytes(32)}};
        auto wp = delete_request_payload(whole), sp = delete_request_payload(some);
        auto wb = parse_delete_request_payload(wp), sb = parse_delete_request_payload(sp);
        CHECK(wb && wb->scope == 1 && wb->op_id == whole.op_id && wb->expires_at == 1700000000 && wb->entries.empty() && sb && sb->scope == 2 && sb->entries == some.entries, "a request names a whole chat, or particular entries by hash");
        auto changed = [&](DeleteRequestInfo base, const std::function<void(DeleteRequestInfo&)>& f) { f(base); return throws([&] { delete_request_payload(base); }); };
        CHECK(changed(whole, [](DeleteRequestInfo& x) { x.scope = 0; }) && changed(whole, [](DeleteRequestInfo& x) { x.scope = 3; }) && changed(whole, [](DeleteRequestInfo& x) { x.entries.push_back(Bytes(32, 1)); }) &&
                  changed(some, [](DeleteRequestInfo& x) { x.entries.clear(); }) && changed(some, [](DeleteRequestInfo& x) { x.entries.assign(65, Bytes(32, 1)); }) && changed(some, [](DeleteRequestInfo& x) { x.op_id.pop_back(); }) &&
                  changed(some, [](DeleteRequestInfo& x) { x.entries[0].pop_back(); }),
              "an invalid request is refused when making it: a bad scope, entries for a whole chat, none or too many for a partial one, IDs and hashes of the wrong size");
        Bytes trailing = sp; trailing.push_back(0);
        bool prefixes = true;
        for (size_t n = 0; n < sp.size(); n++)
            if (parse_delete_request_payload(Bytes(sp.begin(), sp.begin() + static_cast<std::ptrdiff_t>(n)))) prefixes = false;
        Bytes lying; write_u32(lying, 2); write_blob(lying, Bytes(16, 1)); write_u64(lying, 5); write_u32(lying, 0xFFFFFFFF);
        Bytes twice = sp;  // the same entry named twice
        Bytes dup; write_u32(dup, 2); write_blob(dup, Bytes(16, 1)); write_u64(dup, 5); write_u32(dup, 2); write_blob(dup, Bytes(32, 7)); write_blob(dup, Bytes(32, 7));
        CHECK(!parse_delete_request_payload(trailing) && prefixes && !parse_delete_request_payload(Bytes()) && !parse_delete_request_payload(lying) && !parse_delete_request_payload(dup) && !parse_delete_request_payload(Bytes(MAX_DELETE_REQUEST_PAYLOAD + 1, 1)),
              "trailing bytes, every truncation, a huge declared count, an entry named twice and an oversized payload are rejected");

        DeleteAcceptInfo acc{CryptoEngine::random_bytes(16), CryptoEngine::random_bytes(32), CryptoEngine::random_bytes(3309)};
        auto ap = delete_accept_payload(acc);
        auto ab = parse_delete_accept_payload(ap);
        CHECK(ab && ab->op_id == acc.op_id && ab->key_hash == acc.key_hash && ab->signature == acc.signature && ap.size() <= MAX_DELETE_ACCEPT_PAYLOAD, "an acceptance carries the operation, which key signed, and the signature");
        CHECK(throws([&] { delete_accept_payload({Bytes(15, 1), acc.key_hash, acc.signature}); }) && throws([&] { delete_accept_payload({acc.op_id, Bytes(31, 1), acc.signature}); }) && throws([&] { delete_accept_payload({acc.op_id, acc.key_hash, Bytes()}); }),
              "an acceptance with a bad ID, key hash or no signature is refused");
        Bytes atrail = ap; atrail.push_back(0);
        bool aprefixes = true;
        for (size_t n = 0; n < ap.size(); n += 13)
            if (parse_delete_accept_payload(Bytes(ap.begin(), ap.begin() + static_cast<std::ptrdiff_t>(n)))) aprefixes = false;
        CHECK(!parse_delete_accept_payload(atrail) && aprefixes && !parse_delete_accept_payload(Bytes()), "and the same hostile inputs are rejected");

        Bytes recipients = recipients_hash_for({alice.fingerprint, bob.fingerprint});
        auto as_record = [&](uint32_t type, uint32_t version, const Bytes& own_prev, uint32_t seen_count, const Bytes& body) {
            return parse_record(hand_record(alice, version, type, alice.fingerprint, recipients, body, own_prev,
                                            [&](Bytes& b) { if (version == 1) write_blob(b, Bytes()); else { write_u32(b, seen_count); for (uint32_t i = 0; i < seen_count; i++) write_blob(b, CryptoEngine::random_bytes(HASH_BYTES)); } }));
        };
        CHECK(as_record(8, 2, Bytes(), 0, sp).has_value() && as_record(9, 2, Bytes(), 0, ap).has_value(), "(control) both parse as version 2 records");
        CHECK(!as_record(8, 1, Bytes(), 0, sp) && !as_record(9, 1, Bytes(), 0, ap), "...but not as version 1");
        CHECK(!as_record(8, 2, CryptoEngine::random_bytes(HASH_BYTES), 0, sp) && !as_record(9, 2, Bytes(), 1, ap), "they are outside the transcript: no previous entry, nothing seen");
        CHECK(!as_record(8, 2, Bytes(), 0, Bytes(MAX_DELETE_REQUEST_PAYLOAD + 1, 1)) && !as_record(9, 2, Bytes(), 0, Bytes(MAX_DELETE_ACCEPT_PAYLOAD + 1, 1)) && !as_record(11, 2, Bytes(), 0, sp), "and their payloads have limits, and there is no type 11");
    }

    std::cout << "The keyring\n";
    {
        keyring::Contents c;
        for (int i = 0; i < 2; i++) {
            keyring::ArchiveItem a;
            a.conversation_id = CryptoEngine::random_bytes(16);
            a.relay_address = "10.0.0.248:9000";
            a.relay_id = CryptoEngine::random_bytes(32);
            a.role = i + 1;
            a.state = i == 0 ? 1 : 0;
            a.archive_key = CryptoEngine::random_bytes(32);
            a.chat_public_key = CryptoEngine::random_bytes(1952);
            a.chat_private_key = CryptoEngine::random_bytes(4032);
            if (i == 1) a.join_token = CryptoEngine::random_bytes(32);
            c.archives.push_back(a);
        }
        c.verified = {std::string(64, 'a'), std::string(64, 'b')};
        c.member_tokens = {{CryptoEngine::random_bytes(16), std::string(64, 'c'), CryptoEngine::random_bytes(32)}};
        c.introduced = {{std::string(64, 'd'), CryptoEngine::random_bytes(6597), 1700000000, std::string(64, 'e'), 1700000100}};
        c.issued_tokens = {{CryptoEngine::random_bytes(32), "for Bob", 1700000200, std::string(64, 'f'), true}, {CryptoEngine::random_bytes(32), "unnamed card", 1700000300, "", false}};
        c.receipts = {{CryptoEngine::random_bytes(16), false, true}, {CryptoEngine::random_bytes(16), true, false}};

        Bytes data = keyring::serialize(c);
        auto back = keyring::parse(data);
        CHECK(back && back->archives.size() == 2 && back->archives[0].conversation_id == c.archives[0].conversation_id && back->archives[0].chat_private_key == c.archives[0].chat_private_key &&
                  back->archives[1].join_token == c.archives[1].join_token && back->archives[0].join_token.empty() && back->archives[1].role == 2 && back->archives[1].state == 0,
              "archives round trip, with their keys and the join token only where there is one");
        CHECK(back && back->verified == c.verified && back->member_tokens.size() == 1 && back->member_tokens[0].token == c.member_tokens[0].token && back->introduced.size() == 1 &&
                  back->introduced[0].bundle == c.introduced[0].bundle && back->introduced[0].first_seen == 1700000100 && back->introduced[0].introduced_by == c.introduced[0].introduced_by,
              "so do verified people, member tokens and introduced members");
        CHECK(back && back->issued_tokens.size() == 2 && back->issued_tokens[0].revoked && back->issued_tokens[0].label == "for Bob" && !back->issued_tokens[1].revoked && back->issued_tokens[1].bound_fp.empty() &&
                  back->receipts.size() == 2 && !back->receipts[0].delivery && back->receipts[0].read && back->receipts[1].delivery && !back->receipts[1].read,
              "and issued tokens (with revocation and who they are bound to) and receipt settings");
        CHECK(keyring::serialize(*back) == data, "the same contents always give the same bytes, so a changed keyring can be told from an unchanged one");
        CHECK(data.size() < 20000, "(a two-chat keyring is " + std::to_string(data.size()) + " bytes, about 6 KB per chat)");
        keyring::Contents none;
        auto empty_back = keyring::parse(keyring::serialize(none));
        CHECK(none.empty() && empty_back && empty_back->empty() && !c.empty(), "an empty keyring is valid and knows it is empty");

        bool prefixes = true;
        for (size_t n = 0; n < data.size(); n += 17)
            if (keyring::parse(Bytes(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(n)))) prefixes = false;
        Bytes trailing = data; trailing.push_back(0);
        CHECK(prefixes && !keyring::parse(trailing) && !keyring::parse(Bytes()) && !keyring::parse(Bytes(500, 0xFF)), "truncations, trailing bytes, an empty input and garbage are rejected");

        auto altered = [&](const std::function<void(keyring::Contents&)>& f) { keyring::Contents x = c; f(x); return keyring::parse(keyring::serialize(x)); };
        CHECK(!altered([](keyring::Contents& x) { x.archives[0].role = 0; }) && !altered([](keyring::Contents& x) { x.archives[0].role = 3; }) && !altered([](keyring::Contents& x) { x.archives[0].state = 3; }),
              "an archive role or state out of range is rejected");
        CHECK(!altered([](keyring::Contents& x) { x.archives[0].archive_key.pop_back(); }) && !altered([](keyring::Contents& x) { x.archives[0].relay_id.push_back(0); }) &&
                  !altered([](keyring::Contents& x) { x.archives[0].conversation_id.pop_back(); }) && !altered([](keyring::Contents& x) { x.member_tokens[0].token.push_back(0); }) &&
                  !altered([](keyring::Contents& x) { x.issued_tokens[0].hash.pop_back(); }), "keys, IDs and tokens of the wrong size are rejected");
        CHECK(!altered([](keyring::Contents& x) { x.archives[0].relay_address.clear(); }) && !altered([](keyring::Contents& x) { x.archives[0].chat_private_key.clear(); }) && !altered([](keyring::Contents& x) { x.introduced[0].bundle.clear(); }),
              "an archive with no address or key, or an introduced member with no bundle, is rejected");
        CHECK(!altered([](keyring::Contents& x) { x.archives[0].relay_address = std::string(256, 'a'); }), "an over-long address is rejected");
        CHECK(throws([&] { keyring::Contents big; big.verified = {std::string(5000, 'x')}; keyring::serialize(big); }), "something too long to store is refused when making a keyring");

        Bytes newer = data;
        newer[4 + 19 + 3] = 2;  // the version field: after the length-prefixed label
        Bytes wrong_label = data;
        wrong_label[6] ^= 1;
        CHECK(!keyring::parse(newer) && !keyring::parse(wrong_label), "a keyring from a newer version, or one that isn't a keyring, is rejected");
        Bytes lying;
        write_string(lying, "pq-suite v3 keyring"); write_u32(lying, 1); write_u32(lying, 0xFFFFFFFF);
        CHECK(!keyring::parse(lying), "a declared count of four billion archives is rejected without allocating");

        const Bytes key = CryptoEngine::random_bytes(32), mailbox = CryptoEngine::random_bytes(16);
        Bytes sealed = keyring::seal(key, mailbox, data);
        auto opened = keyring::open(key, mailbox, sealed);
        CHECK(opened && *opened == data && sealed.size() == data.size() + 28, "a sealed keyring opens to what was sealed, with 28 bytes of overhead");
        CHECK(!contains(sealed, std::string(c.archives[0].archive_key.begin(), c.archives[0].archive_key.begin() + 16)) && !contains(sealed, "10.0.0.248"), "none of it is visible in the sealed form");
        CHECK(keyring::seal(key, mailbox, data) != sealed, "sealing twice gives different bytes");
        CHECK(!keyring::open(CryptoEngine::random_bytes(32), mailbox, sealed) && !keyring::open(key, CryptoEngine::random_bytes(16), sealed), "it opens only under its own key, for its own mailbox");
        int opened_after_flip = 0;
        for (size_t i = 0; i < sealed.size(); i += 7) {
            Bytes bad = sealed;
            bad[i] ^= 1;
            if (keyring::open(key, mailbox, bad)) opened_after_flip++;
        }
        CHECK(opened_after_flip == 0 && !keyring::open(key, mailbox, Bytes()) && !keyring::open(key, mailbox, Bytes(sealed.begin(), sealed.begin() + 20)), "a changed byte, a truncation or nothing at all is refused");
    }

    std::cout << "Archive entries and chain\n";
    {
        const Bytes key = CryptoEngine::random_bytes(archive::KEY_BYTES), id = CryptoEngine::random_bytes(16);
        const Bytes record = CryptoEngine::random_bytes(300);
        Bytes blob = archive::seal_entry(key, id, 7, record);
        auto opened = archive::open_entry(key, id, 7, blob);
        CHECK(opened && *opened == record && blob.size() == record.size() + archive::NONCE_BYTES + archive::TAG_BYTES, "an entry opens to the record it was made from, with 28 bytes of overhead");
        CHECK(!contains(blob, std::string(record.begin(), record.begin() + 16)), "the record is not visible in it");
        CHECK(archive::seal_entry(key, id, 7, record) != blob, "sealing the same record twice gives different entries");
        std::set<Bytes> nonces;
        for (int i = 0; i < 300; i++) {
            Bytes b = archive::seal_entry(key, id, 7, record);
            nonces.insert(Bytes(b.begin(), b.begin() + archive::NONCE_BYTES));
        }
        CHECK(nonces.size() == 300, "the nonce is random each time: two members racing for the same entry number never share one");
        CHECK(!archive::open_entry(CryptoEngine::random_bytes(32), id, 7, blob) && !archive::open_entry(key, CryptoEngine::random_bytes(16), 7, blob) &&
                  !archive::open_entry(key, id, 8, blob) && !archive::open_entry(key, id, 6, blob),
              "it opens only under its own key, in its own archive, at its own entry number");
        int opened_after_flip = 0;
        for (size_t i = 0; i < blob.size(); i++) {
            Bytes bad = blob;
            bad[i] ^= 0x01;
            if (archive::open_entry(key, id, 7, bad)) opened_after_flip++;
        }
        bool prefixes_fail = true;
        for (size_t n = 0; n < blob.size(); n++)
            if (archive::open_entry(key, id, 7, Bytes(blob.begin(), blob.begin() + static_cast<std::ptrdiff_t>(n)))) prefixes_fail = false;
        CHECK(opened_after_flip == 0 && prefixes_fail && !archive::open_entry(key, id, 7, Bytes()), "a one-bit change anywhere, any truncation, or nothing at all, is refused");
        CHECK(throws([&] { archive::seal_entry(Bytes(31, 1), id, 1, record); }) && throws([&] { archive::seal_entry(key, id, 1, Bytes()); }) &&
                  throws([&] { archive::seal_entry(key, id, 1, Bytes(archive::MAX_RECORD_BYTES + 1, 1)); }),
              "a key of the wrong size, an empty record or an oversized one is refused");
        Bytes biggest = archive::seal_entry(key, id, 1, Bytes(archive::MAX_RECORD_BYTES, 1));
        CHECK(biggest.size() == relay::MAX_ARCHIVE_ENTRY_BYTES && archive::open_entry(key, id, 1, biggest), "the largest record makes exactly the relay's largest entry");
        CHECK(MAX_RECORD_BYTES + 3500 < archive::MAX_RECORD_BYTES, "(any signed record we make fits: they are at most 40 KiB)");

        // The chain.
        std::vector<relay::ArchiveEntry> entries;
        archive::Head head{0, archive::genesis_hash(id)};
        const archive::Head start = head;
        for (uint64_t n = 1; n <= 5; n++) {
            relay::ArchiveEntry e;
            e.number = n;
            e.ciphertext = archive::seal_entry(key, id, n, CryptoEngine::random_bytes(50));
            e.hash = archive::entry_hash(id, n, head.hash, e.ciphertext);
            head = {n, e.hash};
            entries.push_back(e);
        }
        auto ok = archive::verify_chain(id, start, entries);
        CHECK(ok && ok->number == 5 && ok->hash == head.hash, "an unbroken chain verifies and gives its head");
        CHECK(archive::genesis_hash(id) != archive::genesis_hash(CryptoEngine::random_bytes(16)), "each archive starts from its own genesis");
        auto none = archive::verify_chain(id, start, {});
        CHECK(none && none->number == 0 && none->hash == start.hash, "an empty list leaves the head where it was");
        std::vector<relay::ArchiveEntry> tail(entries.begin() + 2, entries.end());
        auto from_middle = archive::verify_chain(id, {2, entries[1].hash}, tail);
        CHECK(from_middle && from_middle->number == 5 && from_middle->hash == head.hash, "it can continue from a head already checked");
        CHECK(!archive::verify_chain(id, start, tail) && !archive::verify_chain(id, {2, entries[0].hash}, tail), "starting from the wrong head fails");
        auto gap = entries; gap.erase(gap.begin() + 2);
        auto swapped = entries; std::swap(swapped[1], swapped[2]);
        auto repeated = entries; repeated.insert(repeated.begin() + 3, repeated[2]);
        auto altered = entries; altered[3].ciphertext[10] ^= 1;
        auto rehashed = entries; rehashed[1].hash = CryptoEngine::sha256(Bytes{1});
        auto renumbered = entries; renumbered[2].number = 9;
        auto truncated_chain = entries; truncated_chain.pop_back();
        CHECK(!archive::verify_chain(id, start, gap) && !archive::verify_chain(id, start, swapped) && !archive::verify_chain(id, start, repeated) && !archive::verify_chain(id, start, altered) &&
                  !archive::verify_chain(id, start, rehashed) && !archive::verify_chain(id, start, renumbered),
              "a missing, reordered, repeated, altered, re-hashed or renumbered entry breaks the chain");
        auto shorter = archive::verify_chain(id, start, truncated_chain);
        CHECK(shorter && shorter->number == 4, "a chain with its last entry withheld still verifies, but ends earlier (the caller compares it with the relay's reported end)");
        CHECK(!archive::verify_chain(CryptoEngine::random_bytes(16), start, entries), "the same entries under another archive's ID do not verify");
    }

    std::cout << "Attachment chunks\n";
    {
        namespace fs = std::filesystem;
        auto begin_ok = [&](uint64_t plain) {
            auto plan = attachment::plan_for(plain);
            relay::FileBegin b;
            b.file_id = CryptoEngine::random_bytes(16); b.total_size = plan.ciphertext_size; b.chunk_size = plan.chunk_size; b.chunk_count = plan.chunk_count; b.expires_at = 1;
            b.token_hashes = {CryptoEngine::random_bytes(32)};
            return relay::decode_file_begin(relay::encode(b)).has_value();
        };
        bool relay_accepts = true;
        for (uint64_t size : std::initializer_list<uint64_t>{0, 1, 100, 49151, 49152, 49153, 98304, 100000, 10ull * 1024 * 1024, 1024ull * 1024 * 1024, attachment::MAX_PLAINTEXT_BYTES}) relay_accepts &= begin_ok(size);
        CHECK(relay_accepts, "for every size, from empty to the largest, the chunking this makes is one the relay's protocol accepts");
        auto p0 = attachment::plan_for(0), p1 = attachment::plan_for(1), pe = attachment::plan_for(2 * 49152), pe1 = attachment::plan_for(2 * 49152 + 1);
        CHECK(p0.chunk_count == 1 && p0.ciphertext_size == 16 && p1.chunk_count == 1 && p1.ciphertext_size == 17 && pe.chunk_count == 2 && pe.ciphertext_size == 2 * 49152 + 32 && pe1.chunk_count == 3 && pe1.chunk_size == 49168,
              "an empty file is one chunk holding only its tag; whole multiples and one over fill chunks as expected");
        CHECK(throws([&] { attachment::plan_for(attachment::MAX_PLAINTEXT_BYTES + 1); }) && attachment::MAX_PLAINTEXT_BYTES == MAX_ATTACHMENT_FILE_BYTES, "a file over the limit is refused, and the file layer and the record agree on the limit");

        const Bytes key = CryptoEngine::random_bytes(32), fid = CryptoEngine::random_bytes(16);
        const Bytes plain = CryptoEngine::random_bytes(300);
        Bytes sealed = attachment::seal_chunk(key, fid, 3, 10, plain);
        auto opened = attachment::open_chunk(key, fid, 3, 10, sealed);
        CHECK(opened && *opened == plain && sealed.size() == plain.size() + 16, "a chunk opens to what was sealed, with a 16-byte tag and no nonce stored (it comes from the chunk number)");
        CHECK(!contains(sealed, std::string(plain.begin(), plain.begin() + 16)), "the content is not visible in it");
        CHECK(!attachment::open_chunk(CryptoEngine::random_bytes(32), fid, 3, 10, sealed) && !attachment::open_chunk(key, CryptoEngine::random_bytes(16), 3, 10, sealed) &&
                  !attachment::open_chunk(key, fid, 4, 10, sealed) && !attachment::open_chunk(key, fid, 3, 11, sealed) && !attachment::open_chunk(key, fid, 2, 10, sealed),
              "it opens only under its own key, for its own file, at its own place, among its own count of chunks: it can't be moved or repeated");
        CHECK(attachment::seal_chunk(key, fid, 0, 10, plain) != attachment::seal_chunk(key, fid, 1, 10, plain) && attachment::seal_chunk(key, fid, 0, 10, plain) == attachment::seal_chunk(key, fid, 0, 10, plain),
              "the same content in two places seals differently (the place is the nonce), while one place always seals the same: fine, because the key is this file's alone");
        std::set<Bytes> distinct;
        for (uint32_t i = 0; i < 2000; i++) distinct.insert(attachment::seal_chunk(key, fid, i, 2000, Bytes(32, 0)));
        CHECK(distinct.size() == 2000, "2,000 chunks of identical content under one key all seal differently: no nonce repeats");
        int accepted = 0;
        for (size_t i = 0; i < sealed.size(); i++) {
            Bytes bad = sealed;
            bad[i] ^= 1;
            if (attachment::open_chunk(key, fid, 3, 10, bad)) accepted++;
        }
        bool prefixes_fail = true;
        for (size_t n = 0; n < sealed.size(); n += 11)
            if (attachment::open_chunk(key, fid, 3, 10, Bytes(sealed.begin(), sealed.begin() + static_cast<std::ptrdiff_t>(n)))) prefixes_fail = false;
        CHECK(accepted == 0 && prefixes_fail && !attachment::open_chunk(key, fid, 3, 10, Bytes()), "a one-bit change anywhere, any truncation, or nothing at all, is refused");
        Bytes empty_sealed = attachment::seal_chunk(key, fid, 0, 1, Bytes());
        auto empty_opened = attachment::open_chunk(key, fid, 0, 1, empty_sealed);
        CHECK(empty_sealed.size() == 16 && empty_opened && empty_opened->empty(), "an empty chunk is just a tag, and opens");
        CHECK(throws([&] { attachment::seal_chunk(Bytes(31, 1), fid, 0, 1, plain); }) && throws([&] { attachment::seal_chunk(key, Bytes(15, 1), 0, 1, plain); }) && throws([&] { attachment::seal_chunk(key, fid, 1, 1, plain); }) &&
                  throws([&] { attachment::seal_chunk(key, fid, 0, 0, plain); }) && throws([&] { attachment::seal_chunk(key, fid, 0, 1, Bytes(attachment::CHUNK_PLAINTEXT_BYTES + 1, 1)); }) &&
                  attachment::open_chunk(key, fid, 0, 1, attachment::seal_chunk(key, fid, 0, 1, Bytes(attachment::CHUNK_PLAINTEXT_BYTES, 1))),
              "a bad key, ID, place or count, or too large a chunk, is refused; the largest chunk is accepted");

        // Hashing a piece at a time gives the same answer as hashing at once.
        bool hashes_match = true;
        for (size_t size : {0u, 1u, 55u, 64u, 1000u, 100000u}) {
            Bytes data = CryptoEngine::random_bytes(size);
            attachment::Sha256 h;
            for (size_t at = 0; at < size; at += 777) h.update(data.data() + at, std::min<size_t>(777, size - at));
            hashes_match &= h.finish() == CryptoEngine::sha256(data);
        }
        CHECK(hashes_match, "hashing in pieces gives the same SHA-256 as all at once, for empty to large");
    }

    std::cout << "Attachment files\n";
    {
        namespace fs = std::filesystem;
        const fs::path dir = fs::temp_directory_path() / ("pq-attach-test-" + std::to_string(::getpid()));
        fs::remove_all(dir);
        fs::create_directories(dir / "in");
        fs::create_directories(dir / "out");
        auto write_file = [&](const fs::path& p, const Bytes& data) { std::ofstream f(p, std::ios::binary); f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size())); };
        auto read_file = [&](const fs::path& p) { std::ifstream f(p, std::ios::binary); return Bytes((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>()); };
        const Bytes key = CryptoEngine::random_bytes(32), fid = CryptoEngine::random_bytes(16);
        // Sends a file through the encryptor and into a decryptor; returns what happened.
        struct Result { bool ok = false; std::string error; fs::path saved; };
        auto round_trip = [&](const Bytes& content, const std::string& name, const fs::path& out_dir) {
            Result r;
            const fs::path src = dir / "in" / "source.bin";
            write_file(src, content);
            auto fp = attachment::fingerprint_file(src, r.error);
            if (!fp) return r;
            attachment::Encryptor enc(src, key, fid, fp->size);
            attachment::Decryptor dec(out_dir, name, key, fid, fp->size, fp->sha256);
            if (!dec.begin(false, r.error)) return r;
            for (uint32_t i = 0; i < enc.plan().chunk_count; i++) {
                Bytes sealed;
                if (!enc.chunk(i, sealed, r.error) || !dec.accept(i, sealed, r.error)) return r;
            }
            r.ok = dec.finish(r.saved, r.error);
            return r;
        };

        const Bytes three = CryptoEngine::random_bytes(2 * 49152 + 31696);
        write_file(dir / "in" / "source.bin", three);
        std::string err;
        auto fp = attachment::fingerprint_file(dir / "in" / "source.bin", err);
        CHECK(fp && fp->size == three.size() && fp->sha256 == CryptoEngine::sha256(three), "a file's size and SHA-256 are worked out by reading it once");
        CHECK(!attachment::fingerprint_file(dir / "in" / "missing.bin", err) && !err.empty(), "a file that isn't there is refused with a reason");

        auto r = round_trip(three, "holiday photo.jpg", dir / "out");
        CHECK(r.ok && r.saved == dir / "out" / "holiday photo.jpg" && read_file(r.saved) == three, "a file of three chunks goes through the encryptor and the decryptor and comes out identical (" + r.error + ")");
        CHECK(!fs::exists(dir / "out" / (".pqft-" + bytes_to_hex(fid).substr(0, 16) + ".part")), "with no temporary file left behind");
        for (size_t size : {size_t(0), size_t(1), size_t(49152), size_t(49153), size_t(2 * 49152), size_t(5 * 1024 * 1024)}) {
            Bytes content = CryptoEngine::random_bytes(size);
            auto x = round_trip(content, "size-" + std::to_string(size) + ".bin", dir / "out");
            CHECK(x.ok && read_file(x.saved) == content, "files of " + std::to_string(size) + " bytes (empty, one byte, exact chunk multiples, 5 MiB) come out identical (" + x.error + ")");
        }
        auto again = round_trip(three, "holiday photo.jpg", dir / "out");
        CHECK(again.ok && again.saved == dir / "out" / "holiday photo (2).jpg" && read_file(dir / "out" / "holiday photo.jpg") == three, "a file with a name already taken is saved under another: nothing existing is overwritten");
        auto sneaky = round_trip(three, "../../etc/passwd", dir / "out");
        CHECK(sneaky.ok && sneaky.saved.parent_path() == dir / "out" && sneaky.saved.filename() == "_.._etc_passwd", "a name that tries to climb out of the folder is made harmless and the file stays inside it");

        // Every way the end can fail leaves nothing saved.
        const fs::path out2 = dir / "out2";
        fs::create_directories(out2);
        auto count_files = [&](const fs::path& d) { size_t n = 0; for (auto& e : fs::directory_iterator(d)) { (void)e; n++; } return n; };
        {
            attachment::Encryptor enc(dir / "in" / "source.bin", key, fid, three.size());
            attachment::Decryptor dec(out2, "x.bin", key, fid, three.size(), CryptoEngine::sha256(Bytes{1}));  // the wrong fingerprint
            std::string e;
            dec.begin(false, e);
            for (uint32_t i = 0; i < 3; i++) { Bytes c; enc.chunk(i, c, e); dec.accept(i, c, e); }
            fs::path saved;
            CHECK(!dec.finish(saved, e) && has(e, "does not match the fingerprint") && count_files(out2) == 0, "a file that doesn't match the fingerprint in the signed message is not saved, and its partial file is removed");
        }
        {
            attachment::Encryptor enc(dir / "in" / "source.bin", key, fid, three.size());
            attachment::Decryptor dec(out2, "x.bin", key, fid, three.size(), fp->sha256);
            std::string e;
            dec.begin(false, e);
            Bytes c0, c1, c2;
            enc.chunk(0, c0, e); enc.chunk(1, c1, e); enc.chunk(2, c2, e);
            CHECK(!dec.accept(1, c1, e) && has(e, "out of order"), "a chunk that skips ahead is refused");
            CHECK(dec.accept(0, c0, e) && !dec.accept(0, c0, e), "(and one repeated)");
            Bytes bad = c1;
            bad[100] ^= 1;
            CHECK(!dec.accept(1, bad, e) && has(e, "damaged"), "a chunk that has been altered is refused");
            CHECK(!dec.accept(1, c2, e), "a chunk from another place is refused");
            Bytes wrong_file;
            { attachment::Encryptor other(dir / "in" / "source.bin", key, CryptoEngine::random_bytes(16), three.size()); other.chunk(1, wrong_file, e); }
            CHECK(!dec.accept(1, wrong_file, e), "and one from another file");
            CHECK(dec.accept(1, c1, e), "(the right one still works)");
            fs::path saved;
            CHECK(!dec.finish(saved, e) && has(e, "not complete") && count_files(out2) == 1, "finishing before the last chunk is refused (only the partial file exists)");
            dec.abort();
            CHECK(count_files(out2) == 0, "and aborting throws away what was written");
        }
        {
            attachment::Decryptor dec(out2, "x.bin", key, fid, three.size() + 1, fp->sha256);  // told the file is a byte longer than it is
            attachment::Encryptor enc(dir / "in" / "source.bin", key, fid, three.size());
            std::string e;
            dec.begin(false, e);
            bool refused = false;
            for (uint32_t i = 0; i < 3 && !refused; i++) { Bytes c; enc.chunk(i, c, e); refused = !dec.accept(i, c, e); }
            CHECK(refused, "a chunk of the wrong size for the declared file size is refused");
            dec.abort();
        }
        {
            attachment::Encryptor enc(dir / "in" / "source.bin", key, fid, three.size() + 5000);  // the file is shorter than expected
            std::string e;
            Bytes c;
            CHECK(enc.chunk(0, c, e) && enc.chunk(1, c, e) && !enc.chunk(2, c, e) && has(e, "changed"), "a file that is shorter when sent than when measured is noticed: " + e);
            CHECK(!enc.chunk(3, c, e) && has(e, "past the end"), "and a chunk past the end is refused");
        }
        {
            attachment::Decryptor dec(dir / "no-such-folder", "x.bin", key, fid, 10, CryptoEngine::sha256(Bytes{1}));
            std::string e;
            CHECK(!dec.begin(false, e) && has(e, "doesn't exist"), "saving into a folder that doesn't exist is refused: " + e);
        }

        // Carrying on after an interruption.
        const fs::path out3 = dir / "out3";
        fs::create_directories(out3);
        {
            attachment::Encryptor enc(dir / "in" / "source.bin", key, fid, three.size());
            std::string e;
            {
                attachment::Decryptor first(out3, "big.bin", key, fid, three.size(), fp->sha256);
                first.begin(false, e);
                for (uint32_t i = 0; i < 2; i++) { Bytes c; enc.chunk(i, c, e); first.accept(i, c, e); }
            }  // interrupted after two chunks
            const fs::path part = out3 / (".pqft-" + bytes_to_hex(fid).substr(0, 16) + ".part");
            CHECK(fs::exists(part) && fs::file_size(part) == 2 * 49152, "(an interrupted download leaves what it had)");
            { std::ofstream junk(part, std::ios::binary | std::ios::app); junk << "half a chunk that never finished"; }
            attachment::Decryptor second(out3, "big.bin", key, fid, three.size(), fp->sha256);
            CHECK(second.begin(true, e) && second.next_chunk() == 2 && fs::file_size(part) == 2 * 49152, "resuming keeps the whole chunks, drops a partial one, and asks for chunk 2 next");
            Bytes c;
            enc.chunk(2, c, e);
            fs::path saved;
            CHECK(second.accept(2, c, e) && second.finish(saved, e) && read_file(saved) == three, "and the rest completes the file, identical to the original, checked as a whole");
        }
        {
            attachment::Encryptor enc(dir / "in" / "source.bin", key, fid, three.size());
            std::string e;
            const fs::path part = out3 / (".pqft-" + bytes_to_hex(fid).substr(0, 16) + ".part");
            {
                attachment::Decryptor first(out3, "damaged.bin", key, fid, three.size(), fp->sha256);
                first.begin(false, e);
                Bytes c;
                enc.chunk(0, c, e); first.accept(0, c, e);
            }
            { std::fstream f(part, std::ios::binary | std::ios::in | std::ios::out); f.seekp(10); f.put('\x55'); }  // the half-finished file is tampered with on disk
            attachment::Decryptor second(out3, "damaged.bin", key, fid, three.size(), fp->sha256);
            second.begin(true, e);
            Bytes c1, c2;
            enc.chunk(1, c1, e); enc.chunk(2, c2, e);
            second.accept(1, c1, e); second.accept(2, c2, e);
            fs::path saved;
            CHECK(!second.finish(saved, e) && has(e, "does not match") && saved.empty(), "a leftover partial file that was altered is caught: the final check covers it too, and nothing is saved");
        }
        {
            attachment::Decryptor fresh(out3, "restart.bin", key, fid, three.size(), fp->sha256);
            std::string e;
            CHECK(fresh.begin(true, e) && fresh.next_chunk() == 0, "resuming when there is nothing to resume from simply starts at the beginning");
            fresh.abort();
        }
        fs::remove_all(dir);
    }

    std::cout << "Safe file names\n";
    {
        namespace fs = std::filesystem;
        auto san = attachment::sanitize_filename;
        CHECK(san("report.pdf") == "report.pdf" && san("résumé 日本.pdf") == "résumé 日本.pdf" && san("a b (1).txt") == "a b (1).txt", "ordinary names, including spaces, accents and other scripts, are left as they are");
        CHECK(san("../../etc/passwd") == "_.._etc_passwd" && san("a/b\\c") == "a_b_c" && san("C:\\Windows\\x") == "C__Windows_x", "path separators and drive colons are replaced");
        CHECK(san("a*b?c\"d<e>f|g") == "a_b_c_d_e_f_g", "characters Windows forbids are replaced");
        CHECK(san(std::string("a\nb\tc\x01" "d\x7f" "e")) == "a_b_c_d_e", "control characters are replaced");
        CHECK(san("invoice\xE2\x80\xAE" "fdp.exe") == "invoice_fdp.exe" && san("a\xE2\x80\x8F" "b") == "a_b" && san("x\xE2\x81\xA7y") == "x_y", "text-direction overrides, isolates and marks, which can make a name read backwards, are replaced");
        CHECK(san(".hidden") == "hidden" && san("  spaced  ") == "spaced" && san("name.") == "name" && san("...") == "attachment" && san("") == "attachment" && san("   ") == "attachment", "no leading or trailing dots or spaces, and never empty");
        CHECK(san("\xFF\xFE") == "attachment" && san("bad\xC0\xAF") == "attachment" && san("\xED\xA0\x80") == "attachment" && san("\xF4\x90\x80\x80") == "attachment", "text that isn't valid UTF-8 (including overlong, surrogate and out-of-range forms) is not used");
        CHECK(san("CON") == "_CON" && san("con.txt") == "_con.txt" && san("NUL.tar.gz") == "_NUL.tar.gz" && san("com1") == "_com1" && san("LPT9.log") == "_LPT9.log" && san("COM0") == "COM0" && san("console.txt") == "console.txt",
              "Windows device names, with or without an extension, are defused; near misses are left alone");
        std::string accents;
        for (int i = 0; i < 120; i++) accents += "\xC3\xA9";  // 240 bytes of é
        std::string longname = san(accents + ".txt");
        bool utf8_ok = longname.size() <= 200 && longname.substr(longname.size() - 4) == ".txt" && (longname.size() - 4) % 2 == 0;
        CHECK(utf8_ok && san(std::string(300, 'a') + ".png").size() == 200 && san(std::string(300, 'a') + ".png").substr(196) == ".png", "a long name is cut to 200 bytes on a character boundary, keeping its extension");

        namespace fs = std::filesystem;
        const fs::path dir = fs::temp_directory_path() / ("pq-name-test-" + std::to_string(::getpid()));
        fs::remove_all(dir);
        fs::create_directories(dir);
        CHECK(attachment::unique_path(dir, "a.txt") == dir / "a.txt", "a free name is used as it is");
        { std::ofstream(dir / "a.txt") << "x"; }
        CHECK(attachment::unique_path(dir, "a.txt") == dir / "a (2).txt", "a taken name gets (2)");
        { std::ofstream(dir / "a (2).txt") << "x"; }
        CHECK(attachment::unique_path(dir, "a.txt") == dir / "a (3).txt", "then (3)");
        { std::ofstream(dir / "noext") << "x"; }
        CHECK(attachment::unique_path(dir, "noext") == dir / "noext (2)", "a name with no extension gets its number at the end");
        std::error_code ec;
        fs::create_symlink(dir / "does-not-exist", dir / "dangling.txt", ec);
        if (!ec) CHECK(attachment::unique_path(dir, "dangling.txt") == dir / "dangling (2).txt", "a name taken by a link that points nowhere counts as taken: a file is never written through a link");
        fs::remove_all(dir);
    }

    std::cout << "The attachment record\n";
    {
        AttachmentInfo a;
        a.file_id = CryptoEngine::random_bytes(16);
        a.name = "holiday photo.jpg";
        a.size = 123456789;
        a.sha256 = CryptoEngine::random_bytes(32);
        a.expires_at = 1700000000;
        a.relay_address = "10.0.0.248:9000";
        a.relay_id = CryptoEngine::random_bytes(32);
        a.caption = "from the beach";
        Bytes payload = attachment_payload(a);
        auto back = parse_attachment_payload(payload);
        CHECK(back && back->file_id == a.file_id && back->name == a.name && back->size == a.size && back->sha256 == a.sha256 && back->expires_at == a.expires_at && back->relay_address == a.relay_address && back->relay_id == a.relay_id && back->caption == a.caption &&
                  payload.size() <= MAX_ATTACHMENT_PAYLOAD,
              "an attachment's details round trip: file, name, size, fingerprint, expiry, relay and caption");
        CHECK(!contains(payload, std::string(32, '\x01')) && payload.size() < 400, "(it is small, and carries no key or token: those are not part of it)");
        a.caption.clear();
        CHECK(parse_attachment_payload(attachment_payload(a)) && parse_attachment_payload(attachment_payload(a))->caption.empty(), "the caption is optional");
        a.caption = "from the beach";
        auto bad = [&](const std::function<void(AttachmentInfo&)>& f) { AttachmentInfo x = a; f(x); return throws([&] { attachment_payload(x); }); };
        CHECK(bad([](AttachmentInfo& x) { x.name.clear(); }) && bad([](AttachmentInfo& x) { x.name = std::string(256, 'a'); }) && bad([](AttachmentInfo& x) { x.name = "a\nb"; }) && bad([](AttachmentInfo& x) { x.name = "evil\xE2\x80\xAEgpj.exe"; }) && bad([](AttachmentInfo& x) { x.name = "\xFF"; }),
              "a name that is empty, too long, has control or direction characters, or isn't UTF-8 is refused");
        CHECK(bad([](AttachmentInfo& x) { x.caption = std::string(1025, 'a'); }) && bad([](AttachmentInfo& x) { x.caption = "x\x01y"; }) && bad([](AttachmentInfo& x) { x.size = MAX_ATTACHMENT_FILE_BYTES + 1; }), "a bad caption, or a file over the limit, is refused");
        CHECK(bad([](AttachmentInfo& x) { x.file_id.pop_back(); }) && bad([](AttachmentInfo& x) { x.sha256.pop_back(); }) && bad([](AttachmentInfo& x) { x.relay_id.push_back(0); }) && bad([](AttachmentInfo& x) { x.relay_address.clear(); }) &&
                  bad([](AttachmentInfo& x) { x.relay_address = "a b:1"; }) && bad([](AttachmentInfo& x) { x.relay_address = std::string(256, 'a'); }), "IDs, hashes and addresses of the wrong size or form are refused");
        Bytes trailing = payload; trailing.push_back(0);
        bool prefixes = true;
        for (size_t n = 0; n < payload.size(); n++)
            if (parse_attachment_payload(Bytes(payload.begin(), payload.begin() + static_cast<std::ptrdiff_t>(n)))) prefixes = false;
        Bytes lying; write_blob(lying, Bytes(16, 1)); write_u32(lying, 0xFFFFFFFF);
        CHECK(!parse_attachment_payload(trailing) && prefixes && !parse_attachment_payload(Bytes()) && !parse_attachment_payload(lying) && !parse_attachment_payload(Bytes(MAX_ATTACHMENT_PAYLOAD + 1, 1)),
              "trailing bytes, every truncation, a huge declared length and an oversized payload are rejected");
        Bytes hostile_name; write_blob(hostile_name, a.file_id); write_blob(hostile_name, Bytes{'a', '\n'}); write_u64(hostile_name, 5); write_blob(hostile_name, a.sha256); write_u64(hostile_name, 5);
        write_blob(hostile_name, Bytes{'h', ':', '1'}); write_blob(hostile_name, a.relay_id); write_blob(hostile_name, Bytes());
        CHECK(!parse_attachment_payload(hostile_name), "a hostile name is rejected on the receiving side too");

        Bytes recipients = recipients_hash_for({alice.fingerprint, bob.fingerprint});
        auto as_record = [&](uint32_t version, const Bytes& own_prev, uint32_t seen_count, const Bytes& body) {
            return parse_record(hand_record(alice, version, 10, alice.fingerprint, recipients, body, own_prev,
                                            [&](Bytes& b) { if (version == 1) write_blob(b, Bytes()); else { write_u32(b, seen_count); for (uint32_t i = 0; i < seen_count; i++) write_blob(b, CryptoEngine::random_bytes(HASH_BYTES)); } }));
        };
        CHECK(as_record(2, Bytes(), 0, payload).has_value(), "(control) an attachment record parses as version 2");
        CHECK(!as_record(1, Bytes(), 0, payload), "...but not as version 1");
        CHECK(as_record(2, CryptoEngine::random_bytes(HASH_BYTES), 1, payload).has_value(), "it is part of the transcript, like text: it can follow an earlier message and have seen others'");
        CHECK(!as_record(2, Bytes(), 0, Bytes(MAX_ATTACHMENT_PAYLOAD + 1, 1)), "its payload has a limit");
    }

    std::cout << "Attachment grants in the envelope\n";
    {
        Inner in;
        in.sender_bundle = Bytes();
        in.records = {CryptoEngine::random_bytes(200)};
        const Bytes plain_form = encode_inner(in);
        size_t off = 0;
        CHECK(read_u32(plain_form.data(), plain_form.size(), off) == 2u, "an envelope with no attachment grants is written exactly as before (version 2)");
        in.grants = {{CryptoEngine::random_bytes(16), CryptoEngine::random_bytes(32), CryptoEngine::random_bytes(32)}, {CryptoEngine::random_bytes(16), CryptoEngine::random_bytes(32), CryptoEngine::random_bytes(32)}};
        in.introduced = {CryptoEngine::random_bytes(500)};
        Bytes encoded = encode_inner(in);
        off = 0;
        auto back = decode_inner(encoded);
        CHECK(read_u32(encoded.data(), encoded.size(), off) == 3u && back && back->grants.size() == 2 && back->grants[0].file_id == in.grants[0].file_id && back->grants[0].key == in.grants[0].key && back->grants[1].token == in.grants[1].token &&
                  back->records == in.records && back->introduced == in.introduced,
              "with grants it is version 3, and each recipient's file ID, key and token come back exactly, alongside the records and introduced bundles");
        auto old_one = decode_inner(plain_form);
        CHECK(old_one && old_one->grants.empty() && old_one->records == in.records, "an envelope without grants reads as having none");
        Bytes sealed = seal_envelope(in, bob.kem.public_key);
        auto opened = open_envelope(sealed, bob.kem.private_key);
        CHECK(opened && opened->grants.size() == 2 && opened->grants[0].key == in.grants[0].key && !open_envelope(sealed, mallory.kem.private_key), "sealed to Bob, the grants are Bob's to read and nobody else's");
        CHECK(!contains(sealed, std::string(in.grants[0].key.begin(), in.grants[0].key.begin() + 16)), "(and the key is not visible in the envelope)");

        auto invalid = [&](const std::function<void(Inner&)>& f) { Inner x = in; f(x); return throws([&] { encode_inner(x); }); };
        CHECK(invalid([](Inner& x) { x.grants.assign(MAX_GRANTS_PER_ENVELOPE + 1, x.grants[0]); }) && invalid([](Inner& x) { x.grants[1].file_id = x.grants[0].file_id; }) && invalid([](Inner& x) { x.grants[0].key.pop_back(); }) &&
                  invalid([](Inner& x) { x.grants[0].token.push_back(0); }) && invalid([](Inner& x) { x.grants[0].file_id.pop_back(); }),
              "too many grants, two for the same file, or a key, token or ID of the wrong size is refused when building");
        Bytes zero;
        write_u32(zero, 3); write_blob(zero, Bytes()); write_u32(zero, 0); write_u32(zero, 0); write_u32(zero, 0);
        Bytes dup = encoded;
        // Make the second grant name the first grant's file by hand.
        Bytes hostile;
        write_u32(hostile, 3); write_blob(hostile, Bytes()); write_u32(hostile, 0); write_u32(hostile, 2);
        for (int i = 0; i < 2; i++) { write_blob(hostile, Bytes(16, 7)); write_blob(hostile, Bytes(32, 1)); write_blob(hostile, Bytes(32, 2)); }
        write_u32(hostile, 0);
        Bytes lying;
        write_u32(lying, 3); write_blob(lying, Bytes()); write_u32(lying, 0); write_u32(lying, 0xFFFFFFFF);
        Bytes shortkey;
        write_u32(shortkey, 3); write_blob(shortkey, Bytes()); write_u32(shortkey, 0); write_u32(shortkey, 1); write_blob(shortkey, Bytes(16, 7)); write_blob(shortkey, Bytes(31, 1)); write_blob(shortkey, Bytes(32, 2)); write_u32(shortkey, 0);
        CHECK(!decode_inner(zero) && !decode_inner(hostile) && !decode_inner(lying) && !decode_inner(shortkey), "version 3 with no grants, the same file twice, a declared count of four billion, or a short key is rejected");
        bool prefixes = true;
        for (size_t n = 0; n < encoded.size(); n += 13)
            if (decode_inner(Bytes(encoded.begin(), encoded.begin() + static_cast<std::ptrdiff_t>(n)))) prefixes = false;
        Bytes trailing = encoded; trailing.push_back(0);
        Bytes version4 = encoded; version4[3] = 4;
        CHECK(prefixes && !decode_inner(trailing) && !decode_inner(version4), "every truncation, trailing bytes and a version this build doesn't know are rejected");
        (void)dup;
    }

    std::cout << "The inside of an envelope: versions and hostile input\n";
    {
        Inner x;
        x.sender_bundle = Bytes(50, 1);
        x.introduced = {Bytes(60, 2), Bytes(70, 3)};
        x.records = {Bytes(80, 4), Bytes(90, 5)};
        Bytes enc = encode_inner(x);
        auto dec = decode_inner(enc);
        CHECK(dec && dec->sender_bundle == x.sender_bundle && dec->introduced == x.introduced && dec->records == x.records, "the inside round-trips");
        Inner plain;
        plain.records = {Bytes(10, 1)};
        auto plain_back = decode_inner(encode_inner(plain));
        CHECK(plain_back && plain_back->introduced.empty() && plain_back->sender_bundle.empty() && plain_back->records == plain.records, "with nothing introduced the list is simply empty");

        // The content the first version wrote: version 1, no introduced list.
        Bytes v1;
        write_u32(v1, 1);
        write_blob(v1, Bytes(40, 9));
        write_u32(v1, 2);
        write_blob(v1, Bytes(30, 7));
        write_blob(v1, Bytes(20, 8));
        auto old = decode_inner(v1);
        CHECK(old && old->sender_bundle == Bytes(40, 9) && old->introduced.empty() && old->records.size() == 2 && old->records[0] == Bytes(30, 7) && old->records[1] == Bytes(20, 8),
              "envelope contents written by the first version are still read, with nothing introduced");
        Bytes v0 = v1; v0[3] = 0;
        Bytes v3 = v1; v3[3] = 3;
        CHECK(!decode_inner(v0) && !decode_inner(v3), "versions 0 and 3 are not understood");
        Bytes v1_with_extra = v1;
        write_u32(v1_with_extra, 0);
        CHECK(!decode_inner(v1_with_extra), "a version 1 inside with trailing bytes is rejected");

        bool prefixes = true;
        for (size_t n = 0; n < enc.size(); n++)
            if (decode_inner(Bytes(enc.begin(), enc.begin() + static_cast<std::ptrdiff_t>(n)))) prefixes = false;
        Bytes trailing = enc; trailing.push_back(0);
        CHECK(prefixes && !decode_inner(trailing) && !decode_inner(Bytes()), "every truncation, trailing bytes and empty input are rejected");

        auto crafted = [&](uint32_t introduced_count, const std::vector<Bytes>& bundles) {
            Bytes b;
            write_u32(b, 2);
            write_blob(b, Bytes());
            write_u32(b, introduced_count);
            for (const auto& bundle : bundles) write_blob(b, bundle);
            write_u32(b, 0);
            return b;
        };
        CHECK(decode_inner(crafted(1, {Bytes(10, 1)})).has_value(), "(control) a hand-written version 2 inside parses");
        CHECK(!decode_inner(crafted(0xFFFFFFFF, {})), "a declared count of four billion introduced bundles is rejected without allocating");
        CHECK(!decode_inner(crafted(16, std::vector<Bytes>(16, Bytes(10, 1)))), "16 declared is rejected");
        CHECK(!decode_inner(crafted(2, {Bytes(10, 1)})), "a count larger than the bundles present is rejected");
        CHECK(!decode_inner(crafted(1, {Bytes(MAX_BUNDLE_BYTES + 1, 1)})), "a bundle longer than the limit is rejected");
    }

    std::cout << "Size padding\n";
    {
        auto size_for = [&](size_t text_len, size_t records = 1, size_t bundle = 0) {
            Inner in;
            in.sender_bundle = Bytes(bundle, 7);
            for (size_t i = 0; i < records; i++) in.records.push_back(sign_record(make_record(alice, bob, std::string(text_len, 'a')), alice.sig.private_key));
            return seal_envelope(in, bob.kem.public_key).size();
        };
        size_t short_a = size_for(3), short_b = size_for(300);
        CHECK(short_a == short_b, "a 3-byte and a 300-byte message produce envelopes of the same size (" + std::to_string(short_a) + ")");
        size_t medium = size_for(2000), large = size_for(20000), huge = size_for(32768);
        // A signed record always carries a 3.3 KB signature, so in practice the smallest size used is 4 KiB.
        CHECK(medium > short_a && large > medium && huge >= large, "bigger messages move up to the next size: " + std::to_string(short_a) + ", " + std::to_string(medium) + ", " + std::to_string(large) + ", " + std::to_string(huge));
        CHECK(size_for(2100) == medium && size_for(3000) == medium, "sizes inside one bucket are indistinguishable");
        CHECK(huge <= relay::MAX_ENVELOPE_BYTES, "the largest envelope fits the relay's limit (" + std::to_string(huge) + " <= " + std::to_string(relay::MAX_ENVELOPE_BYTES) + ")");
        CHECK(size_for(500, 1, 3300) > size_for(500), "including a sender bundle can push a message into a bigger bucket");
        Inner too_big;
        for (int i = 0; i < 4; i++) too_big.records.push_back(sign_record(make_record(alice, bob, std::string(MAX_TEXT_BYTES, 'z')), alice.sig.private_key));
        CHECK(throws([&] { seal_envelope(too_big, bob.kem.public_key); }), "content beyond 64 KiB is refused rather than truncated");
        Inner many;
        for (size_t i = 0; i <= MAX_RECORDS_PER_ENVELOPE; i++) many.records.push_back(Bytes(10, 1));
        CHECK(throws([&] { seal_envelope(many, bob.kem.public_key); }), "more records than the limit is refused");
    }

    std::cout << (failures ? "\nFAILURES: " : "\nAll checks passed. ") << failures << "\n";
    return failures ? 1 : 0;
}
