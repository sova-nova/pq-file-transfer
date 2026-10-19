// Tests for signed message records and sealed envelopes.
#include "crypto_engine.h"
#include "envelope.h"
#include "message_record.h"
#include "protocol.h"
#include "relay_protocol.h"

#include <algorithm>
#include <iostream>
#include <string>

using namespace chat;

static int failures = 0;
#define CHECK(c, msg)                                                  \
    do {                                                               \
        if (c) std::cout << "  PASS " << (msg) << "\n";                \
        else { std::cout << "  FAIL " << (msg) << "\n"; failures++; } \
    } while (0)

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
        r.seen = CryptoEngine::random_bytes(HASH_BYTES);
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
