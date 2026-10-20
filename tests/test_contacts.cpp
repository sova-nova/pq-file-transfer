// Tests for verified contacts: signed bundles in the KeyStore and the import rules.
// POSIX only (switches $HOME to get throwaway key directories).
#include "crypto_engine.h"
#include "identity_bundle.h"
#include "key_store.h"

#include <algorithm>
#include <cstdlib>
#include <sys/stat.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <unistd.h>

namespace fs = std::filesystem;

using Bytes = std::vector<uint8_t>;

static int failures = 0;
#define CHECK(c, msg)                                                  \
    do {                                                               \
        if (c) std::cout << "  PASS " << (msg) << "\n";                \
        else { std::cout << "  FAIL " << (msg) << "\n"; failures++; } \
    } while (0)

static fs::path ROOT;
static void as(const std::string& user) { setenv("HOME", (ROOT / user).c_str(), 1); }
static void spit(const fs::path& p, const std::vector<uint8_t>& d) { std::ofstream f(p, std::ios::binary | std::ios::trunc); f.write(reinterpret_cast<const char*>(d.data()), static_cast<std::streamsize>(d.size())); }
template <typename F> static bool throws(F f) { try { f(); } catch (const std::exception&) { return true; } return false; }

// A bundle with chosen contents, made with `id`'s signing key.
static IdentityBundle make_bundle(const CryptoEngine::SigKeyPair& sig, const std::vector<uint8_t>& kem_pub,
                                  uint64_t issued, const std::string& name = "Alice") {
    auto raw = create_identity_bundle(sig.public_key, kem_pub, name, "", issued, sig.private_key);
    auto b = parse_identity_bundle(raw);
    if (!b) { std::cout << "test setup failed: bundle did not parse\n"; std::exit(2); }
    return *b;
}

int main() {
    ROOT = fs::temp_directory_path() / ("pqft-contacts-" + std::to_string(getpid()));
    fs::remove_all(ROOT);
    fs::create_directories(ROOT);

    // Alice is the identity others will add; Bob is the person doing the adding.
    as("alice"); KeyStore alice_ks; alice_ks.set_kdf_cost(10); alice_ks.initialize_keys();
    as("bob");   KeyStore bob;                  bob.initialize_keys();
    auto alice_sig = CryptoEngine::SigKeyPair{alice_ks.load_public_dsa(), alice_ks.load_private_dsa()};
    auto alice_kem_pub = alice_ks.load_public_kem();
    auto mallory_kem = CryptoEngine::generate_kem_keypair();

    std::cout << "Creating own bundles\n";
    {
        as("alice");
        auto raw = alice_ks.make_own_bundle("Alice", "10.8.0.1");
        auto b = parse_identity_bundle(raw);
        CHECK(b && b->signing_key == alice_ks.load_public_dsa() && b->encryption_key == alice_kem_pub && b->display_name == "Alice",
              "make_own_bundle signs the user's real public keys");
        CHECK(b && b->fingerprint() == alice_ks.own_fingerprint(), "its fingerprint is the user's existing fingerprint");
        CHECK(alice_ks.self_contact().kem_verified, "your own contact counts as verified");

        // With a passphrase, a locked key store cannot sign.
        as("carol");
        KeyStore carol; carol.set_kdf_cost(10); carol.initialize_keys("carol passphrase");
        KeyStore reopened; reopened.set_kdf_cost(10); reopened.initialize_keys();
        CHECK(reopened.private_keys_locked() && throws([&] { reopened.make_own_bundle("Carol"); }), "locked keys cannot make a bundle");
        CHECK(reopened.unlock("carol passphrase") && parse_identity_bundle(reopened.make_own_bundle("Carol")).has_value(),
              "after unlocking, they can");
    }

    as("bob");
    std::cout << "Saving and loading contacts\n";
    {
        bob.save_contact("Alice", alice_kem_pub, alice_ks.load_public_dsa());
        auto c = bob.load_contact("Alice");
        CHECK(c && !c->kem_verified && c->bundle_issued_at == 0, "a contact saved from key files is NOT verified");

        auto b1 = make_bundle(alice_sig, alice_kem_pub, 1000);
        bob.save_contact_bundle("Alice", b1);
        c = bob.load_contact("Alice");
        CHECK(c && c->kem_verified && c->bundle_issued_at == 1000 && c->pub_kem == alice_kem_pub, "saving from a bundle marks the key verified");
        auto passed_on = bob.load_contact_bundle_raw("Alice");
        CHECK(passed_on && *passed_on == b1.raw, "the saved bundle can be read back exactly, to pass on to others");
        CHECK(!bob.load_contact_bundle_raw("Nobody") && !bob.load_contact_bundle_raw("../keys"), "an unknown contact, or a path-like name, has none");

        // Someone swaps the saved encryption key on disk: the bundle no longer matches.
        fs::path dir = ROOT / "bob/.pq-file-transfer/contacts/Alice";
        spit(dir / "pub_kem", mallory_kem.public_key);
        c = bob.load_contact("Alice");
        CHECK(c && !c->kem_verified, "an encryption key swapped on disk is no longer shown as verified");
        CHECK(!bob.load_contact_bundle_raw("Alice"), "...and its bundle is no longer offered to pass on, since it doesn't match");

        bob.save_contact_bundle("Alice", b1);
        spit(dir / "bundle", {1, 2, 3, 4});
        c = bob.load_contact("Alice");
        CHECK(c && !c->kem_verified, "a damaged bundle file means unverified, not a crash");
        CHECK(!bob.load_contact_bundle_raw("Alice"), "...and nothing to pass on");

        bob.save_contact_bundle("Alice", b1);
        bob.save_contact("Alice", alice_kem_pub, alice_ks.load_public_dsa());
        c = bob.load_contact("Alice");
        CHECK(c && !c->kem_verified && !fs::exists(dir / "bundle"), "re-saving from key files drops the old bundle");
        CHECK(!bob.load_contact_bundle_raw("Alice"), "a contact saved from key files has no bundle to pass on");

        CHECK(throws([&] { bob.save_contact_bundle("../keys", b1); }), "a path-like contact name is refused");
        IdentityBundle empty;
        CHECK(throws([&] { bob.save_contact_bundle("Alice", empty); }), "an empty bundle is refused");
        bob.delete_contact("Alice");
    }

    std::cout << "Importing bundles for known identities\n";
    {
        auto b1 = make_bundle(alice_sig, alice_kem_pub, 1000);
        auto unknown = bob.import_bundle_for_known_identity(b1);
        CHECK(unknown.result == KeyStore::BundleImportResult::UnknownIdentity, "a bundle from nobody saved is reported as a new identity");

        // Bob once added Alice from an old v1 card that an attacker had tampered with.
        bob.save_contact("Alice", mallory_kem.public_key, alice_ks.load_public_dsa());
        auto healed = bob.import_bundle_for_known_identity(b1);
        auto c = bob.load_contact("Alice");
        CHECK(healed.result == KeyStore::BundleImportResult::Updated && healed.encryption_key_changed && healed.was_unverified,
              "a genuine bundle replaces the tampered key and says so");
        CHECK(c && c->kem_verified && c->pub_kem == alice_kem_pub, "the contact now holds Alice's real key, verified");

        auto again = bob.import_bundle_for_known_identity(b1);
        CHECK(again.result == KeyStore::BundleImportResult::Unchanged, "importing the same bundle again changes nothing");

        auto rotated_kem = CryptoEngine::generate_kem_keypair();
        auto b2 = make_bundle(alice_sig, rotated_kem.public_key, 2000);
        auto rotated = bob.import_bundle_for_known_identity(b2);
        c = bob.load_contact("Alice");
        CHECK(rotated.result == KeyStore::BundleImportResult::Updated && rotated.encryption_key_changed && !rotated.was_unverified,
              "a newer bundle with a rotated encryption key updates silently");
        CHECK(c && c->kem_verified && c->pub_kem == rotated_kem.public_key && c->bundle_issued_at == 2000, "the contact now has the rotated key");

        auto replay = bob.import_bundle_for_known_identity(b1);
        c = bob.load_contact("Alice");
        CHECK(replay.result == KeyStore::BundleImportResult::Stale && c && c->pub_kem == rotated_kem.public_key,
              "an older bundle with a different key is ignored (replay of an old key)");

        auto same_keys_older = make_bundle(alice_sig, rotated_kem.public_key, 1500);
        CHECK(bob.import_bundle_for_known_identity(same_keys_older).result == KeyStore::BundleImportResult::Unchanged,
              "an older bundle with the same key is harmless");
        auto same_time = make_bundle(alice_sig, rotated_kem.public_key, 2000);
        CHECK(bob.import_bundle_for_known_identity(same_time).result == KeyStore::BundleImportResult::Unchanged, "the same timestamp is not newer");

        // A different signing key is a different identity, even with the same display name.
        auto other_sig = CryptoEngine::generate_sig_keypair();
        auto other = make_bundle(other_sig, CryptoEngine::generate_kem_keypair().public_key, 3000, "Alice");
        CHECK(bob.import_bundle_for_known_identity(other).result == KeyStore::BundleImportResult::UnknownIdentity,
              "a different signing key is never merged into an existing contact");
        c = bob.load_contact("Alice");
        CHECK(c && c->pub_dsa == alice_ks.load_public_dsa(), "and the saved contact is untouched");
    }


    std::cout << "Contact routes and send tokens\n";
    {
        as("bob");
        bob.delete_contact("Alice");  // left over from the section above: same signing key as the test identity
        Bytes relay_id = CryptoEngine::random_bytes(32), mailbox = CryptoEngine::random_bytes(16), token = CryptoEngine::random_bytes(32);
        auto routed_raw = create_identity_bundle(alice_sig.public_key, alice_kem_pub, "Alice", BundleAddress{"10.8.0.1:9000", relay_id, mailbox}, 5000, alice_sig.private_key);
        auto routed = *parse_identity_bundle(routed_raw);

        bob.save_contact_bundle("Carol Route", routed);
        auto c = bob.load_contact("Carol Route");
        CHECK(c && c->relay_address == "10.8.0.1:9000" && c->relay_id == relay_id && c->mailbox_id == mailbox, "a contact's mailbox address comes from their verified bundle");
        CHECK(c && !c->can_message(), "...but without a send token they can't be messaged yet");
        bob.save_contact_token("Carol Route", token);
        c = bob.load_contact("Carol Route");
        CHECK(c && c->send_token == token && c->can_message(), "with the token issued by them, they can");
        struct stat st{};
        stat((ROOT / "bob/.pq-file-transfer/contacts/Carol Route/send_token").c_str(), &st);
        CHECK((st.st_mode & 077) == 0, "the token file is owner-only");
        CHECK(throws([&] { bob.save_contact_token("Carol Route", Bytes(5, 1)); }) && throws([&] { bob.save_contact_token("Nobody", token); }),
              "a wrong-sized token or a missing contact is refused");

        // A contact saved from key files has no address even if a token file exists.
        bob.save_contact("Carol Route", alice_kem_pub, alice_ks.load_public_dsa());
        c = bob.load_contact("Carol Route");
        CHECK(c && !c->can_message() && c->relay_address.empty(), "re-saving from key files drops the verified address");
        bob.delete_contact("Carol Route");

        // Importing a newer card brings its token.
        bob.save_contact_bundle("Dave Route", routed);
        Bytes token2 = CryptoEngine::random_bytes(32);
        auto newer_raw = create_identity_bundle(alice_sig.public_key, alice_kem_pub, "Alice", BundleAddress{"10.8.0.2:9000", relay_id, mailbox}, 6000, alice_sig.private_key);
        auto newer = *parse_identity_bundle(newer_raw);
        auto r = bob.import_bundle_for_known_identity(newer, token2);
        c = bob.load_contact("Dave Route");
        CHECK(r.result == KeyStore::BundleImportResult::Updated && c && c->relay_address == "10.8.0.2:9000" && c->send_token == token2,
              "a newer card updates the address and saves its token");
        auto same = bob.import_bundle_for_known_identity(newer, token2);
        CHECK(same.result == KeyStore::BundleImportResult::Unchanged, "the same card again changes nothing");
        Bytes token3 = CryptoEngine::random_bytes(32);
        auto fresh_token = bob.import_bundle_for_known_identity(newer, token3);
        c = bob.load_contact("Dave Route");
        CHECK(fresh_token.result == KeyStore::BundleImportResult::Updated && c && c->send_token == token3, "a fresh card for the same keys still replaces the token");
        auto older = *parse_identity_bundle(routed_raw);
        auto stale = bob.import_bundle_for_known_identity(older, CryptoEngine::random_bytes(32));
        c = bob.load_contact("Dave Route");
        CHECK(c && c->send_token == token3 && c->relay_address == "10.8.0.2:9000" && stale.result != KeyStore::BundleImportResult::Updated,
              "an older card can't roll back the address or the token");
        bob.delete_contact("Dave Route");
    }

    std::cout << "Local keys derived from the identity\n";
    {
        as("dora");
        KeyStore ks; ks.set_kdf_cost(10); ks.initialize_keys("dora has a passphrase");
        auto a1 = ks.derive_local_key("history"), a2 = ks.derive_local_key("history"), other = ks.derive_local_key("something else");
        CHECK(a1.size() == 32 && a1 == a2, "a derived key is 32 bytes and repeatable");
        CHECK(a1 != other, "different labels give different keys");

        KeyStore reopened; reopened.set_kdf_cost(10); reopened.initialize_keys();
        CHECK(reopened.private_keys_locked() && reopened.derive_local_key("history").empty(), "while locked, no local key is available");
        reopened.unlock("dora has a passphrase");
        CHECK(reopened.derive_local_key("history") == a1, "after unlocking, the same key comes back");
        reopened.set_passphrase("a different passphrase");
        CHECK(reopened.derive_local_key("history") == a1, "changing the passphrase doesn't change it, so existing history stays readable");
        as("eric"); KeyStore other_user; other_user.initialize_keys();
        CHECK(other_user.derive_local_key("history") != a1, "another identity gets a different key");
    }

    std::cout << "The mailbox access key\n";
    {
        as("fay");
        KeyStore ks; ks.set_kdf_cost(10); ks.initialize_keys("fay has a passphrase");
        CHECK(!ks.has_access_key(), "no access key at first");
        ks.create_access_key();
        auto pub = ks.load_access_public(), priv = ks.load_access_private();
        CHECK(ks.has_access_key() && pub.size() == CryptoEngine::sig_public_key_size() && priv.size() == CryptoEngine::sig_secret_key_size(), "an access key pair is created");
        auto sig = CryptoEngine::sign({9, 9}, priv);
        CHECK(CryptoEngine::verify({9, 9}, sig, pub), "its halves belong together");
        CHECK(throws([&] { ks.create_access_key(); }), "a second one is refused");

        fs::path stored = ROOT / "fay/.pq-file-transfer/keys/private_access.enc";
        std::ifstream f(stored, std::ios::binary);
        Bytes on_disk((std::istreambuf_iterator<char>(f)), {});
        CHECK(on_disk.size() > priv.size() && std::search(on_disk.begin(), on_disk.end(), priv.begin(), priv.begin() + 32) == on_disk.end(),
              "the private half is encrypted on disk");
        struct stat st{};
        stat(stored.c_str(), &st);
        CHECK((st.st_mode & 077) == 0, "...and owner-only");

        KeyStore reopened; reopened.set_kdf_cost(10); reopened.initialize_keys();
        CHECK(reopened.has_access_key() && reopened.load_access_private().empty(), "while the keys are locked the access key can't be read");
        reopened.unlock("fay has a passphrase");
        CHECK(reopened.load_access_private() == priv, "after unlocking it can");
        reopened.set_passphrase("fay changed it");
        CHECK(reopened.load_access_private() == priv, "changing the passphrase doesn't affect it");

        Bytes damaged = on_disk; damaged[40] ^= 1;
        spit(stored, damaged);
        CHECK(reopened.load_access_private().empty(), "a damaged file reads as missing, not as a wrong key");

        as("gus"); KeyStore locked_new; locked_new.set_kdf_cost(10); locked_new.initialize_keys("gus passphrase");
        KeyStore locked; locked.initialize_keys();
        CHECK(throws([&] { locked.create_access_key(); }), "creating one needs the keys unlocked");
    }

    std::cout << "Mailbox configuration\n";
    {
        as("hal");
        KeyStore ks; ks.initialize_keys();
        CHECK(!ks.load_mailbox_config(), "none saved at first");
        KeyStore::MailboxConfig cfg{"10.8.0.1", 9000, CryptoEngine::random_bytes(32), CryptoEngine::random_bytes(16)};
        ks.save_mailbox_config(cfg);
        auto got = ks.load_mailbox_config();
        CHECK(got && got->host == cfg.host && got->port == 9000 && got->relay_id == cfg.relay_id && got->mailbox_id == cfg.mailbox_id, "saves and loads");
        spit(ROOT / "hal/.pq-file-transfer/mailbox.cfg", {1, 2, 3});
        CHECK(!ks.load_mailbox_config(), "a damaged config reads as none");
    }

    fs::remove_all(ROOT);
    std::cout << (failures ? "\nFAILURES: " : "\nAll checks passed. ") << failures << "\n";
    return failures ? 1 : 0;
}
