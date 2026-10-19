// Tests for verified contacts: signed bundles in the KeyStore and the import rules.
// POSIX only (switches $HOME to get throwaway key directories).
#include "crypto_engine.h"
#include "identity_bundle.h"
#include "key_store.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <unistd.h>

namespace fs = std::filesystem;

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

        // Someone swaps the saved encryption key on disk: the bundle no longer matches.
        fs::path dir = ROOT / "bob/.pq-file-transfer/contacts/Alice";
        spit(dir / "pub_kem", mallory_kem.public_key);
        c = bob.load_contact("Alice");
        CHECK(c && !c->kem_verified, "an encryption key swapped on disk is no longer shown as verified");

        bob.save_contact_bundle("Alice", b1);
        spit(dir / "bundle", {1, 2, 3, 4});
        c = bob.load_contact("Alice");
        CHECK(c && !c->kem_verified, "a damaged bundle file means unverified, not a crash");

        bob.save_contact_bundle("Alice", b1);
        bob.save_contact("Alice", alice_kem_pub, alice_ks.load_public_dsa());
        c = bob.load_contact("Alice");
        CHECK(c && !c->kem_verified && !fs::exists(dir / "bundle"), "re-saving from key files drops the old bundle");

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

    fs::remove_all(ROOT);
    std::cout << (failures ? "\nFAILURES: " : "\nAll checks passed. ") << failures << "\n";
    return failures ? 1 : 0;
}
