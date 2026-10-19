// Tests for passphrase-protected private keys: the file format and the KeyStore lifecycle.
// POSIX only (switches $HOME to get a throwaway key directory).
#include "crypto_engine.h"
#include "key_store.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <algorithm>
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

static const uint8_t FAST = 10;  // cheapest scrypt cost, to keep the tests quick
static const std::string PASS = "correct horse battery";

static std::vector<uint8_t> slurp(const fs::path& p) { std::ifstream f(p, std::ios::binary); return {std::istreambuf_iterator<char>(f), {}}; }
static void spit(const fs::path& p, const std::vector<uint8_t>& d) { std::ofstream f(p, std::ios::binary | std::ios::trunc); f.write(reinterpret_cast<const char*>(d.data()), static_cast<std::streamsize>(d.size())); }

template <typename F> static bool throws(F f) { try { f(); } catch (const std::exception&) { return true; } return false; }

static void test_blob_format() {
    std::cout << "Protected blob format\n";
    auto secret = CryptoEngine::random_bytes(2400);
    auto blob = CryptoEngine::protect_secret(secret, PASS, "private_kem", FAST);

    CHECK(CryptoEngine::is_protected_blob(blob), "recognised as protected");
    CHECK(!CryptoEngine::is_protected_blob(secret), "raw key bytes are not mistaken for one");
    CHECK(blob.size() == 37 + secret.size() + 16, "overhead is header (37) + tag (16)");
    auto plain = CryptoEngine::unprotect_secret(blob, PASS, "private_kem");
    CHECK(plain && *plain == secret, "round trip with the right passphrase");
    CHECK(!CryptoEngine::unprotect_secret(blob, "wrong passphrase", "private_kem"), "wrong passphrase rejected");
    CHECK(!CryptoEngine::unprotect_secret(blob, PASS, "private_dsa"), "right passphrase but wrong key label rejected");
    CHECK(!CryptoEngine::unprotect_secret(blob, "", "private_kem"), "empty passphrase rejected");

    auto blob2 = CryptoEngine::protect_secret(secret, PASS, "private_kem", FAST);
    CHECK(blob != blob2, "same secret and passphrase give different blobs (random salt and nonce)");
    CHECK(std::search(blob.begin(), blob.end(), secret.begin(), secret.begin() + 32) == blob.end(),
          "the secret does not appear in the blob");

    // Flip one byte in each region; every change must be detected.
    struct Region { const char* name; size_t pos; };
    for (Region r : {Region{"version", 4}, Region{"kdf id", 5}, Region{"log2(N)", 6}, Region{"r", 7}, Region{"p", 8},
                     Region{"salt", 9}, Region{"nonce", 30}, Region{"ciphertext", 60}, Region{"tag", blob.size() - 1}}) {
        auto bad = blob;
        bad[r.pos] ^= 0x01;
        bool rejected = false;
        try { rejected = !CryptoEngine::unprotect_secret(bad, PASS, "private_kem"); }
        catch (const std::exception&) { rejected = true; }
        CHECK(rejected, std::string("tampering with the ") + r.name + " is detected");
    }

    auto huge = blob; huge[6] = 30;
    CHECK(throws([&] { CryptoEngine::unprotect_secret(huge, PASS, "private_kem"); }), "absurd memory cost refused");
    auto tiny = blob; tiny[6] = 4;
    CHECK(throws([&] { CryptoEngine::unprotect_secret(tiny, PASS, "private_kem"); }), "trivially cheap cost refused");
    CHECK(throws([&] { CryptoEngine::unprotect_secret(std::vector<uint8_t>(blob.begin(), blob.begin() + 20), PASS, "private_kem"); }),
          "truncated blob reported as damaged");
    CHECK(throws([&] { CryptoEngine::protect_secret(secret, "", "private_kem", FAST); }), "protecting with an empty passphrase refused");
    CHECK(throws([&] { CryptoEngine::protect_secret(secret, PASS, "private_kem", 30); }), "protecting with an absurd cost refused");

    auto nfc = CryptoEngine::protect_secret(secret, "pass\xC3\xA9word", "private_kem", FAST);
    CHECK(CryptoEngine::unprotect_secret(nfc, "pass\xC3\xA9word", "private_kem").has_value(), "UTF-8 passphrase works");
}

static void test_keystore_lifecycle() {
    std::cout << "KeyStore lifecycle\n";
    fs::path home = fs::temp_directory_path() / ("pqft-keys-" + std::to_string(getpid()));
    fs::remove_all(home);
    fs::create_directories(home);
    setenv("HOME", home.c_str(), 1);
    fs::path keys = home / ".pq-file-transfer" / "keys";

    CHECK(!KeyStore::is_acceptable_passphrase("short"), "7 characters is too short");
    CHECK(KeyStore::is_acceptable_passphrase("long enough"), "a longer passphrase is accepted");

    std::vector<uint8_t> kem_secret, dsa_secret;
    {
        KeyStore ks; ks.set_kdf_cost(FAST);
        CHECK(!ks.keys_exist(), "no keys before first run");
        CHECK(throws([&] { ks.initialize_keys("short"); }), "a short passphrase is refused at creation");
        CHECK(!ks.keys_exist(), "nothing was written by the refused attempt");

        ks.initialize_keys(PASS);
        CHECK(ks.keys_exist() && ks.private_keys_protected(), "keys created protected");
        CHECK(!ks.private_keys_locked(), "a fresh install starts unlocked");
        CHECK(CryptoEngine::is_protected_blob(slurp(keys / "private_kem")), "private_kem is encrypted on disk");
        CHECK(CryptoEngine::is_protected_blob(slurp(keys / "private_dsa")), "private_dsa is encrypted on disk");
        CHECK(!CryptoEngine::is_protected_blob(slurp(keys / "public_kem")), "public keys stay readable");
        kem_secret = ks.load_private_kem(); dsa_secret = ks.load_private_dsa();
        CHECK(kem_secret.size() == CryptoEngine::kem_secret_key_size() && dsa_secret.size() == CryptoEngine::sig_secret_key_size(),
              "unlocked keys have the right sizes");
        auto perms = fs::status(keys / "private_kem").permissions();
        CHECK((perms & (fs::perms::group_all | fs::perms::others_all)) == fs::perms::none, "private key file is owner-only");
    }

    {
        KeyStore ks; ks.set_kdf_cost(FAST);
        CHECK(!throws([&] { ks.initialize_keys(); }), "reopening protected keys doesn't throw");
        CHECK(ks.private_keys_protected() && ks.private_keys_locked(), "reopened: protected and locked");
        CHECK(ks.load_private_kem().empty() && ks.load_private_dsa().empty(), "locked: private keys are not readable");
        CHECK(!ks.load_public_kem().empty() && ks.own_fingerprint().size() == 64, "locked: public keys and fingerprint still work");
        CHECK(!ks.unlock("wrong passphrase"), "wrong passphrase doesn't unlock");
        CHECK(ks.private_keys_locked(), "still locked after a wrong attempt");
        CHECK(!ks.unlock(""), "empty passphrase doesn't unlock");
        CHECK(ks.verify_passphrase(PASS) && !ks.verify_passphrase("nope nope nope"), "verify_passphrase tells right from wrong");
        CHECK(ks.private_keys_locked(), "verify_passphrase doesn't unlock");
        CHECK(throws([&] { ks.set_passphrase("another long phrase"); }), "can't change the passphrase while locked");
        CHECK(throws([&] { ks.remove_passphrase(); }), "can't remove the passphrase while locked");

        CHECK(ks.unlock(PASS), "right passphrase unlocks");
        CHECK(!ks.private_keys_locked() && ks.load_private_kem() == kem_secret && ks.load_private_dsa() == dsa_secret,
              "unlocked keys are the original keys");
        auto sig = CryptoEngine::sign({1, 2, 3}, ks.load_private_dsa());
        CHECK(CryptoEngine::verify({1, 2, 3}, sig, ks.load_public_dsa()), "unlocked private key matches the public key");
        ks.lock();
        CHECK(ks.private_keys_locked() && ks.load_private_dsa().empty(), "lock() forgets the keys");
    }

    {
        KeyStore ks; ks.set_kdf_cost(FAST); ks.initialize_keys();
        CHECK(ks.unlock(PASS), "unlock before changing");
        ks.set_passphrase("another long phrase");
        CHECK(!ks.private_keys_locked(), "changing the passphrase keeps the session unlocked");
        KeyStore other; other.initialize_keys();
        CHECK(!other.unlock(PASS), "old passphrase no longer works");
        CHECK(other.unlock("another long phrase") && other.load_private_kem() == kem_secret, "new passphrase works, same keys");
    }

    {
        KeyStore ks; ks.set_kdf_cost(FAST); ks.initialize_keys();
        CHECK(ks.unlock("another long phrase"), "unlock before removing");
        ks.remove_passphrase();
        CHECK(!ks.private_keys_protected() && !ks.private_keys_locked(), "protection removed");
        CHECK(slurp(keys / "private_kem") == kem_secret && slurp(keys / "private_dsa") == dsa_secret, "keys on disk are the original bytes");
        auto perms = fs::status(keys / "private_kem").permissions();
        CHECK((perms & (fs::perms::group_all | fs::perms::others_all)) == fs::perms::none, "still owner-only after removal");
        KeyStore other; other.initialize_keys();
        CHECK(!other.private_keys_protected() && other.load_private_kem() == kem_secret, "a new session reads them directly");

        ks.set_passphrase(PASS);
        CHECK(ks.private_keys_protected() && CryptoEngine::is_protected_blob(slurp(keys / "private_kem")), "protecting existing plain keys works");
        CHECK(throws([&] { ks.set_passphrase("short"); }), "a short new passphrase is refused");
        CHECK(ks.verify_passphrase(PASS), "refused change left the old passphrase intact");
    }

    std::cout << "Interrupted protect and damage\n";
    {
        // Simulate a crash after only one of the two files was rewritten.
        spit(keys / "private_kem", kem_secret);
        KeyStore ks; ks.set_kdf_cost(FAST); ks.initialize_keys();
        CHECK(ks.private_keys_protected() && ks.private_keys_locked(), "mixed state: treated as protected and locked");
        CHECK(ks.unlock(PASS), "mixed state: unlocks with the passphrase");
        CHECK(ks.load_private_kem() == kem_secret, "mixed state: no key material lost");
        CHECK(CryptoEngine::is_protected_blob(slurp(keys / "private_kem")), "mixed state: unlock finishes the interrupted protection");

        // A damaged protected file must produce an error, not a silent wrong-passphrase.
        auto damaged = std::vector<uint8_t>{'P', 'Q', 'K', 'E', 1, 1, 10, 8, 1, 0, 0, 0};
        spit(keys / "private_dsa", damaged);
        KeyStore bad; bad.initialize_keys();
        CHECK(throws([&] { bad.unlock(PASS); }), "damaged protected file is reported as an error");

        // A swapped pair of files must not unlock: the labels are authenticated.
        spit(keys / "private_dsa", slurp(keys / "private_kem"));
        KeyStore swapped; swapped.initialize_keys();
        CHECK(!swapped.unlock(PASS), "private_kem copied over private_dsa is rejected");
    }
    fs::remove_all(home);
}

int main() {
    test_blob_format();
    test_keystore_lifecycle();
    std::cout << (failures ? "\nFAILURES: " : "\nAll checks passed. ") << failures << "\n";
    return failures ? 1 : 0;
}
