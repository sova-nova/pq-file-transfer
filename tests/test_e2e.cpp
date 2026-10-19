// End-to-end tests: real pq-server process, real TransferEngine/KeyStore/CryptoEngine.
// Usage: test_e2e /path/to/pq-server        (POSIX only; each "user" gets its own $HOME)
#include "crypto_engine.h"
#include "protocol.h"
#include "sharing.h"
#include "transfer_engine.h"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>

#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

namespace fs = std::filesystem;

static fs::path ROOT;
static fs::path STORE;
static std::string SERVER_BIN;
static int PORT = 0;
static pid_t server_pid = -1;
static int failures = 0;

#define CHECK(c, msg)                                                  \
    do {                                                               \
        if (c) std::cout << "  PASS " << (msg) << "\n";                \
        else { std::cout << "  FAIL " << (msg) << "\n"; failures++; } \
    } while (0)

static bool contains(const std::string& s, const char* needle) { return s.find(needle) != std::string::npos; }

// --- helpers ---

static void as(const std::string& user) { setenv("HOME", (ROOT / user).c_str(), 1); }
static std::vector<uint8_t> slurp(const fs::path& p) { std::ifstream f(p, std::ios::binary); return {std::istreambuf_iterator<char>(f), {}}; }
static void spit(const fs::path& p, const std::vector<uint8_t>& d) { std::ofstream f(p, std::ios::binary); f.write(reinterpret_cast<const char*>(d.data()), static_cast<std::streamsize>(d.size())); }

static bool can_connect() {
    addrinfo hints{}, *ai = nullptr;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo("127.0.0.1", std::to_string(PORT).c_str(), &hints, &ai) != 0) return false;
    int s = socket(ai->ai_family, ai->ai_socktype, 0);
    bool ok = s >= 0 && connect(s, ai->ai_addr, ai->ai_addrlen) == 0;
    if (s >= 0) close(s);
    freeaddrinfo(ai);
    return ok;
}

static bool start_server() {
    server_pid = fork();
    if (server_pid == 0) {
        int log = open((ROOT / "server.log").c_str(), O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (log >= 0) { dup2(log, 1); dup2(log, 2); }
        std::string port = std::to_string(PORT);
        execl(SERVER_BIN.c_str(), SERVER_BIN.c_str(), "--port", port.c_str(), "--bind", "127.0.0.1",
              "--storage", STORE.c_str(), static_cast<char*>(nullptr));
        _exit(127);
    }
    for (int i = 0; i < 100; i++) {
        if (can_connect()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return false;
}

static void stop_server() {
    if (server_pid > 0) { kill(server_pid, SIGTERM); waitpid(server_pid, nullptr, 0); server_pid = -1; }
}

struct Result { bool ok = false; std::string error, id, path; };

static Result send(const std::string& user, const fs::path& file, const KeyStore::Contact& to) {
    as(user); Result r; TransferEngine e;
    e.on_error = [&](const std::string& m) { r.error = m; };
    e.on_transfer_id = [&](const std::string& id) { r.id = id; };
    e.on_complete = [&](const std::string&) { r.ok = true; };
    e.upload_file(file.u8string(), "127.0.0.1", static_cast<uint16_t>(PORT), to);
    return r;
}

static Result recv(const std::string& user, const std::string& id) {
    as(user); Result r; TransferEngine e;
    e.on_error = [&](const std::string& m) { r.error = m; };
    e.on_complete = [&](const std::string& p) { r.ok = true; r.path = p; };
    e.download_file(id, "127.0.0.1", static_cast<uint16_t>(PORT), (ROOT / user / "dl").u8string());
    return r;
}

static KeyStore::Contact contact_of(const std::string& user) { as(user); return KeyStore().self_contact(); }

// Adds `user` to `owner`'s contacts the way the app does: through a contact card.
static void add_contact_via_card(const std::string& owner, const std::string& name, const std::string& user) {
    auto c = contact_of(user);
    ContactCard card{name, c.pub_kem, c.pub_dsa, "127.0.0.1"};
    std::string err;
    auto decoded = decode_contact_card(encode_contact_card(card), &err);
    if (!decoded) { std::cout << "card decode failed: " << err << "\n"; failures++; return; }
    as(owner);
    KeyStore().save_contact(sanitize_contact_name(decoded->name), decoded->pub_kem, decoded->pub_dsa);
}

static bool no_part_files(const std::string& user) {
    std::error_code ec;
    for (auto& e : fs::directory_iterator(ROOT / user / "dl", ec))
        if (e.path().extension() == ".part") return false;
    return true;
}

static void age_transfer(const std::string& id, std::chrono::hours age) {
    fs::path header = STORE / id / "header.bin";
    fs::last_write_time(header, fs::file_time_type::clock::now() - age);
}

// Builds a transfer by hand so a hostile filename can be injected (a trusted but
// malicious or buggy sender). Mirrors TransferEngine's upload.
static std::string raw_upload_with_filename(const std::string& sender, const KeyStore::Contact& to,
                                            const std::string& filename, const std::vector<uint8_t>& data) {
    as(sender); KeyStore ks;
    FileHeader h; h.file_size = data.size(); h.chunk_size = DEFAULT_CHUNK_SIZE;
    h.total_chunks = expected_total_chunks(h.file_size, h.chunk_size); h.nonce = CryptoEngine::random_bytes(12);
    auto enc = CryptoEngine::encapsulate(to.pub_kem); h.kem_ciphertext = enc.ciphertext;
    auto pub = serialize_header_public_fields(h);
    auto keys = CryptoEngine::derive_session_keys(enc.shared_secret, CryptoEngine::sha256(pub));
    FileMetadata m; m.filename = filename; m.sender_fingerprint = ks.own_fingerprint();
    std::vector<uint8_t> sp; write_string(sp, "pq-file-transfer v2 header signature"); write_blob(sp, pub);
    write_string(sp, m.filename); write_string(sp, m.sender_fingerprint);
    m.signature = CryptoEngine::sign(sp, ks.load_private_dsa());
    std::string aad = "pq-file-transfer v2 metadata";
    h.sealed_metadata = CryptoEngine::encrypt(keys.metadata_key, h.nonce, serialize_file_metadata(m), {aad.begin(), aad.end()});

    addrinfo* ai = nullptr; getaddrinfo("127.0.0.1", std::to_string(PORT).c_str(), nullptr, &ai);
    int s = socket(AF_INET, SOCK_STREAM, 0); connect(s, ai->ai_addr, ai->ai_addrlen); freeaddrinfo(ai);
    send_message(s, MessageType::UPLOAD_REQUEST, serialize_file_header(h));
    auto ack = recv_message(s, 4096); std::string id(ack->payload.begin(), ack->payload.end());
    std::string caad = "pq-file-transfer v2 chunk";
    std::vector<uint8_t> a(caad.begin(), caad.end()); write_u32(a, 0); a.push_back(1);
    FileChunk c{0, CryptoEngine::encrypt(keys.data_key, h.nonce, data, a)};
    send_message(s, MessageType::UPLOAD_CHUNK, serialize_file_chunk(c));
    send_message(s, MessageType::UPLOAD_DONE, {}); recv_message(s, 4096); close(s);
    return id;
}

// --- tests ---

int main(int argc, char** argv) {
    if (argc < 2) { std::cerr << "usage: test_e2e /path/to/pq-server\n"; return 2; }
    SERVER_BIN = argv[1];
    PORT = 20000 + static_cast<int>(getpid() % 20000);
    ROOT = fs::temp_directory_path() / ("pqft-e2e-" + std::to_string(getpid()));
    STORE = ROOT / "server";
    fs::remove_all(ROOT);
    fs::create_directories(ROOT);
    platform_init();

    if (!start_server()) { std::cout << "FAIL could not start " << SERVER_BIN << "\n"; return 1; }

    for (auto u : {"alice", "bob", "eve"}) { as(u); KeyStore().initialize_keys(); }
    add_contact_via_card("bob", "Alice", "alice");
    add_contact_via_card("alice", "Bob", "bob");
    auto bob = contact_of("bob");

    std::vector<uint8_t> big = CryptoEngine::random_bytes(300000);
    spit(ROOT / "big.bin", big);
    spit(ROOT / "empty.txt", {});

    std::cout << "1. Normal transfer (contacts added via cards), 300 KB / 5 chunks\n";
    auto up = send("alice", ROOT / "big.bin", bob);
    CHECK(up.ok && up.id.size() == 32, "upload succeeds with a 128-bit ID (" + up.error + ")");

    std::cout << "2. Share link round trip\n";
    std::string link = build_share_link({"127.0.0.1", static_cast<uint16_t>(PORT)}, up.id);
    auto parsed = parse_share_link(link);
    CHECK(parsed && parsed->transfer_id == up.id && parsed->server.port == PORT, "link parses back to the same ID/server");

    std::cout << "3. Eve has the ID but is not the recipient\n";
    auto eve = recv("eve", up.id);
    CHECK(!eve.ok && contains(eve.error, "not encrypted for your keys"), "Eve rejected: " + eve.error);
    CHECK(no_part_files("eve"), "no partial file left for Eve");

    std::cout << "4. Bob downloads after Eve's attempt, using the ID from the link\n";
    auto got = recv("bob", parsed ? parsed->transfer_id : up.id);
    CHECK(got.ok, "Bob receives it (" + got.error + ")");
    CHECK(got.ok && slurp(got.path) == big, "content matches byte-for-byte");
    auto again = recv("bob", up.id);
    CHECK(!again.ok && contains(again.error, "not found"), "server deleted it after confirmation");

    std::cout << "5. Same name again does not overwrite\n";
    auto up2 = send("alice", ROOT / "big.bin", bob); auto got2 = recv("bob", up2.id);
    CHECK(got2.ok && fs::path(got2.path).filename() == "big (1).bin", "saved as 'big (1).bin'");

    std::cout << "6. Empty file\n";
    auto up3 = send("alice", ROOT / "empty.txt", bob); auto got3 = recv("bob", up3.id);
    CHECK(got3.ok && fs::file_size(got3.path) == 0, "empty file round-trips (" + got3.error + ")");

    std::cout << "7. Unknown sender (Eve -> Bob, Bob hasn't added Eve)\n";
    auto up4 = send("eve", ROOT / "big.bin", bob); auto got4 = recv("bob", up4.id);
    CHECK(!got4.ok && contains(got4.error, "not in your contacts"), "rejected: " + got4.error);
    add_contact_via_card("bob", "Eve", "eve");
    CHECK(recv("bob", up4.id).ok, "after adding Eve, the kept transfer can be retried");

    std::cout << "8. Tampering on the server's disk\n";
    auto up5 = send("alice", ROOT / "big.bin", bob);
    auto chunk = STORE / up5.id / "chunk_00000002.bin"; auto bytes = slurp(chunk); bytes[100] ^= 1; spit(chunk, bytes);
    auto got5 = recv("bob", up5.id);
    CHECK(!got5.ok && contains(got5.error, "failed authentication"), "flipped chunk bit rejected: " + got5.error);
    CHECK(no_part_files("bob"), "partial plaintext deleted");
    auto up6 = send("alice", ROOT / "big.bin", bob);
    fs::remove(STORE / up6.id / "chunk_00000004.bin");
    auto got6 = recv("bob", up6.id);
    CHECK(!got6.ok, "dropped final chunk rejected: " + got6.error);
    CHECK(no_part_files("bob"), "partial plaintext deleted");
    auto up7 = send("alice", ROOT / "big.bin", bob);
    auto hb = slurp(STORE / up7.id / "header.bin"); hb[15] ^= 1; spit(STORE / up7.id / "header.bin", hb);
    CHECK(!recv("bob", up7.id).ok, "edited public header rejected");

    std::cout << "9. Hostile filenames from a trusted contact stay inside the downloads folder\n";
    for (std::string evil : std::vector<std::string>{"../../../tmp/pqft-pwned.txt", "/etc/passwd", "..\\..\\win.ini",
                                                     ".bashrc", "CON.txt", std::string("a\x01\xff" "b.txt")}) {
        auto id = raw_upload_with_filename("alice", bob, evil, {'h', 'i'});
        auto r = recv("bob", id);
        bool inside = r.ok && fs::path(r.path).parent_path() == ROOT / "bob" / "dl";
        CHECK(inside, "'" + evil + "' -> '" + (r.ok ? fs::path(r.path).filename().string() : r.error) + "'");
    }
    CHECK(!fs::exists("/tmp/pqft-pwned.txt"), "nothing written outside the downloads folder");

    std::cout << "10. Sending to yourself\n";
    auto me = contact_of("alice");
    auto up8 = send("alice", ROOT / "big.bin", me); auto got8 = recv("alice", up8.id);
    CHECK(got8.ok && slurp(got8.path) == big, "self send works (" + got8.error + ")");

    std::cout << "11. Bad transfer IDs\n";
    auto g = recv("bob", "../../etc/passwd");
    CHECK(!g.ok && contains(g.error, "transfer ID"), "rejected client-side: " + g.error);
    auto g2 = recv("bob", std::string(32, 'a'));
    CHECK(!g2.ok && contains(g2.error, "not found"), "unknown ID: " + g2.error);

    std::cout << "12. Server restart: transfers survive, expiry is honoured\n";
    auto fresh = send("alice", ROOT / "big.bin", bob);
    auto near_expiry = send("alice", ROOT / "big.bin", bob);
    auto stale = send("alice", ROOT / "big.bin", bob);
    stop_server();
    age_transfer(near_expiry.id, std::chrono::hours(23));
    age_transfer(stale.id, std::chrono::hours(25));
    CHECK(start_server(), "server restarts");
    auto r_fresh = recv("bob", fresh.id);
    CHECK(r_fresh.ok, "fresh transfer survives a restart (" + r_fresh.error + ")");
    auto r_near = recv("bob", near_expiry.id);
    CHECK(r_near.ok, "23-hour-old transfer is still available (" + r_near.error + ")");
    auto r_stale = recv("bob", stale.id);
    CHECK(!r_stale.ok && contains(r_stale.error, "not found"), "25-hour-old transfer is gone: " + r_stale.error);
    CHECK(!fs::exists(STORE / stale.id), "expired transfer's files were deleted from disk");

    std::cout << "13. Key store hardening\n";
    as("bob");
    auto perms = fs::status(ROOT / "bob/.pq-file-transfer/keys/private_kem").permissions();
    CHECK((perms & (fs::perms::group_all | fs::perms::others_all)) == fs::perms::none, "private keys are owner-only");
    bool threw = false;
    try { KeyStore().save_contact("../keys", bob.pub_kem, bob.pub_dsa); } catch (...) { threw = true; }
    CHECK(threw, "contact name '../keys' rejected");
    fs::remove(ROOT / "eve/.pq-file-transfer/keys/public_kem"); as("eve");
    threw = false;
    try { KeyStore().initialize_keys(); } catch (...) { threw = true; }
    CHECK(threw, "a partial key set is not silently overwritten");

    stop_server();
    std::error_code ec; fs::remove_all(ROOT, ec);
    std::cout << (failures ? "\nFAILURES: " : "\nAll checks passed. ") << failures << "\n";
    return failures ? 1 : 0;
}
