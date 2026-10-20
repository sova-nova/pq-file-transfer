// Setup safety for the mailbox relay. POSIX only.
// Usage: test_relay_setup /path/to/pq-server
//
// The mistake this guards against: running `pq-server --create-invite` with a different storage
// folder than the running relay uses. That used to create a second, brand-new relay identity
// without a word, and the invite then carried an ID the running relay didn't have, so clients
// reported "does not match the one you pinned".
#include "relay_service.h"

#include <cstdio>
#include <filesystem>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>

#include <sys/wait.h>
#include <unistd.h>

namespace fs = std::filesystem;

static int failures = 0;
#define CHECK(c, msg)                                                  \
    do {                                                               \
        if (c) std::cout << "  PASS " << (msg) << "\n";                \
        else { std::cout << "  FAIL " << (msg) << "\n"; failures++; } \
    } while (0)

static bool has(const std::string& s, const std::string& needle) { return s.find(needle) != std::string::npos; }

static std::string SERVER_BIN;
static fs::path ROOT;

// True if fn throws a std::runtime_error whose message contains `needle`.
static bool throws_with(const std::function<void()>& fn, const std::string& needle, std::string* what = nullptr) {
    try {
        fn();
    } catch (const std::runtime_error& e) {
        if (what) *what = e.what();
        return has(e.what(), needle);
    } catch (...) {
    }
    return false;
}

struct Run {
    int code = -1;
    std::string out;  // stdout and stderr together
};

static Run run(const std::string& shell_command) {
    Run r;
    FILE* p = popen((shell_command + " 2>&1").c_str(), "r");
    if (!p) return r;
    char buf[512];
    while (fgets(buf, sizeof(buf), p)) r.out += buf;
    int status = pclose(p);
    r.code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    return r;
}

static std::string quote(const std::string& s) { return "\"" + s + "\""; }  // test paths never contain quotes

// The text after `label` on its line, without surrounding blanks. "" if the label isn't there.
static std::string line_value(const std::string& out, const std::string& label) {
    size_t at = out.find(label);
    if (at == std::string::npos) return "";
    size_t start = at + label.size();
    size_t end = out.find('\n', start);
    std::string v = out.substr(start, end == std::string::npos ? std::string::npos : end - start);
    size_t first = v.find_first_not_of(" \t\r");
    size_t last = v.find_last_not_of(" \t\r");
    return first == std::string::npos ? "" : v.substr(first, last - first + 1);
}

// --- RelayService itself ---

static void test_identity_helpers() {
    std::cout << "The relay says when it creates a new identity\n";
    relay::RelayLimits limits;
    fs::path dir = ROOT / "unit" / "v3";
    CHECK(!relay::RelayService::identity_exists(dir), "an empty location has no identity");

    relay::Bytes first_id;
    {
        relay::RelayService first(dir, limits);
        CHECK(first.identity_created(), "the first start reports that it created an identity");
        first_id = first.relay_id();
        CHECK(first_id.size() == 32, "...a 32-byte relay ID");
    }
    CHECK(relay::RelayService::identity_exists(dir), "afterwards the identity exists");
    {
        relay::RelayService again(dir, limits);
        CHECK(!again.identity_created() && again.relay_id() == first_id, "the next start reports nothing new and keeps the same ID");
    }

    fs::path half = ROOT / "half" / "v3";
    { relay::RelayService seed(half, limits); }
    fs::remove(half / "relay_public.key");
    CHECK(!relay::RelayService::identity_exists(half), "with only one key file the identity does not count as existing");
    CHECK(throws_with([&] { relay::RelayService broken(half, limits); }, "Only one of the relay's key files"),
          "and starting refuses instead of generating a new identity");
}

static void test_owner_check() {
    std::cout << "A folder that belongs to another user is explained, not left to fail oddly\n";
    fs::path dir = ROOT / "owner";
    fs::create_directories(dir);
    const unsigned long me = relay::RelayService::current_uid();

    CHECK(!throws_with([&] { relay::RelayService::check_owner(dir, "The folder", me); }, ""), "a folder owned by the current user passes");
    std::string what;
    bool threw = throws_with([&] { relay::RelayService::check_owner(dir, "The relay's state folder", me + 1); }, "belongs to user id", &what);
    CHECK(threw, "a folder owned by someone else is refused: " + what);
    CHECK(has(what, "The relay's state folder") && has(what, dir.string()), "the message names what and where");
    CHECK(has(what, "chown") && has(what, "sudo -u"), "and says how to fix it");
    bool missing_ok = true;
    try { relay::RelayService::check_owner(dir / "does-not-exist", "x", me + 1); } catch (...) { missing_ok = false; }
    CHECK(missing_ok, "a path that doesn't exist yet is fine (it will be created by us)");
}

// --- The pq-server command line ---

static void test_command_line() {
    const std::string bin = quote(SERVER_BIN);

    std::cout << "--create-invite refuses to invent a relay identity\n";
    fs::path fresh = ROOT / "cli-fresh";
    Run refused = run(bin + " --storage " + quote(fresh.string()) + " --create-invite --public-address 127.0.0.1:9000");
    CHECK(refused.code != 0, "with no relay identity in that storage it fails");
    CHECK(has(refused.out, "No relay identity found") && has(refused.out, (fresh / "v3").string()), "...says so and names the folder it looked in: " + refused.out.substr(0, 90));
    CHECK(has(refused.out, "--allow-new-identity") && has(refused.out, "does not match the one you pinned"), "...explains the likely mistake and the override");
    CHECK(!has(refused.out, "pqft-relay://"), "...and prints no invite");
    CHECK(!fs::exists(fresh / "v3" / "relay_private.key"), "...and does not leave a new key behind");

    std::cout << "...unless a new identity is asked for\n";
    Run created = run(bin + " --storage " + quote(fresh.string()) + " --create-invite --allow-new-identity --public-address 127.0.0.1:9000");
    CHECK(created.code == 0 && has(created.out, "pqft-relay://"), "with --allow-new-identity it makes the identity and the invite");
    CHECK(has(created.out, "Created a new relay identity"), "and says that it created a new identity");
    std::string created_id = line_value(created.out, "Relay ID:");
    CHECK(created_id.size() == 64, "it prints the relay ID");
    CHECK(line_value(created.out, "Relay state:") == (fresh / "v3").string(), "it prints which folder the identity lives in");
    CHECK(!has(created.out, "no --storage was given"), "an explicit --storage gets no default-location warning");

    std::cout << "Once the identity exists, invites come from the same one\n";
    Run again = run(bin + " --storage " + quote(fresh.string()) + " --create-invite --public-address 127.0.0.1:9000");
    CHECK(again.code == 0 && has(again.out, "pqft-relay://"), "no override is needed any more");
    CHECK(line_value(again.out, "Relay ID:") == created_id, "it is the same relay ID");
    CHECK(!has(again.out, "Created a new relay identity"), "and it does not claim to have created anything");

    std::cout << "A relative --storage is shown (and used) as an absolute path\n";
    fs::path rel_base = ROOT / "cli-rel";
    fs::create_directories(rel_base);
    Run rel = run("cd " + quote(rel_base.string()) + " && " + bin + " --storage data --create-invite --allow-new-identity --public-address 127.0.0.1:9000");
    CHECK(rel.code == 0, "a relative path works");
    std::string shown = line_value(rel.out, "Relay state:");
    CHECK(!shown.empty() && shown[0] == '/' && has(shown, "cli-rel/data/v3"), "the folder is printed as an absolute path: " + shown);

    std::cout << "No --storage at all is called out\n";
    fs::path tmp = ROOT / "cli-tmp";
    fs::create_directories(tmp);
    Run dflt = run("env -u PQ_STORAGE_DIR TMPDIR=" + quote(tmp.string()) + " " + bin + " --create-invite --allow-new-identity --public-address 127.0.0.1:9000");
    CHECK(dflt.code == 0 && has(dflt.out, "no --storage was given"), "a warning says the temporary default is being used");
    CHECK(has(dflt.out, tmp.string()), "and shows where");
    Run via_env = run("PQ_STORAGE_DIR=" + quote((ROOT / "cli-env").string()) + " " + bin + " --create-invite --allow-new-identity --public-address 127.0.0.1:9000");
    CHECK(via_env.code == 0 && !has(via_env.out, "no --storage was given"), "PQ_STORAGE_DIR counts as choosing a location");
}

int main(int argc, char** argv) {
    if (argc < 2) { std::cerr << "usage: test_relay_setup /path/to/pq-server\n"; return 2; }
    SERVER_BIN = fs::absolute(argv[1]).string();  // some checks run the server from another directory
    ROOT = fs::temp_directory_path() / ("pqft-relay-setup-" + std::to_string(getpid()));
    fs::remove_all(ROOT);
    fs::create_directories(ROOT);

    test_identity_helpers();
    test_owner_check();
    test_command_line();

    std::error_code ec;
    fs::remove_all(ROOT, ec);
    std::cout << (failures ? "\nFAILURES: " : "\nAll checks passed. ") << failures << "\n";
    return failures ? 1 : 0;
}
