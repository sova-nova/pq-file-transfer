// PQ relay server: stores encrypted transfers and hands them to whoever
// presents the (unguessable) transfer ID. It never sees keys, filenames,
// sender identities or plaintext; only sizes and opaque ciphertext.

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <openssl/rand.h>

#include "protocol.h"
#include "relay_service.h"
#include "scope_exit.h"

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;

// --- Configuration ---

static constexpr uint16_t DEFAULT_PORT = 9000;
static constexpr int BACKLOG = 16;
static constexpr int MAX_CONNECTIONS = 64;
static constexpr int SOCKET_TIMEOUT_SECONDS = 120;
static constexpr auto TRANSFER_TTL = std::chrono::hours(24);
static constexpr auto CLEANUP_INTERVAL = std::chrono::minutes(5);
static constexpr uint64_t DEFAULT_QUOTA_GB = 50;
// How long a download request waits if another download of the same transfer is
// still in flight (e.g. a rejected attempt whose disconnect hasn't been noticed yet).
static constexpr auto BUSY_WAIT = std::chrono::seconds(10);

// --- Server state ---

struct StoredTransfer {
    FileHeader header;
    fs::path dir;
    Clock::time_point created;
    uint64_t reserved_bytes = 0;
    bool downloading = false;
};

static std::map<std::string, StoredTransfer> g_transfers;  // completed uploads only
static std::mutex g_mutex;
static std::condition_variable g_download_released;  // signalled when a download ends
static uint64_t g_reserved_bytes = 0;  // guarded by g_mutex
static uint64_t g_storage_quota = DEFAULT_QUOTA_GB * 1024 * 1024 * 1024;
static fs::path g_storage_dir;
static std::atomic<int> g_active_connections{0};

static std::unique_ptr<relay::RelayService> g_relay;  // protocol v3 (mailboxes); v2 file transfer is handled below

static std::mutex g_log_mutex;

static void log_line(const std::string& line) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    std::cout << line << std::endl;
}

// Transfer IDs are download credentials; only log a prefix.
static std::string short_id(const std::string& id) {
    return id.substr(0, 8) + "...";
}

// --- Helpers ---

static std::optional<std::string> generate_transfer_id() {
    uint8_t buf[TRANSFER_ID_BYTES];
    if (RAND_bytes(buf, sizeof(buf)) != 1) return std::nullopt;
    return bytes_to_hex(buf, sizeof(buf));
}

static void send_error(socket_t sock, const std::string& message) {
    send_text_message(sock, MessageType::ERROR_MSG, message);
}

static std::string chunk_filename(uint32_t index) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "chunk_%08u.bin", index);
    return buf;
}

static bool write_whole_file(const fs::path& path, const uint8_t* data, size_t len) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    if (len > 0) f.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(len));
    f.close();
    return !f.fail();
}

static std::optional<std::vector<uint8_t>> read_whole_file(const fs::path& path, uint64_t max_size) {
    std::error_code ec;
    auto size = fs::file_size(path, ec);
    if (ec || size > max_size) return std::nullopt;
    std::ifstream f(path, std::ios::binary);
    if (!f) return std::nullopt;
    std::vector<uint8_t> data(static_cast<size_t>(size));
    if (size > 0 && !f.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(size)))
        return std::nullopt;
    return data;
}

static void remove_dir_quietly(const fs::path& dir) {
    std::error_code ec;
    fs::remove_all(dir, ec);
}

// Bytes a transfer occupies on disk (ciphertext + tags + header), used for the quota.
static uint64_t storage_cost(const FileHeader& h, size_t header_bytes) {
    return h.file_size + static_cast<uint64_t>(h.total_chunks) * AEAD_TAG_SIZE + header_bytes;
}

// How long ago a transfer was uploaded, judged by its header file's modification
// time. Used on startup so that restarting the server doesn't give every stored
// transfer a fresh 24 hours.
static Clock::duration transfer_age_on_disk(const fs::path& header_file) {
    std::error_code ec;
    auto mtime = fs::last_write_time(header_file, ec);
    if (ec) return Clock::duration::zero();
    auto age = fs::file_time_type::clock::now() - mtime;
    if (age < decltype(age)::zero()) return Clock::duration::zero();
    return std::chrono::duration_cast<Clock::duration>(age);
}

// --- Upload ---

static void handle_upload(socket_t sock, const std::vector<uint8_t>& header_bytes) {
    auto header = deserialize_file_header(header_bytes.data(), header_bytes.size());
    if (!header) {
        send_error(sock, "Malformed file header (client and server versions may not match)");
        return;
    }
    std::string problem = validate_file_header(*header);
    if (!problem.empty()) {
        send_error(sock, problem);
        return;
    }

    // Reserve space up front so concurrent uploads can't overrun the quota.
    const uint64_t reserve = storage_cost(*header, header_bytes.size());
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_reserved_bytes + reserve > g_storage_quota) {
            send_error(sock, "Relay server storage is full, try again later");
            return;
        }
        g_reserved_bytes += reserve;
    }

    fs::path dir;
    auto cleanup = make_scope_exit([&] {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_reserved_bytes -= reserve;
        if (!dir.empty()) remove_dir_quietly(dir);
    });

    auto id = generate_transfer_id();
    if (!id) {
        send_error(sock, "Server could not generate a transfer ID");
        return;
    }

    std::error_code ec;
    fs::path candidate = g_storage_dir / *id;
    if (!fs::create_directory(candidate, ec) || ec) {
        send_error(sock, "Server storage error");
        return;
    }
    dir = candidate;

    if (!write_whole_file(dir / "header.bin", header_bytes.data(), header_bytes.size())) {
        send_error(sock, "Server storage error");
        return;
    }

    if (!send_text_message(sock, MessageType::ACK, *id)) return;
    log_line("Upload started: " + short_id(*id) + " (" + std::to_string(header->file_size) +
             " bytes, " + std::to_string(header->total_chunks) + " chunks)");

    std::vector<bool> received(header->total_chunks, false);
    uint32_t received_count = 0;

    while (true) {
        auto msg = recv_message(sock, MAX_CHUNK_MESSAGE);
        if (!msg) {
            log_line("Upload aborted (sender disconnected): " + short_id(*id));
            return;
        }
        if (msg->type == MessageType::UPLOAD_DONE) break;
        if (msg->type != MessageType::UPLOAD_CHUNK) {
            send_error(sock, "Unexpected message during upload");
            return;
        }

        auto chunk = deserialize_file_chunk(msg->payload.data(), msg->payload.size());
        if (!chunk) {
            send_error(sock, "Malformed chunk");
            return;
        }
        uint32_t idx = chunk->chunk_index;
        if (idx >= header->total_chunks || received[idx]) {
            send_error(sock, "Invalid or duplicate chunk index " + std::to_string(idx));
            return;
        }
        uint64_t expected = expected_chunk_plaintext_size(*header, idx) + AEAD_TAG_SIZE;
        if (chunk->data.size() != expected) {
            send_error(sock, "Chunk " + std::to_string(idx) + " has an unexpected size");
            return;
        }
        if (!write_whole_file(dir / chunk_filename(idx), chunk->data.data(), chunk->data.size())) {
            send_error(sock, "Server storage error");
            return;
        }
        received[idx] = true;
        received_count++;
    }

    if (received_count != header->total_chunks) {
        send_error(sock, "Upload incomplete: received " + std::to_string(received_count) +
                         " of " + std::to_string(header->total_chunks) + " chunks");
        return;
    }

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_transfers[*id] = StoredTransfer{*header, dir, Clock::now(), reserve, false};
    }
    cleanup.dismiss();

    send_text_message(sock, MessageType::ACK, "UPLOAD_COMPLETE");
    log_line("Upload complete: " + short_id(*id));
}

// --- Download ---

static void handle_download(socket_t sock, const std::vector<uint8_t>& payload) {
    std::string id(payload.begin(), payload.end());
    const std::string not_found = "Transfer not found (it may have expired or already been received)";
    if (!is_lower_hex(id, TRANSFER_ID_HEX_LEN)) {
        send_error(sock, not_found);
        return;
    }

    StoredTransfer transfer;
    bool found = false, busy = false;
    {
        std::unique_lock<std::mutex> lock(g_mutex);
        auto is_free = [&] {
            auto it = g_transfers.find(id);
            return it == g_transfers.end() || !it->second.downloading;
        };
        g_download_released.wait_for(lock, BUSY_WAIT, is_free);

        auto it = g_transfers.find(id);
        if (it != g_transfers.end()) {
            found = true;
            busy = it->second.downloading;
            if (!busy) {
                it->second.downloading = true;
                transfer = it->second;
            }
        }
    }
    if (!found) { send_error(sock, not_found); return; }
    if (busy)   { send_error(sock, "This transfer is already being downloaded"); return; }

    // If anything below fails, release the transfer so the receiver can retry.
    auto release = make_scope_exit([&] {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_transfers.find(id);
        if (it != g_transfers.end()) it->second.downloading = false;
        g_download_released.notify_all();
    });

    log_line("Download started: " + short_id(id));

    auto header_bytes = read_whole_file(transfer.dir / "header.bin", MAX_HEADER_MESSAGE);
    if (!header_bytes) {
        send_error(sock, "Server storage error");
        return;
    }
    if (!send_message(sock, MessageType::DOWNLOAD_HEADER, *header_bytes)) return;

    for (uint32_t i = 0; i < transfer.header.total_chunks; i++) {
        auto data = read_whole_file(transfer.dir / chunk_filename(i), MAX_CHUNK_SIZE + AEAD_TAG_SIZE);
        if (!data) {
            log_line("Chunk file missing for " + short_id(id) + ": " + std::to_string(i));
            send_error(sock, "Server storage error");
            return;
        }
        FileChunk chunk{i, std::move(*data)};
        if (!send_message(sock, MessageType::DOWNLOAD_CHUNK, serialize_file_chunk(chunk))) {
            log_line("Receiver disconnected: " + short_id(id));
            return;
        }
    }
    if (!send_message(sock, MessageType::DOWNLOAD_DONE, {})) return;

    // Only delete once the receiver confirms it decrypted and verified the file.
    // Someone who merely obtained the ID (but isn't the recipient) can't confirm
    // a valid transfer, so they can't make it disappear for the real recipient.
    auto confirm = recv_message(sock, MAX_CONTROL_MESSAGE);
    if (!confirm || confirm->type != MessageType::ACK) {
        log_line("Download not confirmed, keeping transfer: " + short_id(id));
        return;
    }

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_transfers.find(id);
        if (it != g_transfers.end()) {
            g_reserved_bytes -= it->second.reserved_bytes;
            g_transfers.erase(it);
        }
        g_download_released.notify_all();
    }
    release.dismiss();
    remove_dir_quietly(transfer.dir);
    log_line("Download complete, deleted: " + short_id(id));
}

// --- Connection handling ---

static void handle_client(socket_t sock, std::string peer_ip) {
    auto guard = make_scope_exit([sock] {
        close_socket(sock);
        g_active_connections--;
    });

    set_socket_timeouts(sock, SOCKET_TIMEOUT_SECONDS);
    disable_sigpipe(sock);

    try {
        auto first = recv_message(sock, MAX_HEADER_MESSAGE);
        if (!first) return;

        switch (first->type) {
            case MessageType::UPLOAD_REQUEST:
                handle_upload(sock, first->payload);
                break;
            case MessageType::DOWNLOAD_REQUEST:
                handle_download(sock, first->payload);
                break;
            case MessageType::RELAY_HELLO:
                // Protocol v3. Sessions are long-lived: the idle limit is the service's, not the socket's.
                g_relay->handle_session(sock, first->payload, peer_ip);
                break;
            default:
                send_error(sock, "Unexpected first message");
                break;
        }
    } catch (const std::exception& e) {
        log_line(std::string("Connection error: ") + e.what());
    }
}

// Deletes transfers older than TRANSFER_TTL that nobody is downloading.
static void cleanup_loop() {
    while (true) {
        std::this_thread::sleep_for(CLEANUP_INTERVAL);

        std::vector<fs::path> expired;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            auto now = Clock::now();
            for (auto it = g_transfers.begin(); it != g_transfers.end();) {
                if (!it->second.downloading && now - it->second.created > TRANSFER_TTL) {
                    g_reserved_bytes -= it->second.reserved_bytes;
                    expired.push_back(it->second.dir);
                    it = g_transfers.erase(it);
                } else {
                    ++it;
                }
            }
        }
        for (const auto& dir : expired) remove_dir_quietly(dir);
        if (!expired.empty()) log_line("Expired " + std::to_string(expired.size()) + " transfer(s)");
    }
}

// --- Storage setup ---

static fs::path default_storage_dir() {
#ifdef _WIN32
    if (const wchar_t* temp = _wgetenv(L"TEMP")) return fs::path(temp) / "pq-transfer";
    return fs::path("C:\\temp\\pq-transfer");
#else
    const char* tmp = std::getenv("TMPDIR");
    fs::path base = (tmp && *tmp) ? fs::path(tmp) : fs::path("/tmp");
    // Per-user name so another local user can't pre-create the directory.
    return base / ("pq-transfer-" + std::to_string(geteuid()));
#endif
}

static bool prepare_storage_dir(const fs::path& dir) {
    std::error_code ec;
    if (fs::is_symlink(fs::symlink_status(dir, ec))) {
        std::cerr << "Refusing to use storage directory that is a symlink: " << dir << std::endl;
        return false;
    }
    fs::create_directories(dir, ec);
    if (ec) {
        std::cerr << "Cannot create storage directory " << dir << ": " << ec.message() << std::endl;
        return false;
    }
#ifndef _WIN32
    struct stat st {};
    if (lstat(dir.c_str(), &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != geteuid()) {
        std::cerr << "Storage directory " << dir << " is not a directory owned by this user" << std::endl;
        return false;
    }
    if (chmod(dir.c_str(), 0700) != 0) {
        std::cerr << "Cannot restrict permissions on " << dir << std::endl;
        return false;
    }
#endif
    return true;
}

// Re-registers complete transfers left by a previous run and removes partial ones.
static void restore_transfers() {
    std::error_code ec;
    std::vector<fs::path> dirs;
    for (const auto& entry : fs::directory_iterator(g_storage_dir, ec)) {
        std::string name = entry.path().filename().string();
        if (entry.is_directory(ec) && is_lower_hex(name, TRANSFER_ID_HEX_LEN)) dirs.push_back(entry.path());
    }

    size_t restored = 0, removed = 0, expired = 0;
    for (const auto& dir : dirs) {
        std::string id = dir.filename().string();
        auto bytes = read_whole_file(dir / "header.bin", MAX_HEADER_MESSAGE);
        std::optional<FileHeader> header;
        if (bytes) header = deserialize_file_header(bytes->data(), bytes->size());

        bool complete = header && validate_file_header(*header).empty();
        for (uint32_t i = 0; complete && i < header->total_chunks; i++) {
            auto size = fs::file_size(dir / chunk_filename(i), ec);
            complete = !ec && size == expected_chunk_plaintext_size(*header, i) + AEAD_TAG_SIZE;
        }

        if (complete) {
            Clock::duration age = transfer_age_on_disk(dir / "header.bin");
            if (age > TRANSFER_TTL) {
                remove_dir_quietly(dir);
                expired++;
                continue;
            }
            uint64_t cost = storage_cost(*header, bytes->size());
            g_transfers[id] = StoredTransfer{*header, dir, Clock::now() - age, cost, false};
            g_reserved_bytes += cost;
            restored++;
        } else {
            remove_dir_quietly(dir);
            removed++;
        }
    }
    if (restored || removed || expired)
        std::cout << "Restored " << restored << " transfer(s), removed " << removed
                  << " incomplete and " << expired << " expired" << std::endl;
}

// --- Main ---

static void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [--port N] [--bind ADDR] [--storage DIR] [--quota-gb N]\n"
              << "  --port N       TCP port to listen on (default " << DEFAULT_PORT << ")\n"
              << "  --bind ADDR    IPv4 address to listen on (default 0.0.0.0, all interfaces).\n"
              << "                 Use your WireGuard address, e.g. 10.8.0.1, to accept tunnel traffic only\n"
              << "  --storage DIR  where everything is kept, including the relay's signing key in DIR/v3.\n"
              << "                 Always pass the same absolute path (default: temp dir, or $PQ_STORAGE_DIR)\n"
              << "  --quota-gb N   max total storage in GiB (default " << DEFAULT_QUOTA_GB << ")\n"
              << "\nMailbox relay (protocol v3). Its state lives in <storage>/v3, including the relay's\n"
              << "signing key: back that folder up.\n"
              << "  --create-invite             make a single-use invite, print it and exit\n"
              << "  --allow-new-identity        with --create-invite: allow creating the relay's identity if\n"
              << "                              this storage has none (normally a sign of the wrong --storage)\n"
              << "  --public-address HOST:PORT  put this address in the printed invite string\n"
              << "  --mailbox-quota-kib N       queued bytes allowed per mailbox (default 65536)\n"
              << "  --rate-limit N              deposits per minute per send token and per address (default 120)\n"
              << "  --sweep-seconds N           how often expired envelopes are removed (default 60)\n"
              << "  --max-archives N            chat archives the relay will hold (default 1000)\n"
              << "  --archive-quota-mib N       encrypted bytes allowed per chat archive (default 512)\n"
              << "  --keyring-max-kib N         largest keyring one mailbox may store (default 4096)\n"
              << "  --max-attachment-mib N      largest single attachment (default 1024)\n"
              << "  --attachment-quota-mib N    all of one mailbox's stored attachments together (default 4096)\n"
              << "  --attachment-max-days N     how long an attachment may be kept for (default 30)\n"
              << "\nMembers vouching for friends: anyone on the relay can make single-use invites from the app.\n"
              << "The relay records who vouched for whom.\n"
              << "  --member-invites N          unused invites one member may have at once (default 3; 0 turns\n"
              << "                              this off so only your own --create-invite invites exist)\n"
              << "  --member-invites-total N    most people one member may ever invite (default 10)\n"
              << "  --list-mailboxes            show every mailbox, who vouched for it and what is queued, and exit\n"
              << "  --remove-mailbox ID         remove a mailbox (an ID prefix of at least 8 characters from\n"
              << "                              --list-mailboxes) and exit; its owner can no longer sign in\n"
              << "  --with-invitees             with --remove-mailbox: also everyone it invited, and theirs\n";
}

// A unix time as "YYYY-MM-DD HH:MM" (UTC), without the platform's time functions.
static std::string format_time(int64_t t) {
    int64_t days = t / 86400, secs = t % 86400;
    if (secs < 0) { secs += 86400; days--; }
    // Civil date from a day count (Howard Hinnant's algorithm).
    days += 719468;
    const int64_t era = (days >= 0 ? days : days - 146096) / 146097;
    const int64_t doe = days - era * 146097;
    const int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const int64_t mp = (5 * doy + 2) / 153;
    const int64_t day = doy - (153 * mp + 2) / 5 + 1;
    const int64_t month = mp < 10 ? mp + 3 : mp - 9;
    const int64_t year = yoe + era * 400 + (month <= 2 ? 1 : 0);
    char buf[96];  // roomy enough that the compiler can see no field can overflow it
    std::snprintf(buf, sizeof(buf), "%04lld-%02lld-%02lld %02lld:%02lld", static_cast<long long>(year), static_cast<long long>(month),
                  static_cast<long long>(day), static_cast<long long>(secs / 3600), static_cast<long long>(secs % 3600 / 60));
    return buf;
}

static std::string short_mailbox(const std::vector<uint8_t>& id) {
    return bytes_to_hex(id.data(), id.size()).substr(0, 12);
}

int main(int argc, char* argv[]) {
    uint16_t port = DEFAULT_PORT;
    relay::RelayLimits limits;
    bool create_invite = false;
    std::string public_address;
    std::string bind_text = "0.0.0.0";
    in_addr bind_addr{};
    bind_addr.s_addr = htonl(INADDR_ANY);
    const char* env_dir = std::getenv("PQ_STORAGE_DIR");
    g_storage_dir = (env_dir && *env_dir) ? fs::path(env_dir) : default_storage_dir();
    bool storage_explicit = env_dir && *env_dir;
    bool allow_new_identity = false;
    bool list_mailboxes = false, with_invitees = false;
    std::string remove_prefix;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        bool has_value = i + 1 < argc;
        try {
            if (arg == "--port" && has_value) {
                unsigned long p = std::stoul(argv[++i]);
                if (p == 0 || p > 65535) throw std::out_of_range("port");
                port = static_cast<uint16_t>(p);
            } else if (arg == "--bind" && has_value) {
                bind_text = argv[++i];
                if (inet_pton(AF_INET, bind_text.c_str(), &bind_addr) != 1)
                    throw std::invalid_argument("bind");
            } else if (arg == "--create-invite") {
                create_invite = true;
            } else if (arg == "--allow-new-identity") {
                allow_new_identity = true;
            } else if (arg == "--list-mailboxes") {
                list_mailboxes = true;
            } else if (arg == "--remove-mailbox" && has_value) {
                remove_prefix = argv[++i];
            } else if (arg == "--with-invitees") {
                with_invitees = true;
            } else if (arg == "--max-archives" && has_value) {
                limits.max_archives = std::stoull(argv[++i]);
            } else if (arg == "--max-attachment-mib" && has_value) {
                limits.max_attachment_bytes = std::stoull(argv[++i]) * 1024 * 1024;
            } else if (arg == "--attachment-quota-mib" && has_value) {
                limits.attachment_quota_bytes = std::stoull(argv[++i]) * 1024 * 1024;
            } else if (arg == "--attachment-max-days" && has_value) {
                limits.attachment_max_seconds = static_cast<int64_t>(std::stoull(argv[++i])) * 86400;
            } else if (arg == "--keyring-max-kib" && has_value) {
                limits.keyring_max_bytes = std::stoull(argv[++i]) * 1024;
            } else if (arg == "--archive-quota-mib" && has_value) {
                limits.archive_quota_bytes = std::stoull(argv[++i]) * 1024 * 1024;
            } else if (arg == "--member-invites" && has_value) {
                limits.member_invites_outstanding = std::stoull(argv[++i]);
            } else if (arg == "--member-invites-total" && has_value) {
                limits.member_invites_total = std::stoull(argv[++i]);
            } else if (arg == "--public-address" && has_value) {
                public_address = argv[++i];
            } else if (arg == "--mailbox-quota-kib" && has_value) {
                limits.mailbox_quota_bytes = std::stoull(argv[++i]) * 1024;
            } else if (arg == "--rate-limit" && has_value) {
                limits.rate_limit_per_minute = std::stoi(argv[++i]);
            } else if (arg == "--sweep-seconds" && has_value) {
                limits.sweep_seconds = std::stoi(argv[++i]);
                if (limits.sweep_seconds < 1) throw std::out_of_range("sweep");
            } else if (arg == "--storage" && has_value) {
                g_storage_dir = fs::path(argv[++i]);
                storage_explicit = true;
            } else if (arg == "--quota-gb" && has_value) {
                g_storage_quota = std::stoull(argv[++i]) * 1024ull * 1024 * 1024;
            } else {
                print_usage(argv[0]);
                return arg == "--help" || arg == "-h" ? 0 : 1;
            }
        } catch (const std::exception&) {
            std::cerr << "Invalid value for " << arg << std::endl;
            return 1;
        }
    }

    if (platform_init() != 0) {
        std::cerr << "Failed to initialize network" << std::endl;
        return 1;
    }

    {   // Use (and show) an absolute path, so a relative --storage can't mean two different folders.
        std::error_code abs_ec;
        fs::path absolute = fs::absolute(g_storage_dir, abs_ec);
        if (!abs_ec) g_storage_dir = absolute;
    }

    if (!prepare_storage_dir(g_storage_dir)) return 1;

    const fs::path relay_dir = g_storage_dir / "v3";
    if (!storage_explicit) {
        std::cerr << "Warning: no --storage was given, so the temporary default is used:\n"
                  << "  " << g_storage_dir.string() << "\n"
                  << "The relay's signing key lives in " << relay_dir.string() << ". Every pq-server run that uses a\n"
                  << "different storage folder has a different relay identity, and an invite made by one is useless\n"
                  << "to another. Pass the same absolute --storage every time, and keep it out of /tmp.\n";
    }
    if ((list_mailboxes || !remove_prefix.empty()) && !relay::RelayService::identity_exists(relay_dir)) {
        std::cerr << "No relay has run in " << relay_dir.string() << ", so there is nothing to " << (list_mailboxes ? "list" : "remove")
                  << ". This is probably not the --storage your relay uses.\n";
        return 1;
    }
    if (create_invite && !allow_new_identity && !relay::RelayService::identity_exists(relay_dir)) {
        std::cerr << "No relay identity found in " << relay_dir.string() << ".\n"
                  << "This usually means --storage is not the folder your running relay uses. An invite made here\n"
                  << "would carry a brand-new relay identity that the running relay doesn't have, and clients would\n"
                  << "report that the relay's identity does not match the one you pinned.\n"
                  << "Use the same --storage (as the same user) as the running relay. If this relay has never been\n"
                  << "started, start it once, or add --allow-new-identity to create its identity now.\n";
        return 1;
    }

    try {
        g_relay = std::make_unique<relay::RelayService>(relay_dir, limits);
    } catch (const std::exception& e) {
        std::cerr << "Cannot start the mailbox relay: " << e.what() << std::endl;
        return 1;
    }
    g_relay->set_logger(log_line);
    if (g_relay->identity_created())
        std::cerr << "Created a new relay identity in " << relay_dir.string() << ".\n"
                  << "Back that folder up: if relay_private.key is lost, every client reports that the relay changed.\n";

    if (list_mailboxes) {
        auto members = g_relay->members();
        std::cout << "Mailboxes on this relay: " << members.size() << "\n";
        if (members.empty()) return 0;
        std::cout << "  ID            Created           Invited by    Queued\n";
        for (const auto& m : members) {
            std::string by = "operator";
            if (!m.invited_by.empty()) {
                by = short_mailbox(m.invited_by);
                bool known = false;
                for (const auto& other : members) known |= other.id == m.invited_by;
                if (!known) by += "*";
            }
            std::string by_padded = by + std::string(by.size() < 12 ? 12 - by.size() : 0, ' ');
            std::cout << "  " << short_mailbox(m.id) << "  " << format_time(m.created_at) << "  " << by_padded << "  " << m.envelopes << "\n";
        }
        std::cout << "(* = the mailbox that vouched for this one has been removed)\n";
        return 0;
    }
    if (!remove_prefix.empty()) {
        std::string prefix;
        for (char c : remove_prefix) prefix += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (prefix.size() < 8) { std::cerr << "Give at least 8 characters of the mailbox ID (see --list-mailboxes).\n"; return 1; }
        std::vector<uint8_t> found;
        size_t matches = 0;
        for (const auto& m : g_relay->members())
            if (bytes_to_hex(m.id.data(), m.id.size()).rfind(prefix, 0) == 0) { found = m.id; matches++; }
        if (matches != 1) {
            std::cerr << (matches ? "That prefix matches several mailboxes; give more characters.\n" : "No mailbox starts with that.\n");
            return 1;
        }
        size_t invited = 0;
        for (const auto& m : g_relay->members()) invited += m.invited_by == found ? 1 : 0;
        size_t removed = g_relay->remove_mailbox(found, with_invitees);
        std::cout << "Removed " << removed << " mailbox(es). Their owners can no longer sign in, and anything queued for them is gone.\n";
        if (!with_invitees && invited)
            std::cout << invited << " mailbox(es) it invited were left alone; add --with-invitees to remove those too.\n";
        return 0;
    }
    if (create_invite) {
        std::string code = g_relay->create_invite();
        std::string grouped;
        for (size_t i = 0; i < code.size(); i += 4) grouped += (i ? "-" : "") + code.substr(i, 4);
        std::cout << "Invite code:  " << grouped << "\n"
                  << "Relay ID:     " << g_relay->relay_id_hex() << "\n"
                  << "Relay state:  " << relay_dir.string() << "\n";
        if (!public_address.empty())
            std::cout << "Invite string (give this to the person; it works once and expires in 14 days):\n"
                      << "  pqft-relay://" << public_address << "/" << g_relay->relay_id_hex() << "/" << code << "\n";
        else
            std::cout << "Add --public-address HOST:PORT to also print a ready-to-paste invite string.\n";
        return 0;
    }
    g_relay->start_sweeper();
    restore_transfers();
    std::cout << "Storage directory: " << g_storage_dir.string() << std::endl;
    std::cout << "Mailbox relay ID: " << g_relay->relay_id_hex() << std::endl;

    socket_t server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == INVALID_SOCKET_VAL) {
        std::cerr << "Failed to create socket" << std::endl;
        platform_cleanup();
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr = bind_addr;
    addr.sin_port = htons(port);

    if (bind(server_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR_VAL) {
        std::cerr << "Failed to bind to " << bind_text << ":" << port << std::endl;
        close_socket(server_fd);
        platform_cleanup();
        return 1;
    }

    if (listen(server_fd, BACKLOG) == SOCKET_ERROR_VAL) {
        std::cerr << "Failed to listen" << std::endl;
        close_socket(server_fd);
        platform_cleanup();
        return 1;
    }

    std::thread(cleanup_loop).detach();

    std::cout << "PQ Relay Server listening on " << bind_text << ":" << port << std::endl;
    if (bind_text == "0.0.0.0")
        std::cout << "Note: listening on all interfaces. Use --bind to restrict it (e.g. to a WireGuard address)." << std::endl;
    std::cout << "Press Ctrl+C to stop." << std::endl;

    while (true) {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        socket_t client_fd = accept(server_fd, reinterpret_cast<sockaddr*>(&client_addr), &client_len);
        if (client_fd == INVALID_SOCKET_VAL) {
            // Avoid a hot loop if accept keeps failing (e.g. out of file descriptors).
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        char client_ip[INET_ADDRSTRLEN] = "?";
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

        if (g_active_connections.load() >= MAX_CONNECTIONS) {
            log_line(std::string("Too many connections, rejecting ") + client_ip);
            close_socket(client_fd);
            continue;
        }

        g_active_connections++;
        log_line(std::string("Connection from ") + client_ip + ":" + std::to_string(ntohs(client_addr.sin_port)));

        try {
            std::thread(handle_client, client_fd, std::string(client_ip)).detach();
        } catch (const std::exception&) {
            g_active_connections--;
            close_socket(client_fd);
        }
    }
}
