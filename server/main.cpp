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
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <openssl/rand.h>

#include "protocol.h"
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

static void handle_client(socket_t sock) {
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

    size_t restored = 0, removed = 0;
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
            uint64_t cost = storage_cost(*header, bytes->size());
            g_transfers[id] = StoredTransfer{*header, dir, Clock::now(), cost, false};
            g_reserved_bytes += cost;
            restored++;
        } else {
            remove_dir_quietly(dir);
            removed++;
        }
    }
    if (restored || removed)
        std::cout << "Restored " << restored << " transfer(s), removed " << removed << " incomplete" << std::endl;
}

// --- Main ---

static void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [--port N] [--storage DIR] [--quota-gb N]\n"
              << "  --port N       TCP port to listen on (default " << DEFAULT_PORT << ")\n"
              << "  --storage DIR  where encrypted transfers are kept (default: temp dir, or $PQ_STORAGE_DIR)\n"
              << "  --quota-gb N   max total storage in GiB (default " << DEFAULT_QUOTA_GB << ")\n";
}

int main(int argc, char* argv[]) {
    uint16_t port = DEFAULT_PORT;
    const char* env_dir = std::getenv("PQ_STORAGE_DIR");
    g_storage_dir = (env_dir && *env_dir) ? fs::path(env_dir) : default_storage_dir();

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        bool has_value = i + 1 < argc;
        try {
            if (arg == "--port" && has_value) {
                unsigned long p = std::stoul(argv[++i]);
                if (p == 0 || p > 65535) throw std::out_of_range("port");
                port = static_cast<uint16_t>(p);
            } else if (arg == "--storage" && has_value) {
                g_storage_dir = fs::path(argv[++i]);
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

    if (!prepare_storage_dir(g_storage_dir)) return 1;
    restore_transfers();
    std::cout << "Storage directory: " << g_storage_dir.string() << std::endl;

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
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(server_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR_VAL) {
        std::cerr << "Failed to bind to port " << port << std::endl;
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

    std::cout << "PQ Relay Server listening on port " << port << std::endl;
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
            std::thread(handle_client, client_fd).detach();
        } catch (const std::exception&) {
            g_active_connections--;
            close_socket(client_fd);
        }
    }
}
