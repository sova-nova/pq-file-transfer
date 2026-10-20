#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "platform.h"
#include "relay_store.h"

namespace relay {

struct RelayLimits {
    size_t mailbox_quota_bytes = 64ull * 1024 * 1024;  // queued envelopes per mailbox
    size_t max_mailboxes = 1000;
    size_t max_tokens_per_mailbox = 256;   // one per card handed out, and one per first message sent
    int rate_limit_per_minute = 120;                   // deposits per send token, and per client address
    int sweep_seconds = 60;                            // how often expired envelopes are removed
    int64_t invite_lifetime_seconds = 14ll * 24 * 3600;
    int idle_timeout_seconds = 180;                    // clients ping every minute or so
    int poll_millis = 250;                             // how often a connected owner is checked for news
};

// The v3 mailbox relay: its identity key, invites, sessions and expiry. It sees only mailbox
// IDs, send token hashes and sealed envelopes, never keys of identities, names or content.
class RelayService {
public:
    // Creates (or opens) the relay state under data_dir. The relay's signing key is generated
    // on first use and kept there; losing it makes every client report "relay changed".
    // Throws std::runtime_error if the state can't be created.
    RelayService(const std::filesystem::path& data_dir, const RelayLimits& limits);
    ~RelayService();
    RelayService(const RelayService&) = delete;
    RelayService& operator=(const RelayService&) = delete;

    const Bytes& relay_id() const { return relay_id_; }  // SHA-256 of the relay's public key
    std::string relay_id_hex() const;

    // True if this run generated a new signing key because the storage had none. A wrong
    // storage folder looks exactly like a first start, so callers should say so out loud.
    bool identity_created() const { return identity_created_; }

    // Whether data_dir already holds a relay identity (both key files).
    static bool identity_exists(const std::filesystem::path& data_dir);

    // POSIX: throws a plain-language error if `path` exists and is owned by a user other than
    // `expected_uid`. Does nothing if it doesn't exist yet, and always on Windows.
    static void check_owner(const std::filesystem::path& path, const std::string& what, unsigned long expected_uid);
    // The user ID the relay runs as (0 on Windows, where nothing is checked).
    static unsigned long current_uid();

    void set_logger(std::function<void(const std::string&)> logger) { log_ = std::move(logger); }

    // Makes a single-use invite and returns it as 32 lowercase hex characters.
    std::string create_invite();

    // Runs one client session to completion. `hello_payload` is the already-received first
    // message. Returns when the client disconnects or breaks the protocol.
    void handle_session(socket_t sock, const Bytes& hello_payload, const std::string& peer_ip);

    // Removes expired envelopes and invites once; returns how many envelopes went.
    size_t sweep_once();
    void start_sweeper();
    void stop_sweeper();

private:
    // A fixed one-minute window counter per key.
    class RateLimiter {
    public:
        bool allow(const std::string& key, int limit, int64_t now);
        void prune(int64_t now);

    private:
        struct Window { int64_t start = 0; int count = 0; };
        std::map<std::string, Window> windows_;
        std::mutex mutex_;
    };

    void load_or_create_identity(const std::filesystem::path& data_dir);
    void log(const std::string& line) const { if (log_) log_(line); }
    bool push_pending(socket_t sock, const Bytes& mailbox, int64_t& last_seq);

    void install_owner(const Bytes& mailbox, const std::shared_ptr<std::atomic<bool>>& kick);
    void release_owner(const Bytes& mailbox, const std::shared_ptr<std::atomic<bool>>& kick);

    RelayLimits limits_;
    std::unique_ptr<RelayStore> store_;
    Bytes public_key_;
    Bytes private_key_;
    Bytes relay_id_;
    bool identity_created_ = false;
    RateLimiter rate_;
    std::function<void(const std::string&)> log_;

    std::mutex owners_mutex_;
    std::map<std::string, std::shared_ptr<std::atomic<bool>>> owners_;  // mailbox -> "you were replaced" flag

    std::thread sweeper_;
    std::atomic<bool> stop_sweeper_{false};
};

}  // namespace relay
