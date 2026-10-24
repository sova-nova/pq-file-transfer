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
    size_t max_tokens_per_mailbox = 1024;  // one per card handed out, per first message sent, and per other member of each group joined
    int rate_limit_per_minute = 120;                   // deposits per send token, and per client address
    int sweep_seconds = 60;                            // how often expired envelopes are removed
    int64_t invite_lifetime_seconds = 14ll * 24 * 3600;
    // Members vouching for friends: how many unused invites one mailbox may have at once (0 turns
    // this off, leaving only the operator's invites), and how many people it may ever invite.
    size_t member_invites_outstanding = 3;
    size_t member_invites_total = 10;
    // Chat archives (M4).
    size_t max_archives = 1000;                          // on the whole relay
    size_t archive_quota_bytes = 512ull * 1024 * 1024;   // of ciphertext, per archive
    int64_t archive_join_window_seconds = 30ll * 24 * 3600;  // members must register their keys within this
    size_t keyring_max_bytes = 4ull * 1024 * 1024;       // one mailbox's keyring (each chat's key alone is about 4 KB)
    // Prekeys (M6).
    uint32_t max_prekeys = 200;          // one-time prekeys one mailbox may have on the relay
    uint32_t prekey_takes_per_hour = 60; // prekeys one send token may take in an hour, so a contact can't drain the pool
    // Attachments (M5).
    uint64_t max_attachment_bytes = 1024ull * 1024 * 1024;     // one file
    uint64_t attachment_quota_bytes = 4096ull * 1024 * 1024;   // all of one mailbox's stored files together
    int64_t attachment_max_seconds = 30ll * 24 * 3600;         // how far ahead a file's expiry may be
    int64_t abandoned_upload_seconds = 3600;                   // an upload not finished by then is thrown away
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

    // Who is on this relay and who vouched for them (operator tools).
    std::vector<RelayStore::Member> members() { return store_->members(); }
    // Removes a mailbox (and, if `with_invitees`, everyone it invited, and theirs in turn) together
    // with their unused invites. Returns how many mailboxes were removed.
    size_t remove_mailbox(const Bytes& mailbox_id, bool with_invitees);

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
    std::filesystem::path file_path(const Bytes& file_id, const char* extension) const;
    void remove_file_bytes(const Bytes& file_id);
    std::filesystem::path files_dir_;
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
