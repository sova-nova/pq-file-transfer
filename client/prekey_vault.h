#pragma once

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <vector>

#include "prekey.h"

struct sqlite3;

// Where this device keeps the private halves of its prekeys (M6). A separate small database next to the chat history:
// - each private half is sealed under its own key (from the user's keys) and is never in the keyring or any backup;
// - a used one is overwritten and then deleted, with SQLite's secure deletion on and its journal kept in memory, so no copy
//   of it is left in the file or in a journal file (a solid-state disk may still keep old copies of its own: see HANDOFF.md);
// - if the file is damaged it is started afresh, and the app then replaces the pool on the relay.
class PrekeyVault {
public:
    using Bytes = std::vector<uint8_t>;
    PrekeyVault(const std::filesystem::path& path, const Bytes& key);
    ~PrekeyVault();
    PrekeyVault(const PrekeyVault&) = delete;
    PrekeyVault& operator=(const PrekeyVault&) = delete;

    Bytes generation();                          // the pool's generation; empty if there is none
    void start_generation(const Bytes& generation);  // forgets every prekey (securely) and starts a new pool
    void add(const prekey::Generated& g, int64_t now);  // kept with its public half until it has been uploaded
    std::vector<prekey::Prekey> not_uploaded();
    void mark_uploaded(const Bytes& id);
    std::optional<prekey::Secret> find(const Bytes& id);  // nothing if unknown, deleted, or not readable with this key
    bool erase(const Bytes& id);                          // overwrites, then deletes
    bool erase_one_time(const Bytes& id);                 // the same, but only if it is a one-time prekey
    std::optional<int64_t> current_last_resort_created();  // the newest last-resort prekey that isn't retired
    // A new last-resort prekey is on the relay: the older ones are retired, but kept for a while for envelopes still on their way.
    void retire_last_resort_except(const Bytes& keep_id, int64_t now);
    // Deletes retired last-resort prekeys from before `retired_before`, and one-time ones made before `unused_before` (by then
    // no envelope sealed to them can still be waiting). Returns how many went.
    size_t forget_old(int64_t retired_before, int64_t unused_before);
    struct Counts {
        size_t one_time = 0;     // one-time prekeys held (on the relay, or taken by a sender and not yet used)
        size_t last_resort = 0;  // current last-resort prekeys (1, or 0 before the first)
        size_t retired = 0;      // old last-resort prekeys kept for envelopes on their way
        size_t pending = 0;      // made but not yet uploaded
    };
    Counts counts();

private:
    void open_or_recreate(const std::filesystem::path& path);
    void exec(const char* sql);
    void secure_erase_where(const char* where, const std::vector<Bytes>& blobs, const std::vector<int64_t>& ints);
    Bytes seal(const Bytes& plain, const Bytes& id);
    std::optional<Bytes> unseal(const Bytes& sealed, const Bytes& id);
    sqlite3* db_ = nullptr;
    Bytes key_;
    std::mutex mutex_;
};
