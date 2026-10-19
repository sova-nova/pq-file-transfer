#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <vector>

struct sqlite3;

namespace relay {

using Bytes = std::vector<uint8_t>;

// The relay's persistent state: invites, mailboxes, send tokens and queued envelopes, in one
// SQLite database. Every method that depends on the time takes it as a parameter (unix
// seconds), so expiry can be tested with a controlled clock. Thread-safe: one connection,
// guarded by a mutex. Methods throw std::runtime_error on database failures.
class RelayStore {
public:
    explicit RelayStore(const std::filesystem::path& db_path);
    ~RelayStore();
    RelayStore(const RelayStore&) = delete;
    RelayStore& operator=(const RelayStore&) = delete;

    // --- Invites: single-use permission to create a mailbox (only the hash is stored) ---
    void add_invite(const Bytes& invite_hash, int64_t expires_at);

    // --- Mailboxes ---
    enum class RegisterResult { Ok, BadInvite, MailboxExists, LimitReached };
    // Creates the mailbox with its first send token and consumes the invite, atomically.
    // Nothing changes unless every step succeeds, so a failed attempt never burns an invite.
    RegisterResult register_mailbox(const Bytes& invite_hash, const Bytes& mailbox_id,
                                    const Bytes& access_public_key, const Bytes& token_hash,
                                    int64_t now, size_t max_mailboxes);
    std::optional<Bytes> access_key(const Bytes& mailbox_id);
    size_t mailbox_count();

    // --- Send tokens (only hashes are stored) ---
    bool token_valid(const Bytes& mailbox_id, const Bytes& token_hash);
    enum class TokenResult { Ok, NoSuchMailbox, LimitReached };
    TokenResult add_token(const Bytes& mailbox_id, const Bytes& token_hash, int64_t now, size_t max_tokens);
    bool revoke_token(const Bytes& mailbox_id, const Bytes& token_hash);  // true if one was removed

    // --- Envelopes ---
    enum class DepositResult { Ok, MailboxFull };
    // Refuses if the mailbox's unexpired envelopes plus this one would exceed quota_bytes.
    DepositResult deposit(const Bytes& mailbox_id, const Bytes& envelope_id, const Bytes& envelope,
                          int64_t now, uint32_t ttl_seconds, size_t quota_bytes);

    struct Stored {
        int64_t seq = 0;  // arrival order within the relay; only used to page through a mailbox
        Bytes id;
        int64_t deposited_at = 0;
        Bytes envelope;
    };
    // Unexpired envelopes of one mailbox with seq greater than `after_seq`, oldest first.
    std::vector<Stored> fetch(const Bytes& mailbox_id, int64_t after_seq, int64_t now, size_t limit);
    // Deletes the named envelopes, but only from this mailbox. Returns how many were deleted.
    size_t ack(const Bytes& mailbox_id, const std::vector<Bytes>& envelope_ids);
    size_t envelope_count(const Bytes& mailbox_id);

    struct Swept {
        size_t envelopes = 0;
        size_t invites = 0;
    };
    Swept sweep(int64_t now);  // removes expired envelopes and invites

private:
    sqlite3* db_ = nullptr;
    std::mutex mutex_;
};

}  // namespace relay
