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
    void add_invite(const Bytes& invite_hash, int64_t expires_at);  // made by the operator

    // An invite a member vouches for. The relay remembers who made it, and so who each new
    // mailbox was invited by.
    enum class IssueResult { Ok, NoSuchMailbox, TooManyOutstanding, TooManyIssued };
    // `max_outstanding`: unused, unexpired invites this member may have at once. `max_total`: all the
    // people they may ever invite (used plus outstanding).
    IssueResult add_member_invite(const Bytes& issuer_mailbox, const Bytes& invite_hash, int64_t now, int64_t expires_at,
                                  size_t max_outstanding, size_t max_total);

    struct UnusedInvite {
        Bytes hash;
        int64_t expires_at = 0;
    };
    struct JoinedMember {
        Bytes mailbox_id;
        int64_t joined_at = 0;
    };
    // This member's unused, unexpired invites (soonest to expire first) and the people who used theirs.
    std::vector<UnusedInvite> unused_invites(const Bytes& issuer_mailbox, int64_t now);
    std::vector<JoinedMember> joined_through(const Bytes& issuer_mailbox);
    // Cancels one of this member's own unused invites. False if it isn't theirs, or isn't there.
    bool cancel_member_invite(const Bytes& issuer_mailbox, const Bytes& invite_hash);

    struct Member {
        Bytes id;
        int64_t created_at = 0;
        Bytes invited_by;      // the mailbox that vouched for them; empty for an operator invite
        size_t envelopes = 0;  // queued now
    };
    std::vector<Member> members();  // oldest first
    // Removes a mailbox with its tokens, its queued envelopes and the unused invites it made.
    // True if it existed. (Mailboxes it invited stay; see RelayService::remove_mailbox.)
    bool delete_mailbox(const Bytes& mailbox_id);

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
    // `token_hash` records which send token was used, so the owner can later tell which card a
    // deposit came through.
    DepositResult deposit(const Bytes& mailbox_id, const Bytes& envelope_id, const Bytes& envelope,
                          const Bytes& token_hash, int64_t now, uint32_t ttl_seconds, size_t quota_bytes);

    struct Stored {
        int64_t seq = 0;  // arrival order within the relay; only used to page through a mailbox
        Bytes id;
        int64_t deposited_at = 0;
        Bytes token_hash;  // 32 bytes; all zero for envelopes stored before this was recorded
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
