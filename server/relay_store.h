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

    // --- Prekeys: each mailbox's signed one-time keys (opaque here), with an hourly allowance per send token ---
    enum class PrekeyPutResult { Ok, WrongGeneration, TooMany, Duplicate, NoSuchMailbox };
    struct PrekeyEntryIn {
        Bytes id;
        bool last_resort = false;
        Bytes blob;
    };
    // Adds prekeys, or with `replace` throws away the mailbox's pool first and starts a new generation. Without `replace`
    // they are added only if the relay's generation is the owner's (or there is none yet). A new last-resort prekey replaces
    // the old one. All or nothing: a batch that would take the one-time pool over `max_one_time` is refused whole.
    PrekeyPutResult put_prekeys(const Bytes& mailbox_id, bool replace, const Bytes& generation, const std::vector<PrekeyEntryIn>& prekeys, int64_t now,
                                uint32_t max_one_time);
    enum class PrekeyTakeResult { Ok, Empty, RateLimited };
    // Hands out the oldest one-time prekey and removes it; if there are none, the last-resort one (kept). Counts against the
    // token's allowance for the hour, `per_hour`.
    PrekeyTakeResult take_prekey(const Bytes& mailbox_id, const Bytes& token_hash, int64_t now, uint32_t per_hour, Bytes& blob, bool& last_resort);
    struct PrekeyPoolStatus {
        uint32_t one_time = 0;
        bool last_resort = false;
        Bytes generation;
    };
    PrekeyPoolStatus prekey_status(const Bytes& mailbox_id);
    void sweep_prekey_takes(int64_t now);  // forgets allowances for hours that are over

    // --- Attachments: encrypted files, fetched once by each recipient. The bytes live on disk; this holds
    // who may fetch them and when they go. ---
    struct FileMeta {
        Bytes id;
        Bytes owner;  // the mailbox that uploaded it: needed to enforce quotas and to let only them withdraw it
        uint64_t total_size = 0;
        uint32_t chunk_size = 0;
        uint32_t chunk_count = 0;
        int64_t expires_at = 0;
        bool ready = false;  // fully uploaded
        uint32_t tokens_total = 0;
        uint32_t tokens_redeemed = 0;
    };
    enum class BeginFileResult { Ok, Exists, QuotaExceeded, NoSuchMailbox };
    // Records a file about to be uploaded (not yet fetchable). `quota_bytes` bounds what this mailbox may have stored.
    BeginFileResult begin_file(const Bytes& owner, const Bytes& file_id, uint64_t total_size, uint32_t chunk_size, uint32_t chunk_count,
                               int64_t expires_at, const std::vector<Bytes>& token_hashes, int64_t now, uint64_t quota_bytes);
    void finish_file(const Bytes& file_id);  // the last chunk has arrived: it can be fetched now
    std::optional<FileMeta> file(const Bytes& file_id);
    enum class TokenCheck { Ok, NoSuchFile, NotReady, Expired, BadToken, AlreadyRedeemed };
    TokenCheck check_file_token(const Bytes& file_id, const Bytes& token_hash, int64_t now);
    enum class RedeemResult { Ok, NoSuchFile, BadToken, AlreadyRedeemed };
    // Uses the token up. When that was the last one, the file's record is removed and `*all_redeemed` is true:
    // the caller then deletes the bytes.
    RedeemResult redeem_file_token(const Bytes& file_id, const Bytes& token_hash, bool* all_redeemed);
    // Removes a file's record. With a non-empty `owner`, only that mailbox's file. True if there was one.
    bool delete_file(const Bytes& file_id, const Bytes& owner);
    // Removes expired files and uploads abandoned before `abandoned_before`; returns their IDs so the caller can
    // delete the bytes.
    std::vector<Bytes> sweep_files(int64_t now, int64_t abandoned_before);
    std::vector<Bytes> all_file_ids();
    uint64_t owner_file_bytes(const Bytes& owner);

    // --- Keyring: one opaque encrypted blob per mailbox, replaced as a whole ---
    void put_keyring(const Bytes& mailbox_id, const Bytes& blob, int64_t now);
    std::optional<Bytes> get_keyring(const Bytes& mailbox_id);

    // --- Chat archives: one chat's encrypted, hash-chained log ---
    // The relay never records which mailbox created an archive, nor who its members are: a member is
    // only a public key registered with a one-time join token. It sees an ID, a member count, entry
    // sizes and when they arrive.
    struct ArchiveState {
        uint64_t number = 0;  // how many entries there are
        Bytes hash;           // the head: the genesis hash when there are none
    };
    struct ArchiveInfo {
        size_t member_count = 0;
        size_t joined = 0;
        bool registration_open = false;  // fewer keys than members, and the window hasn't passed
        ArchiveState head;
        uint64_t bytes = 0;
    };
    enum class CreateArchiveResult { Ok, Exists, LimitReached };
    // One join token hash per member (at least one). Registration closes when every member has joined or
    // at `closes_at`, whichever is first.
    CreateArchiveResult create_archive(const Bytes& archive_id, const std::vector<Bytes>& join_token_hashes, const Bytes& genesis_hash,
                                       int64_t now, int64_t closes_at, size_t max_archives);
    enum class JoinResult { Ok, NoSuchArchive, BadToken, Closed, KeyExists };
    // Registers a chat key and spends the token, atomically.
    JoinResult join_archive(const Bytes& archive_id, const Bytes& token_hash, const Bytes& key_hash, const Bytes& public_key, int64_t now);
    std::optional<Bytes> archive_member_key(const Bytes& archive_id, const Bytes& key_hash);
    std::optional<ArchiveInfo> archive_info(const Bytes& archive_id, int64_t now);
    size_t archive_count();
    enum class AppendResult { Ok, Stale, ArchiveFull, NoSuchArchive };
    // Adds an entry only if the head is still (expected_number, expected_hash). `new_hash` is the hash the
    // caller computed for the new entry from them. `head` receives the head after the call (the new one, or
    // the current one if the append was refused).
    AppendResult append_entry(const Bytes& archive_id, uint64_t expected_number, const Bytes& expected_hash, const Bytes& new_hash,
                              const Bytes& ciphertext, int64_t now, size_t quota_bytes, ArchiveState* head);
    struct StoredEntry {
        uint64_t number = 0;
        Bytes hash;
        Bytes ciphertext;  // empty for a tombstone
        bool redacted = false;
    };
    struct MemberKey {
        Bytes key_hash;
        Bytes public_key;
    };
    std::vector<MemberKey> archive_member_keys(const Bytes& archive_id);  // every registered key
    // Removes the whole archive: entries, keys and unspent tokens. False if there was none.
    bool delete_archive(const Bytes& archive_id);
    enum class RedactResult { Ok, NoSuchArchive, UnknownEntry };
    // Replaces the content of the named entries (by chain hash) with a tombstone that keeps the hash, so the chain
    // still holds. All or nothing: if any hash isn't an entry of this archive, nothing changes. Redacting an
    // entry that is already a tombstone is harmless.
    RedactResult redact_entries(const Bytes& archive_id, const std::vector<Bytes>& entry_hashes);
    // Up to `limit` entries numbered from_number onwards, in order.
    std::vector<StoredEntry> fetch_entries(const Bytes& archive_id, uint64_t from_number, size_t limit);

    struct Swept {
        size_t envelopes = 0;
        size_t invites = 0;
        size_t archives = 0;  // never joined by anyone before their registration window closed
    };
    Swept sweep(int64_t now);  // removes expired envelopes and invites

private:
    sqlite3* db_ = nullptr;
    std::mutex mutex_;
};

}  // namespace relay
