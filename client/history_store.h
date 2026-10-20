#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

struct sqlite3;

// The client's local database: conversations, message history, the outgoing queue, pending
// message requests and the send tokens this user has handed out.
//
// Everything sensitive (the signed records, i.e. the messages) is encrypted row by row with
// AES-256-GCM under a key derived from the identity (KeyStore::derive_local_key). Each row's
// identity is part of what is authenticated, so rows can't be swapped around or replayed into a
// different conversation. Columns used for lookup and ordering (times, ids, status) stay in the
// clear: that is the price of being able to search by them, and it leaks timing to anyone who can
// read the file, but not content.
//
// Thread-safe: one connection guarded by a mutex.
class HistoryStore {
public:
    using Bytes = std::vector<uint8_t>;

    // `history_key` must be 32 bytes. Throws std::runtime_error if the database can't be opened.
    HistoryStore(const std::filesystem::path& db_path, const Bytes& history_key);
    ~HistoryStore();
    HistoryStore(const HistoryStore&) = delete;
    HistoryStore& operator=(const HistoryStore&) = delete;

    // --- Conversations ---
    // One per contact (Direct) or per group. A direct conversation is a group of two: the other
    // person is its one member, so delivery tracking and membership work the same for both.
    enum Kind : int { Direct = 1, Group = 2 };
    // SettingUp: a group this user has joined but whose members' send tokens haven't all arrived.
    enum State : int { Active = 0, SettingUp = 1 };
    enum Mode : int { Saved = 1 };  // Private chats (timers) arrive with a later milestone
    static constexpr size_t MAX_OTHER_MEMBERS = 15;  // a group is at most 16 people including this user
    static constexpr size_t MAX_TITLE_BYTES = 64;

    struct Conversation {
        Bytes id;
        std::string contact_fp;  // Direct: the other person (lowercase hex). Group: empty.
        int64_t created_at = 0;
        int64_t last_activity = 0;
        bool send_delivery_receipts = true;
        bool send_read_receipts = true;
        int kind = Direct;
        int state = Active;
        std::string title;       // groups: the creator's suggestion; untrusted text
        std::string creator_fp;  // groups: who made it (lowercase hex); empty for direct
        int mode = Saved;
        int64_t timer_seconds = 0;
        Bytes previous_id;       // the conversation this one replaces (a changed group), or empty
        std::vector<std::string> members;  // everyone except this user, lowercase hex, in stored order
    };
    // Direct conversations. `ensure_conversation` returns the existing one for that contact if
    // there is one (whatever ID it has).
    Conversation ensure_conversation(const Bytes& id, const std::string& contact_fp, int64_t now);
    std::optional<Conversation> conversation_for(const std::string& contact_fp);  // the direct one only
    // Groups. Creates the conversation and its member list together. If a conversation with that
    // ID already exists it is returned unchanged, so a replayed creation record changes nothing.
    // `members` are everyone except this user (1 to MAX_OTHER_MEMBERS, each 64 lowercase hex
    // characters, no duplicates). Throws std::runtime_error for anything invalid.
    Conversation create_group(const Bytes& id, const std::string& title, const std::string& creator_fp, int mode,
                              int64_t timer_seconds, const Bytes& previous_id, const std::vector<std::string>& members,
                              int state, int64_t now);
    std::optional<Conversation> conversation(const Bytes& id);
    void set_conversation_state(const Bytes& id, int state);
    std::vector<Conversation> conversations();  // direct and group, most recent activity first
    void set_receipt_settings(const Bytes& conversation_id, bool delivery, bool read);

    // --- Messages ---
    // Outgoing status only goes up: Queued, Sent (the relay has it), Delivered, Read.
    // Incoming status is 0 (unread) or 1 (read).
    enum Status : int { Queued = 0, Sent = 1, Delivered = 2, Read = 3 };
    struct Message {
        int64_t row = 0;
        Bytes conversation_id;
        Bytes message_id;
        bool outgoing = false;
        int64_t sent_at = 0;
        int64_t received_at = 0;
        int status = 0;
        bool gap = false;  // the sender's record points at something we never received
        Bytes entry_hash;
        Bytes record;      // the signed record, decrypted
    };
    // False if a message with that ID is already stored in the conversation (a replay or duplicate).
    bool add_message(const Message& message);
    // The newest `limit` messages of a conversation, oldest first. Rows that no longer decrypt are skipped.
    std::vector<Message> messages(const Bytes& conversation_id, size_t limit);
    std::optional<Message> find_message(const Bytes& conversation_id, const Bytes& message_id);
    bool raise_status(const Bytes& conversation_id, const Bytes& message_id, int status);

    // Delivery of one of our outgoing messages, per recipient. Each member has their own state
    // (Queued, Sent, Delivered, Read); a member without a row is Queued. The message's overall
    // status is the lowest across all members of the conversation, so it never claims more than
    // is true for everyone, and it only ever goes up.
    struct Delivery {
        std::string member_fp;  // lowercase hex
        int status = 0;
    };
    // Raises one member's state (never lowers it) and then the message's overall status.
    // False if nothing changed, or if the message isn't one of our outgoing ones, or the
    // fingerprint isn't a member of its conversation (so a stranger's receipt counts for nothing).
    bool raise_delivery(const Bytes& conversation_id, const Bytes& message_id, const std::string& member_fp, int status);
    // Every member's state for a message, in member order.
    std::vector<Delivery> deliveries(const Bytes& conversation_id, const Bytes& message_id);
    bool has_entry(const Bytes& conversation_id, const Bytes& entry_hash);
    std::optional<Bytes> last_entry_hash(const Bytes& conversation_id, bool outgoing);
    size_t unread_count(const Bytes& conversation_id);
    std::vector<Bytes> mark_all_read(const Bytes& conversation_id);  // returns the IDs it just marked

    // The conversation one of our outgoing messages belongs to, found by its message ID.
    std::optional<Bytes> conversation_of_outgoing(const Bytes& message_id);

    // --- Pending group invitations ---
    // A group creation record from a contact waits here until the user accepts or declines it.
    // Messages that arrive for the group in the meantime are held with it, in order, and replayed
    // when the invitation is accepted. (The record itself is encrypted like every other message.)
    static constexpr size_t MAX_HELD_RECORDS = 200;
    struct GroupInvite {
        Bytes conversation_id;
        std::string creator_fp;  // lowercase hex
        int64_t received_at = 0;
        std::vector<Bytes> records;  // [0] is the creation record, then any held messages
    };
    // False if an invitation with that conversation ID is already waiting.
    bool add_group_invite(const Bytes& conversation_id, const std::string& creator_fp, const Bytes& creation_record, int64_t now);
    std::optional<GroupInvite> group_invite(const Bytes& conversation_id);
    std::vector<GroupInvite> group_invites();  // oldest first
    size_t group_invite_count();
    // Appends a record to an invitation's held messages. False if there is no such invitation or
    // it already holds MAX_HELD_RECORDS. Holding the same record twice keeps one copy (true).
    bool hold_for_invite(const Bytes& conversation_id, const Bytes& record);
    void delete_group_invite(const Bytes& conversation_id);

    // --- People a group's creator introduced (public, self-signed bundles) ---
    struct IntroducedMember {
        std::string fp;  // lowercase hex of the signing-key fingerprint
        Bytes bundle;
        int64_t issued_at = 0;
        std::string introduced_by;  // the first person who introduced them
        int64_t first_seen = 0;
    };
    // Keeps the newest bundle per person; who introduced them and when stay as first recorded.
    void save_introduced(const std::string& fp, const Bytes& bundle, int64_t issued_at, const std::string& introduced_by, int64_t now);
    std::optional<IntroducedMember> introduced(const std::string& fp);
    std::vector<IntroducedMember> introduced_members();
    // Forgets everyone not in `keep` (those no longer in any group or pending invitation).
    void delete_introduced_except(const std::set<std::string>& keep);

    // --- Chat archives (M4) ---
    // What this device holds about one chat's archive on the relay: where it is, the key its entries are
    // encrypted under, this device's own signing key for it, and how far this device has checked the
    // chain. The secrets are encrypted like everything else here.
    enum ArchiveRole : int { ArchiveCreator = 1, ArchiveMember = 2 };
    enum ArchiveState : int { ArchiveGranted = 0, ArchiveJoined = 1, ArchiveFailed = 2 };
    struct Archive {
        Bytes conversation_id;  // also the archive's ID on the relay
        std::string relay_address;
        Bytes relay_id;
        int role = ArchiveMember;
        int state = ArchiveGranted;
        Bytes archive_key;
        Bytes chat_public_key, chat_private_key;
        Bytes join_token;         // until the member has joined; then empty
        uint64_t head_number = 0;  // how far the chain has been checked here
        Bytes head_hash;           // empty before any entry
        int64_t created_at = 0;
        std::string note;          // why joining failed
    };
    // False if the conversation already has an archive.
    bool add_archive(const Archive& archive);
    std::optional<Archive> archive(const Bytes& conversation_id);
    std::vector<Archive> archives();  // oldest first
    std::vector<Archive> archives_in_state(int state);  // e.g. ArchiveGranted: waiting to join
    void set_archive_joined(const Bytes& conversation_id);  // and forgets the join token
    void set_archive_failed(const Bytes& conversation_id, const std::string& note);
    // Moves the checked head forward; never backwards.
    void set_archive_head(const Bytes& conversation_id, uint64_t number, const Bytes& hash);

    // --- People the user has verified ---
    // "I compared this person's fingerprint with them." It is about the person, not about how we
    // know them, so it holds whether they are a contact or only known from a group, and carries over
    // if one becomes the other.
    void set_verified(const std::string& fp, bool verified, int64_t now);
    bool is_verified(const std::string& fp);
    std::vector<std::string> verified_people();

    // --- Send tokens other group members gave us ---
    // A token lets us write to one member's mailbox, and is good for one group only. It is a bearer
    // secret, so it is stored encrypted like the messages. Saving again for the same group and
    // member replaces it.
    void save_member_token(const Bytes& conversation_id, const std::string& member_fp, const Bytes& token, int64_t now);
    std::optional<Bytes> member_token(const Bytes& conversation_id, const std::string& member_fp);

    // --- Outgoing queue: records waiting to be sealed and deposited ---
    struct OutboxItem {
        int64_t id = 0;
        std::string contact_fp;
        int kind = 0;  // 0 = message, 1 = receipt
        Bytes message_id;
        std::vector<Bytes> records;
        int64_t due_at = 0;
        int attempts = 0;
    };
    int64_t enqueue(const std::string& contact_fp, int kind, const Bytes& message_id,
                    const std::vector<Bytes>& records, int64_t due_at, int64_t now);
    std::vector<OutboxItem> due_items(int64_t now, size_t limit);
    void update_outbox_records(int64_t id, const std::vector<Bytes>& records);
    void outbox_failed(int64_t id, int64_t next_due);
    void outbox_done(int64_t id);
    size_t outbox_size();

    // --- Message requests: first messages from people who aren't contacts yet ---
    struct Request {
        int64_t id = 0;
        std::string sender_fp;
        Bytes bundle;  // their identity bundle (self-signed, public)
        int64_t received_at = 0;
        std::vector<Bytes> records;
    };
    void add_request(const std::string& sender_fp, const Bytes& bundle, const std::vector<Bytes>& records, int64_t now);
    std::vector<Request> requests();
    size_t request_count();
    void delete_requests(const std::string& sender_fp);

    // --- Send tokens this user handed out (only hashes; the relay holds the same) ---
    struct IssuedToken {
        Bytes hash;
        std::string label;
        int64_t created_at = 0;
        std::string bound_fp;  // who first used it ("" until someone does)
        bool revoked = false;
    };
    void add_issued_token(const Bytes& hash, const std::string& label, const std::string& bound_fp, int64_t now);
    std::optional<IssuedToken> find_issued_token(const Bytes& hash);
    std::vector<IssuedToken> issued_tokens();
    void bind_issued_token(const Bytes& hash, const std::string& fp);
    void mark_token_revoked(const Bytes& hash);

    // --- First-contact state ---
    bool bundle_sent(const std::string& contact_fp);
    void set_bundle_sent(const std::string& contact_fp);

private:
    void migrate_v1_to_v2(const std::filesystem::path& db_path);
    // Opens a stored invitation row; std::nullopt if it is damaged or sealed under another key.
    std::optional<GroupInvite> open_invite(const Bytes& conv_id, const std::string& creator_fp, int64_t received_at, const Bytes& sealed) const;
    Bytes seal(const Bytes& plaintext, const Bytes& aad) const;
    std::optional<Bytes> unseal(const Bytes& sealed, const Bytes& aad) const;

    sqlite3* db_ = nullptr;
    Bytes key_;
    mutable std::mutex mutex_;
};
