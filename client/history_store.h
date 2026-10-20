#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
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
    Bytes seal(const Bytes& plaintext, const Bytes& aad) const;
    std::optional<Bytes> unseal(const Bytes& sealed, const Bytes& aad) const;

    sqlite3* db_ = nullptr;
    Bytes key_;
    mutable std::mutex mutex_;
};
