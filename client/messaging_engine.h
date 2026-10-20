#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "archive.h"
#include "envelope.h"
#include "history_store.h"
#include "identity_bundle.h"
#include "key_store.h"
#include "message_record.h"
#include "relay_client.h"
#include "sharing.h"

// One-to-one and group Saved chats over a mailbox relay.
//
// The engine owns this user's side of the conversation machinery: it keeps one connection to the
// relay for receiving, turns what arrives into verified messages in the encrypted history, queues
// what the user writes and deposits it (retrying when the relay or the other person's mailbox is
// unreachable), handles first contact and message requests, and sends and applies receipts.
//
// Threading: call pump() in a loop from ONE worker thread. Every other method may be called from
// any other thread (typically the UI thread); none of them touch the network except setup(),
// make_card() and revoke_token(), which open their own short connections and block until done.
//
// The keys must be unlocked when the engine is constructed; their private halves are held in
// memory until it is destroyed.
class MessagingEngine {
public:
    struct Options {
        int receipt_delay_max_seconds = 5;      // "delivered" receipts wait a random moment, to blur timing
        int reconnect_min_seconds = 2;
        int reconnect_max_seconds = 60;
        int ping_seconds = 60;
        int connect_timeout_seconds = 8;
        int retry_base_seconds = 5;             // a failed send is retried after this, then 2x, 4x... up to 10 minutes
        uint32_t envelope_ttl_seconds = 30u * 24 * 3600;  // how long the relay may hold an undelivered envelope
    };

    // Throws std::runtime_error if the keys are locked or the history can't be opened.
    MessagingEngine(KeyStore& keys, const std::filesystem::path& history_path, const Options& options);
    MessagingEngine(KeyStore& keys, const std::filesystem::path& history_path)
        : MessagingEngine(keys, history_path, Options()) {}
    ~MessagingEngine();
    MessagingEngine(const MessagingEngine&) = delete;
    MessagingEngine& operator=(const MessagingEngine&) = delete;

    // --- Setting up ---
    bool is_set_up() const;
    // Registers a mailbox with the relay named in the invite (whose ID is pinned from then on).
    bool setup(const RelayInvite& invite, std::string& error);

    // Asks the relay for one single-use invite to give a friend, as a ready-to-paste string. The relay
    // limits how many a member may make, and remembers that this mailbox vouched for whoever uses it.
    // The string names the relay by the address this app uses; a friend who reaches the relay another
    // way needs that part changed. Talks to the relay, so call it from the UI thread only when that's fine.
    bool create_relay_invite(std::string& invite, std::string& error);

    // What this member has done with their invites on the relay. The relay doesn't keep the invites
    // themselves, so an unused one is identified by `id` (a hash), and a joined person only by when
    // they joined: you know who you gave each invite to, the relay doesn't.
    struct RelayInviteStatus {
        size_t max_unused = 0;  // unused invites allowed at once
        size_t max_total = 0;   // people you may invite in all
        struct Unused {
            std::string id;     // lowercase hex of the invite's hash
            int64_t expires_at = 0;
        };
        struct Joined {
            std::string mailbox;  // a short form of the new mailbox's ID, for telling them apart
            int64_t joined_at = 0;
        };
        std::vector<Unused> unused;  // soonest to expire first
        std::vector<Joined> joined;  // oldest first
    };
    bool relay_invite_status(RelayInviteStatus& status, std::string& error);
    // Cancels one unused invite (by `id` from relay_invite_status), so the friend can no longer use it.
    bool cancel_relay_invite(const std::string& id, std::string& error);
    // Shown in the identity bundles this user hands out. Optional.
    void set_display_name(const std::string& name);

    // --- Contact cards ---
    // Makes a card for one person: a fresh send token is registered with the relay and put in the
    // card, so it can be revoked later without affecting anyone else. `label` is for the user's
    // own list ("for Bob"). Needs the relay.
    bool make_card(const std::string& label, std::string& card, std::string& error);

    struct IssuedToken {
        std::vector<uint8_t> hash;
        std::string label;
        int64_t created_at = 0;
        std::string used_by;  // fingerprint of whoever used it first; "" if nobody yet
        bool revoked = false;
    };
    std::vector<IssuedToken> issued_tokens();
    bool revoke_token(const std::vector<uint8_t>& hash, std::string& error);  // needs the relay
    // Revokes every token that person has used or been given: the card you made for them and any
    // token sent along with a first message. Returns how many; -1 (with a reason) on failure.
    int revoke_tokens_for(const std::string& contact_fp, std::string& error);

    // --- Conversations ---
    struct ChatSummary {
        std::string contact_name;
        std::string contact_fp;  // lowercase hex
        size_t unread = 0;
        int64_t last_activity = 0;
        bool can_send = false;
        bool verified = false;           // you compared their fingerprint with them
        std::string cannot_send_reason;  // why not, in words
    };
    std::vector<ChatSummary> chats();

    // --- Trust ---
    // Marks someone (a contact, or a person known from a group) as verified: you compared their
    // fingerprint with them yourself. Accepting a message request does this too, because the app
    // asks you to check the fingerprint first. False if we don't know that person.
    bool set_verified(const std::string& fp, bool verified);
    bool is_verified(const std::string& fp);

    struct ChatMessage {
        int64_t row = 0;
        bool outgoing = false;
        int64_t sent_at = 0;
        std::string text;
        int status = 0;   // outgoing: 0 queued, 1 sent, 2 delivered, 3 read. Incoming: 0 unread, 1 read.
        bool gap = false; // the sender's record points at a message we never got
    };
    std::vector<ChatMessage> messages(const std::string& contact_fp, size_t limit = 300);

    // Queues a message; it is sent by pump(). False (with a reason) if it can't be sent.
    bool send_text(const std::string& contact_fp, const std::string& text, std::string& error);
    // Marks everything in the conversation read, and queues a read receipt if those are on.
    void mark_read(const std::string& contact_fp);
    void set_receipts(const std::string& contact_fp, bool delivery, bool read);
    bool receipts_enabled(const std::string& contact_fp, bool* delivery, bool* read);

    // --- Message requests: first messages from people who aren't contacts ---
    struct Request {
        std::string sender_fp;
        std::string display_name;  // their suggestion; untrusted text
        int64_t received_at = 0;
        size_t message_count = 0;
        std::string first_text;
    };
    std::vector<Request> requests();
    // Adds the sender as a contact (marked verified) and delivers what they sent. The caller has
    // already checked the fingerprint with the user.
    bool accept_request(const std::string& sender_fp, const std::string& contact_name, std::string& error);
    void decline_request(const std::string& sender_fp);

    // --- Groups ---
    // A group is created by one person, who invites the others; each of them accepts or declines.
    // Membership never changes afterwards, and a message is sent to each member separately.
    // Members who aren't each other's contacts get a send token from one another when they accept:
    // each makes a token for the others and sends it sealed through the group's creator, who can't
    // read it. Until those arrive the group shows as not ready.
    // How far a person can be trusted to be who they seem. A group's creator can pass on the keys of
    // people you have never checked, so the app shows where each person's identity came from.
    enum class Trust {
        Unknown,     // we hold no keys for them
        Introduced,  // someone in a group the creator introduced; nobody has checked their fingerprint
        Contact,     // in your contacts, not marked verified
        Verified,    // you compared their fingerprint with them
    };
    struct GroupMember {
        std::string fp;        // lowercase hex
        std::string name;      // a contact's name; else the display name in their bundle (untrusted text); else a short fingerprint
        bool is_contact = false;
        bool can_send = false; // from here, we can write to them
        Trust trust = Trust::Unknown;
        std::string introduced_by;  // for someone known only from a group: the name of who introduced them
        std::string label;     // for display: "Verified by you", "Contact", "Introduced by Alice" or "Unknown"
    };
    struct GroupSummary {
        std::string id;        // lowercase hex
        std::string title;     // the creator's suggestion; untrusted text; may be empty
        std::string creator_fp;
        bool created_by_me = false;
        std::vector<GroupMember> members;  // the others; not this user
        size_t unread = 0;
        int64_t last_activity = 0;
        bool ready = false;    // false while some member can't be written to yet ("setting up")
    };
    std::vector<GroupSummary> groups();  // most recent activity first

    // Makes a group of the given contacts (not including this user) and invites them all.
    // Each must be a contact you can message; 1 to 15 of them. `group_id` receives the new ID.
    bool create_group(const std::string& title, const std::vector<std::string>& member_fps, std::string& group_id, std::string& error);

    struct GroupMessage {
        int64_t row = 0;
        std::string message_id;  // lowercase hex
        std::string sender_fp;   // lowercase hex; this user's own for outgoing messages
        std::string sender_name; // empty for outgoing messages
        bool outgoing = false;
        int64_t sent_at = 0;
        std::string text;
        int status = 0;    // outgoing: 0 queued, 1 sent, 2 delivered, 3 read (the lowest across all members). Incoming: 0 unread, 1 read.
        bool gap = false;  // the sender's record points at a message of theirs we never got
    };
    std::vector<GroupMessage> group_messages(const std::string& group_id, size_t limit = 300);
    struct MemberDelivery {
        std::string fp;
        std::string name;
        int status = 0;  // as above, for this member alone
    };
    std::vector<MemberDelivery> group_delivery(const std::string& group_id, const std::string& message_id);
    // Queues a message to every member; it is sent by pump().
    bool send_group_text(const std::string& group_id, const std::string& text, std::string& error);
    // Marks everything read and queues read receipts (to each message's author) if those are on.
    void mark_group_read(const std::string& group_id);
    void set_group_receipts(const std::string& group_id, bool delivery, bool read);
    bool group_receipts_enabled(const std::string& group_id, bool* delivery, bool* read);

    // --- Group invitations: from contacts, waiting for the user's answer ---
    // (An invitation from someone who isn't a contact arrives as a message request first; once
    // that person is accepted, their invitation appears here.)
    struct GroupInvite {
        std::string id;          // the group's ID, lowercase hex
        std::string title;       // untrusted text; may be empty
        std::string creator_fp;
        std::string creator_name;
        std::vector<GroupMember> members;  // everyone but this user, creator included
        int64_t received_at = 0;
        size_t held_messages = 0;  // messages that arrived for the group while it waited
    };
    std::vector<GroupInvite> group_invites();
    // Joins the group: stores it, then delivers what was held. False (with a reason) if the invitation is gone or invalid.
    bool accept_group_invite(const std::string& group_id, std::string& error);
    // Forgets the invitation without telling the creator.
    void decline_group_invite(const std::string& group_id);

    // --- Chat archive (M4) ---
    // A chat's archive is an encrypted, hash-chained copy on a relay (see the design document). One person
    // makes it (a group's creator; in a one-to-one chat, whoever has the smaller fingerprint) and gives every
    // other member a grant; each member registers their own key with the relay. These calls talk to the relay.
    // The ID of the one-to-one conversation with a contact, in lowercase hex, for the calls below.
    std::optional<std::string> direct_conversation_id(const std::string& contact_fp);
    struct ArchiveStatus {
        bool exists = false;
        bool joined = false;   // this device has registered its key and can use the archive
        bool failed = false;
        std::string note;      // why joining failed
        bool is_creator = false;
        uint64_t entries = 0;  // how far this device has checked the chain
        std::string relay;     // host:port of the relay that holds it
    };
    ArchiveStatus archive_status(const std::string& conversation_id);
    // Makes the archive on this app's relay and queues each other member's grant (sent by pump()). Only
    // the person whose job it is may; the others get theirs. False, with a reason, otherwise.
    bool create_archive(const std::string& conversation_id, std::string& error);
    struct ArchivedRecord {
        uint64_t number = 0;
        std::vector<uint8_t> record;  // a signed record; empty if the entry could not be read with the archive key
    };
    // Adds one signed record to the archive after the latest entry. It first catches up on whatever others
    // added meanwhile (checked, decrypted, returned in `others`), and tries again if someone gets in first.
    // `number` is the new entry's number.
    bool archive_append(const std::string& conversation_id, const std::vector<uint8_t>& record, uint64_t& number, std::vector<ArchivedRecord>& others,
                        std::string& error);
    // Fetches what this device hasn't seen yet, checks the whole chain from where it left off, and decrypts
    // it. Fails if the relay's copy doesn't add up (altered, reordered, or its end withheld).
    bool archive_sync(const std::string& conversation_id, std::vector<ArchivedRecord>& fresh, std::string& error);

    // --- Running ---
    // Handles at most a few events: connects and signs in if needed, waits up to wait_ms for the
    // relay to say something, stores and acknowledges what arrives, sends whatever is queued.
    void pump(int wait_ms);
    bool connected() const { return connected_.load(); }
    std::string status() const;
    std::vector<std::string> take_notices();  // things the user should hear about, oldest first
    uint64_t revision() const { return revision_.load(); }  // changes whenever anything visible changes

private:
    using Bytes = std::vector<uint8_t>;

    bool connect_authenticated(RelayClient& client, std::string& error);
    bool try_connect_owner();
    void notify(const std::string& line);
    void set_status(const std::string& s);
    void bump() { revision_++; }

    // Someone we can verify and (maybe) write to: a contact, or a person a group creator introduced.
    struct Peer {
        std::string fp;
        std::string name;
        Bytes pub_dsa, pub_kem;
        std::string relay_address;
        Bytes relay_id, mailbox_id, send_token;
        bool is_contact = false;
        bool keys_verified = false;  // their encryption key is bound to their identity by a signed bundle
        bool can_send = false;
    };
    static Peer peer_from_contact(const KeyStore::Contact& contact);
    // With `conversation_id`, a send token a member gave us for that group counts too.
    std::optional<Peer> resolve_peer(const std::string& fp, const Bytes& conversation_id = Bytes());
    GroupMember member_info(const std::string& fp, const Bytes& conversation_id = Bytes());
    std::string person_name(const std::string& fp);  // a contact's name, else a short fingerprint
    // After joining a group: queues the job of making a send token for each member who needs one.
    void queue_group_grants(const Bytes& conversation_id, const std::string& creator_fp, const std::vector<std::string>& others);
    // Turns such a job into signed Forward records for the creator. False if it must be retried.
    bool build_grant_forwards(const HistoryStore::OutboxItem& job, std::vector<Bytes>& forwards);

    bool process_envelope(const relay::StoredEnvelope& envelope);  // true = acknowledge it
    bool handle_record(const KeyStore::Contact& contact, const chat::SignedRecord& record, bool delay_receipt);
    bool handle_group_record(const Peer& sender, const chat::SignedRecord& record, bool delay_receipt);
    // A creation record from a contact: keeps it as an invitation, and remembers the people it introduces.
    bool receive_group_invite(const KeyStore::Contact& creator, const chat::SignedRecord& record, const std::vector<Bytes>& introduced);
    void prune_introduced();
    std::vector<Bytes> latest_heads(const Bytes& conversation_id, const std::vector<std::string>& members);
    void note_token_use(const Bytes& token_hash, const std::string& sender_fp);

    // Chat archive: who a conversation's members are and whose job the archive is.
    struct ArchiveContext {
        std::vector<std::string> others;  // everyone but this user, lowercase hex
        Bytes recipients_hash;
        std::string maker_fp;             // who makes the archive
        bool direct = false;
    };
    std::optional<ArchiveContext> archive_context(const Bytes& conversation_id);
    bool receive_archive_grant(const Peer& sender, const chat::SignedRecord& record);
    void join_pending_archives();
    bool open_archive_session(const HistoryStore::Archive& archive, RelayClient& client, std::string& error);
    bool archive_catch_up(RelayClient& client, const HistoryStore::Archive& archive, archive::Head& head, std::vector<ArchivedRecord>& fresh, std::string& error);
    std::map<std::string, std::chrono::steady_clock::time_point> archive_join_retry_;  // when to try joining again
    void enqueue_receipt(const std::string& contact_fp, chat::ReceiptKind kind, const std::vector<Bytes>& ids, bool delayed);
    void enqueue_receipt_in(const Bytes& conversation_id, const Bytes& recipients_hash, const std::string& to_fp,
                            chat::ReceiptKind kind, const std::vector<Bytes>& ids, bool delayed);
    void flush_outbox();
    int64_t retry_delay(int attempts) const;
    Bytes own_bundle_raw();

    KeyStore& keys_;
    Options options_;
    std::unique_ptr<HistoryStore> history_;
    Bytes kem_private_, dsa_private_;
    Bytes my_fp_;
    std::string my_fp_hex_;

    mutable std::mutex mutex_;  // guards the fields below
    std::string display_name_;
    std::string status_ = "Not connected";
    std::vector<std::string> notices_;
    std::set<std::string> told_about_;  // notices already shown once (so repeats don't flood)

    // Used only by the pump thread:
    RelayClient owner_;
    std::chrono::steady_clock::time_point next_attempt_{};
    std::chrono::steady_clock::time_point last_ping_{};
    int backoff_seconds_ = 0;

    std::atomic<bool> connected_{false};
    std::atomic<uint64_t> revision_{0};
};
