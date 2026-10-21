#pragma once

#include <atomic>
#include <condition_variable>
#include <deque>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <thread>
#include <string>
#include <vector>

#include "archive.h"
#include "attachment.h"
#include "envelope.h"
#include "history_store.h"
#include "identity_bundle.h"
#include "key_store.h"
#include "keyring.h"
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
        // Chat archives: how often to look for chats that need one, how often to catch up on each archive,
        // and when to add a checkpoint (after this many entries, or if there has been activity and this
        // long has passed since the last).
        int archive_check_seconds = 10;
        int archive_sync_seconds = 300;
        int archive_checkpoint_every = 50;
        int archive_checkpoint_max_age_seconds = 24 * 3600;
        int keyring_check_seconds = 60;  // how often to see whether the keyring on the relay needs updating
        uint64_t max_attachment_bytes = 1024ull * 1024 * 1024;  // the largest file this app will try to send (a relay may allow less)
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

    // An attachment as the chat shows it. States are HistoryStore::AttachmentState: uploading (waiting and retrying until it is
    // on the relay), available, transferred (fetched by us, or by everyone it was for), expired, withdrawn, unavailable
    // (arrived without a key, for instance read back from an archive), failed, downloading.
    struct AttachmentView {
        std::string file_id;  // lowercase hex
        std::string name;     // as the sender called it; shown, and made safe before it is used as a file name
        uint64_t size = 0;
        std::string caption;
        int state = 5;
        int64_t expires_at = 0;
        bool outgoing = false;
        size_t recipients = 0;   // outgoing: how many it is for
        size_t redeemed = 0;     // outgoing: how many have fetched it
        std::string saved_path;  // incoming, once fetched: where it was saved
        std::string note;        // why it failed, or how the last attempt went
    };
    struct ChatMessage {
        int64_t row = 0;
        bool outgoing = false;
        int64_t sent_at = 0;
        std::string text;
        int status = 0;   // outgoing: 0 queued, 1 sent, 2 delivered, 3 read. Incoming: 0 unread, 1 read.
        bool gap = false; // the sender's record points at a message we never got
        bool deleted = false;  // removed by agreement of everyone in the chat: only its place is left
        bool is_attachment = false;  // then `text` is the caption and `attachment` has the rest
        AttachmentView attachment;
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
        bool deleted = false;  // removed by agreement of everyone in the chat: only its place is left
        bool is_attachment = false;  // then `text` is the caption and `attachment` has the rest
        AttachmentView attachment;
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
        uint64_t checkpoint_seen = 0;  // the latest entry any member's checkpoint says they had seen
        std::string warning;   // the relay's copy contradicts something this device holds; empty if all is well
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

    // --- Deleting by agreement (M4) ---
    // Any member can ask to delete the whole chat, or particular messages, from the archive and from every
    // device. It happens only if EVERY member accepts; one who declines, or doesn't answer, stops it, and the
    // request lapses after 7 days. Each acceptance is signed with that member's archive key, so the relay can
    // check that all of them agreed before it acts. Messages sent before the chat's archive was made can't be
    // named, because the archive doesn't hold them.
    struct DeletionInfo {
        std::string op_id;            // lowercase hex
        std::string conversation_id;  // lowercase hex
        bool whole_chat = true;
        size_t entries = 0;           // how many messages, when it isn't the whole chat
        std::string requester_fp;
        std::string requester_name;
        bool mine = false;            // this user asked for it
        int64_t expires_at = 0;
        int state = 0;                // HistoryStore::DeletionState: pending (your answer is wanted), accepted, declined, done, expired
        size_t accepted = 0;          // acceptances held, including this user's
        size_t members = 0;           // everyone in the chat, including this user
    };
    bool request_chat_deletion(const std::string& conversation_id, std::string& error);
    bool request_message_deletion(const std::string& conversation_id, const std::vector<std::string>& message_ids, std::string& error);
    std::vector<DeletionInfo> deletions();  // newest first
    bool accept_deletion(const std::string& op_id, std::string& error);
    bool decline_deletion(const std::string& op_id);

    // --- Attachments (M5) ---
    // A file is sent as a message that points at an encrypted copy on this app's relay. The upload runs in the
    // background and the message is not delivered until the file is there, so a relay that is down just means waiting and
    // retrying. Each recipient gets their own one-time download token and the file key in their own envelope. Files are
    // never fetched automatically: the recipient chooses (download_attachment). `days` is how long the relay keeps it
    // (1 to 30). The file is read once to fingerprint it, here, before this returns.
    bool send_attachment(const std::string& contact_fp, const std::filesystem::path& file, const std::string& caption, int days, std::string& error);
    bool send_group_attachment(const std::string& group_id, const std::filesystem::path& file, const std::string& caption, int days, std::string& error);
    // Starts fetching an incoming attachment into `directory` and returns at once; follow it with the message's state and
    // attachment_progress(). The file is checked against the fingerprint the sender signed before it is saved under a safe
    // name that never replaces anything, and only then is the one-time token used up. A failed or interrupted attempt can be
    // started again and carries on where it stopped.
    bool download_attachment(const std::string& file_id, const std::filesystem::path& directory, std::string& error);
    // One attachment as the chat shows it (the caption lives in the message, so it is empty here). Nothing if it isn't known.
    std::optional<AttachmentView> attachment(const std::string& file_id);
    // Takes back an attachment this user sent: the relay deletes it, and recipients who have not fetched it can't.
    bool withdraw_attachment(const std::string& file_id, std::string& error);
    // Bytes done and in all, for an upload or download under way. False if nothing is.
    bool attachment_progress(const std::string& file_id, uint64_t& done, uint64_t& total);

    // --- Restoring after a reinstall (M4) ---
    // The keyring is what a reinstalled app needs, beyond the keys folder, to find and open its chats'
    // archives. It is encrypted so the relay can't read it and kept in a slot of the user's own mailbox;
    // pump() keeps it up to date. Without the keys folder and its passphrase there is nothing to restore from.
    // Builds the keyring and stores it on the relay now, instead of waiting for pump() to.
    bool save_keyring(std::string& error);
    struct RestoreReport {
        bool found = false;               // the relay held a keyring that these keys could open
        size_t archives = 0;              // chats whose archive details were restored
        size_t chats_restored = 0;        // chats whose messages were read back from their archive
        size_t chats_skipped = 0;         // chats that could not be rebuilt or read
        size_t messages = 0;              // messages read back (all marked read)
        std::vector<std::string> notes;   // what could not be restored, in words
    };
    // Fetches and opens the keyring, restores what it holds, then reads every chat's archive, checking each
    // chain, and rebuilds the chats and their messages. Safe to run again: nothing held is added twice.
    // Chats that were never archived (older than M4, and Private chats) cannot come back.
    bool restore_from_relay(RestoreReport& report, std::string& error);

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
    void ensure_archives();                  // makes the archive for chats where that is our job
    void sync_archives();                    // catches up on each archive now and then, and when a gap shows
    void queue_archive_entry(const Bytes& conversation_id, const Bytes& record, const Bytes& message_id);
    void flush_archive_item(const HistoryStore::OutboxItem& item, int64_t now);
    bool handle_archived_records(const Bytes& conversation_id, const std::vector<ArchivedRecord>& records);
    bool process_checkpoint(const Bytes& conversation_id, const chat::SignedRecord& record, const std::string& sender_fp);
    void maybe_post_checkpoint(const Bytes& conversation_id);
    void warn_archive(const Bytes& conversation_id, const std::string& what);
    bool start_deletion(const Bytes& conversation_id, uint32_t scope, const std::vector<Bytes>& entries, std::string& error);
    bool receive_deletion_request(const Peer& sender, const chat::SignedRecord& record);
    bool receive_deletion_accept(const Peer& sender, const chat::SignedRecord& record);
    Bytes sign_deletion(const HistoryStore::Archive& archive, const HistoryStore::Deletion& deletion);
    void try_submit_deletion(const Bytes& op_id);
    void apply_deletion_locally(const HistoryStore::Deletion& deletion);
    void check_deletions();
    std::map<std::string, size_t> deletion_submit_attempts_;  // operation -> acceptances held at the last attempt
    std::chrono::steady_clock::time_point next_deletion_check_{};
    // Attachments: sending and fetching run on one background thread, so a large file never holds up messages.
    struct TransferJob {
        enum Kind { Upload, Download } kind = Upload;
        Bytes file_id;
        int64_t outbox_id = 0;   // an upload's queue entry, so it can be retried or finished
        std::string directory;   // a download's destination
    };
    AttachmentView attachment_view(const chat::AttachmentInfo& info);
    void note_incoming_attachment(const chat::SignedRecord& record);
    bool start_attachment_send(const Bytes& conversation_id, const std::vector<std::string>& recipients, const Bytes& recipients_hash,
                               const std::vector<Bytes>& seen, const std::filesystem::path& file, const std::string& caption, int days, std::string& error);
    void queue_transfer(TransferJob job);
    void transfer_loop();
    void stop_transfers();
    void run_upload(const TransferJob& job);
    void run_download(const TransferJob& job);
    void check_attachments();
    std::vector<chat::AttachmentGrant> envelope_grants_;  // the grants in the envelope being handled
    std::mutex xfer_mutex_;
    std::condition_variable xfer_cv_;
    std::deque<TransferJob> xfer_queue_;
    std::set<std::string> xfer_active_;
    std::map<std::string, std::pair<uint64_t, uint64_t>> xfer_progress_;
    std::thread xfer_thread_;
    bool xfer_stop_ = false;
    std::atomic<bool> xfer_cancel_{false};
    std::chrono::steady_clock::time_point next_attachment_check_{};
    keyring::Contents build_keyring();
    bool store_keyring(const Bytes& plaintext, std::string& error);
    void maintain_keyring();
    bool rebuild_direct_chat(const Bytes& conversation_id);
    bool rebuild_group_chat(const Bytes& conversation_id, const std::vector<ArchivedRecord>& records, std::string& why);
    size_t restore_records(const Bytes& conversation_id, const std::vector<ArchivedRecord>& records);
    Bytes keyring_uploaded_hash_;
    std::chrono::steady_clock::time_point next_keyring_check_{};
    std::map<std::string, std::chrono::steady_clock::time_point> archive_create_retry_;
    std::map<std::string, std::chrono::steady_clock::time_point> archive_next_sync_;
    std::set<std::string> archive_sync_now_;  // chats where a message showed a gap
    std::chrono::steady_clock::time_point next_archive_check_{};
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
