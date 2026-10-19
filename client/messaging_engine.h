#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "envelope.h"
#include "history_store.h"
#include "identity_bundle.h"
#include "key_store.h"
#include "message_record.h"
#include "relay_client.h"
#include "sharing.h"

// One-to-one Saved chats over a mailbox relay.
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
        std::string cannot_send_reason;  // why not, in words
    };
    std::vector<ChatSummary> chats();

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
    // Adds the sender as a contact and delivers what they sent. The caller has already checked
    // the fingerprint with the user.
    bool accept_request(const std::string& sender_fp, const std::string& contact_name, std::string& error);
    void decline_request(const std::string& sender_fp);

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

    bool process_envelope(const relay::StoredEnvelope& envelope);  // true = acknowledge it
    bool handle_record(const KeyStore::Contact& contact, const chat::SignedRecord& record, bool delay_receipt);
    void note_token_use(const Bytes& token_hash, const std::string& sender_fp);
    void enqueue_receipt(const std::string& contact_fp, chat::ReceiptKind kind, const std::vector<Bytes>& ids, bool delayed);
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
