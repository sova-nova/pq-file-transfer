#pragma once

#include <cstdint>
#include <functional>
#include <deque>
#include <set>
#include <string>
#include <vector>

#include "crypto_engine.h"
#include "messages.h"
#include "platform.h"
#include "relay_protocol.h"

// One connection to a v3 mailbox relay (see relay_protocol.h). Blocking calls with timeouts:
// call it from a worker thread. Not thread-safe; use one RelayClient per connection.
//
// Every operation returns false with a message in `error` rather than throwing. After a
// failure the connection may be unusable; check connected().
class RelayClient {
public:
    RelayClient() = default;
    ~RelayClient();
    RelayClient(const RelayClient&) = delete;
    RelayClient& operator=(const RelayClient&) = delete;

    // Connects and checks the relay's identity. If `expected_relay_id` is not empty, the relay
    // must prove it holds exactly that key (pinning): a different relay, or a replayed answer,
    // is refused. If it is empty (first contact) the relay is accepted and the caller must
    // show relay_id() so the user can compare it with the operator's.
    bool connect(const std::string& host, uint16_t port, const std::vector<uint8_t>& expected_relay_id,
                 int timeout_seconds, std::string& error);
    bool connected() const { return sock_ != INVALID_SOCKET_VAL; }
    const std::vector<uint8_t>& relay_id() const { return relay_id_; }
    void close();

    // Creates a mailbox. `access_key` is a fresh ML-DSA key pair made for this mailbox only;
    // `send_token` is the first send token (SEND_TOKEN_BYTES random bytes).
    bool register_mailbox(const std::vector<uint8_t>& invite, const std::vector<uint8_t>& mailbox_id,
                          const CryptoEngine::SigKeyPair& access_key, const std::vector<uint8_t>& send_token,
                          std::string& error);

    // Proves ownership of a mailbox for this connection.
    bool authenticate(const std::vector<uint8_t>& mailbox_id, const std::vector<uint8_t>& access_private_key,
                      std::string& error);

    // Needs no sign-in: anyone holding the send token can deposit.
    bool deposit(const std::vector<uint8_t>& mailbox_id, const std::vector<uint8_t>& send_token,
                 const std::vector<uint8_t>& envelope, uint32_t ttl_seconds,
                 std::vector<uint8_t>* envelope_id, std::string& error);

    // Needs sign-in. Starts delivery of queued envelopes, then of new ones as they arrive.
    bool collect(std::string& error);

    struct Event {
        enum class Kind { Envelope, CollectEnd, Timeout, Closed } kind = Kind::Timeout;
        relay::StoredEnvelope envelope;  // for Envelope
        std::string text;                // for Closed: why
    };
    // Waits up to timeout_ms for the next envelope (each ID is delivered once per connection),
    // the end of the backlog, or the end of the connection.
    Event next_event(int timeout_ms);

    // Tells the relay these envelopes are stored safely, so it can delete them. `deleted`, if
    // given, is set to how many the relay actually deleted (it only deletes this mailbox's own).
    bool acknowledge(const std::vector<std::vector<uint8_t>>& envelope_ids, size_t* deleted, std::string& error);

    // Needs sign-in. Asks the relay for one single-use invite to give a friend. The relay limits how
    // many a member may make and records that this mailbox vouched for whoever uses it.
    bool create_invite(std::vector<uint8_t>& invite, std::string& error);
    // Needs sign-in. Your unused invites, the people who have joined through you, and the relay's limits.
    bool list_invites(relay::InviteStatus& status, std::string& error);
    // Needs sign-in. Cancels one of your unused invites, named by the hash the list gave.
    bool cancel_invite(const std::vector<uint8_t>& invite_hash, std::string& error);

    // --- Prekeys (see relay_protocol.h) ---
    // Needs a mailbox sign-in. On success `status` (if given) says what the relay now holds.
    bool put_prekeys(const relay::PrekeyPut& put, relay::PrekeyStatus* status, std::string& error);
    bool prekey_status(relay::PrekeyStatus& status, std::string& error);
    // Needs no sign-in, only a send token for the mailbox. The prekey must still be checked against its owner's identity key.
    bool take_prekey(const std::vector<uint8_t>& mailbox_id, const std::vector<uint8_t>& send_token, relay::PrekeyData& prekey, std::string& error);

    // --- Attachments (see relay_protocol.h). Chunks are passed one at a time, so a file is never held whole in memory. ---
    // Gives chunk `index` (of ciphertext); false stops the transfer.
    using FileChunkSource = std::function<bool(uint32_t index, std::vector<uint8_t>& chunk)>;
    // Receives chunk `index`; false stops the transfer.
    using FileChunkSink = std::function<bool(uint32_t index, const std::vector<uint8_t>& chunk)>;
    // Needs a mailbox sign-in. Uploads a file whose chunking and one-token-per-recipient are in `begin`.
    bool upload_file(const relay::FileBegin& begin, const FileChunkSource& source, std::string& error);
    // Needs no sign-in: the token is the permission. Fetches from `from_chunk` onwards. This does NOT use the token up:
    // call redeem_file once the file has been decrypted and checked.
    bool download_file(const std::vector<uint8_t>& file_id, const std::vector<uint8_t>& token, uint32_t from_chunk, relay::FileInfo& info,
                       const FileChunkSink& sink, std::string& error);
    bool redeem_file(const std::vector<uint8_t>& file_id, const std::vector<uint8_t>& token, std::string& error);
    // Need a mailbox sign-in, and the file to be this mailbox's.
    bool cancel_file(const std::vector<uint8_t>& file_id, std::string& error);
    bool file_status(const std::vector<uint8_t>& file_id, relay::FileStatus& status, std::string& error);

    // --- Keyring (needs a mailbox sign-in): one encrypted blob per mailbox, sent in chunks ---
    bool put_keyring(const std::vector<uint8_t>& blob, std::string& error);
    // `exists` is false (and `blob` empty) if the relay holds none.
    bool get_keyring(std::vector<uint8_t>& blob, bool& exists, std::string& error);

    // --- Chat archives (see relay_protocol.h) ---
    // Needs a mailbox sign-in. Makes an archive for as many members as there are join token hashes.
    bool create_archive(const std::vector<uint8_t>& archive_id, const std::vector<std::vector<uint8_t>>& join_token_hashes, std::string& error);
    // Needs no sign-in: the join token is the permission. `chat_key` is made for this chat only.
    bool join_archive(const std::vector<uint8_t>& archive_id, const std::vector<uint8_t>& join_token,
                      const CryptoEngine::SigKeyPair& chat_key, std::string& error);
    // Proves membership of one archive for this connection (one attempt per connection, like a mailbox sign-in).
    bool authenticate_archive(const std::vector<uint8_t>& archive_id, const CryptoEngine::SigKeyPair& chat_key, std::string& error);
    enum class AppendOutcome { Appended, Stale, Failed };
    // Adds an entry after the head the caller knows. Appended: `head` is the new head. Stale: someone else
    // appended first and `head` is where the head is now; fetch what was missed and try again.
    AppendOutcome append_entry(uint64_t expected_number, const std::vector<uint8_t>& expected_hash,
                               const std::vector<uint8_t>& ciphertext, relay::ArchiveHead& head, std::string& error);
    // Deletes the whole archive, or redacts the entries named, once every member's key has signed the same
    // order (see relay::archive_delete_signing_input). The connection must be signed in to the archive.
    bool delete_in_archive(const relay::ArchiveDelete& order, std::string& error);
    // Entries numbered from_number onwards (at most `limit`), in the order the relay sends them, and the head.
    bool fetch_entries(uint64_t from_number, uint32_t limit, std::vector<relay::ArchiveEntry>& entries,
                       relay::ArchiveHead& head, std::string& error);

    bool add_token(const std::vector<uint8_t>& token_hash, std::string& error);
    bool revoke_token(const std::vector<uint8_t>& token_hash, std::string& error);
    bool ping(std::string& error);

private:
    bool send_request(MessageType type, const std::vector<uint8_t>& payload, std::string& error);
    // Waits for `expected`, queueing envelopes that arrive first. False on ERROR_MSG or failure.
    bool read_reply(MessageType expected, std::vector<uint8_t>* payload, std::string& error);
    // The same, when either of two replies is a valid answer; `which` says which came.
    bool read_reply_either(MessageType first, MessageType second, MessageType* which, std::vector<uint8_t>* payload, std::string& error);
    void queue_envelope(const std::vector<uint8_t>& payload);

    socket_t sock_ = INVALID_SOCKET_VAL;
    std::vector<uint8_t> relay_id_;
    std::vector<uint8_t> challenge_;
    std::deque<Event> queue_;
    std::set<std::vector<uint8_t>> seen_;
};
