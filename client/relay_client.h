#pragma once

#include <cstdint>
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

    bool add_token(const std::vector<uint8_t>& token_hash, std::string& error);
    bool revoke_token(const std::vector<uint8_t>& token_hash, std::string& error);
    bool ping(std::string& error);

private:
    bool send_request(MessageType type, const std::vector<uint8_t>& payload, std::string& error);
    // Waits for `expected`, queueing envelopes that arrive first. False on ERROR_MSG or failure.
    bool read_reply(MessageType expected, std::vector<uint8_t>* payload, std::string& error);
    void queue_envelope(const std::vector<uint8_t>& payload);

    socket_t sock_ = INVALID_SOCKET_VAL;
    std::vector<uint8_t> relay_id_;
    std::vector<uint8_t> challenge_;
    std::deque<Event> queue_;
    std::set<std::vector<uint8_t>> seen_;
};
