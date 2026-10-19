#include "relay_client.h"

#include "messages.h"
#include "protocol.h"
#include "scope_exit.h"

#include <cstring>

namespace {

std::string clean(const std::vector<uint8_t>& payload) {
    std::string out;
    for (uint8_t b : payload) {
        if (out.size() >= 200) break;
        out.push_back(b >= 0x20 && b != 0x7F ? static_cast<char>(b) : ' ');
    }
    return out.empty() ? "unknown error" : out;
}

}  // namespace

RelayClient::~RelayClient() { close(); }

void RelayClient::close() {
    if (sock_ != INVALID_SOCKET_VAL) {
        close_socket(sock_);
        sock_ = INVALID_SOCKET_VAL;
    }
    queue_.clear();
    seen_.clear();
}

bool RelayClient::connect(const std::string& host, uint16_t port, const std::vector<uint8_t>& expected_relay_id,
                          int timeout_seconds, std::string& error) {
    close();

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* results = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &results) != 0 || !results) {
        error = "Could not resolve the relay address \"" + host + "\"";
        return false;
    }
    auto free_results = make_scope_exit([results] { freeaddrinfo(results); });

    int failure = 0;
    for (addrinfo* ai = results; ai; ai = ai->ai_next) {
        socket_t s = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == INVALID_SOCKET_VAL) continue;
        set_socket_timeouts(s, timeout_seconds);
        disable_sigpipe(s);
        if (::connect(s, ai->ai_addr, static_cast<socklen_t>(ai->ai_addrlen)) == 0) {
            sock_ = s;
            break;
        }
        failure = last_socket_error();  // read before close_socket can change it
        close_socket(s);
    }
    if (sock_ == INVALID_SOCKET_VAL) {
        error = describe_connect_failure("relay", host + ":" + std::to_string(port), failure);
        return false;
    }

    relay::Hello hello;
    hello.client_nonce = CryptoEngine::random_bytes(relay::NONCE_BYTES);
    if (!send_request(MessageType::RELAY_HELLO, relay::encode(hello), error)) return false;

    auto msg = recv_message(sock_, relay::MAX_MESSAGE_PAYLOAD);
    if (!msg) {
        error = "The relay did not answer";
        close();
        return false;
    }
    if (msg->type == MessageType::ERROR_MSG) {
        error = "Relay: " + clean(msg->payload);
        close();
        return false;
    }
    auto reply = msg->type == MessageType::RELAY_HELLO_REPLY ? relay::decode_hello_reply(msg->payload) : std::nullopt;
    if (!reply || reply->relay_public_key.size() != CryptoEngine::sig_public_key_size()) {
        error = "That is not a PQ File Transfer relay, or it speaks an incompatible version";
        close();
        return false;
    }

    relay_id_ = CryptoEngine::sha256(reply->relay_public_key);
    if (!expected_relay_id.empty() && relay_id_ != expected_relay_id) {
        error = "This relay's identity does not match the one you pinned (expected " +
                bytes_to_hex(expected_relay_id).substr(0, 16) + "..., got " + bytes_to_hex(relay_id_).substr(0, 16) +
                "...). Someone may be impersonating it, or it was rebuilt without its key.";
        close();
        return false;
    }
    if (!CryptoEngine::verify(relay::hello_signing_input(hello.client_nonce, relay_id_, relay::WIRE_VERSION, reply->auth_challenge),
                              reply->signature, reply->relay_public_key)) {
        error = "The relay failed to prove its identity. It may be impersonated, or an old answer is being replayed.";
        close();
        return false;
    }
    challenge_ = reply->auth_challenge;
    return true;
}

bool RelayClient::send_request(MessageType type, const std::vector<uint8_t>& payload, std::string& error) {
    if (!connected()) {
        error = "Not connected to a relay";
        return false;
    }
    if (!send_message(sock_, type, payload)) {
        error = "Lost the connection to the relay";
        close();
        return false;
    }
    return true;
}

void RelayClient::queue_envelope(const std::vector<uint8_t>& payload) {
    auto env = relay::decode_stored_envelope(payload);
    if (!env) return;                          // malformed: ignore rather than trust it
    if (!seen_.insert(env->id).second) return;  // the same envelope again: deliver once
    Event e;
    e.kind = Event::Kind::Envelope;
    e.envelope = std::move(*env);
    queue_.push_back(std::move(e));
}

bool RelayClient::read_reply(MessageType expected, std::vector<uint8_t>* payload, std::string& error) {
    while (true) {
        auto msg = recv_message(sock_, relay::MAX_MESSAGE_PAYLOAD);
        if (!msg) {
            error = "Lost the connection to the relay";
            close();
            return false;
        }
        if (msg->type == expected) {
            if (payload) *payload = std::move(msg->payload);
            return true;
        }
        switch (msg->type) {
            case MessageType::ERROR_MSG:
                error = "Relay: " + clean(msg->payload);
                return false;  // an error answers one request; the connection is still usable unless closed
            case MessageType::RELAY_ENVELOPE:
                queue_envelope(msg->payload);
                break;
            case MessageType::RELAY_COLLECT_END: {
                Event e;
                e.kind = Event::Kind::CollectEnd;
                queue_.push_back(std::move(e));
                break;
            }
            case MessageType::RELAY_PONG:
                break;
            default:
                error = "The relay sent something unexpected";
                close();
                return false;
        }
    }
}

bool RelayClient::register_mailbox(const std::vector<uint8_t>& invite, const std::vector<uint8_t>& mailbox_id,
                                   const CryptoEngine::SigKeyPair& access_key, const std::vector<uint8_t>& send_token,
                                   std::string& error) {
    relay::Register r;
    r.invite = invite;
    r.mailbox_id = mailbox_id;
    r.access_public_key = access_key.public_key;
    r.send_token_hash = CryptoEngine::sha256(send_token);
    try {
        r.signature = CryptoEngine::sign(relay::register_signing_input(relay_id_, mailbox_id, access_key.public_key, r.send_token_hash),
                                         access_key.private_key);
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
    return send_request(MessageType::RELAY_REGISTER, relay::encode(r), error) &&
           read_reply(MessageType::RELAY_REGISTER_OK, nullptr, error);
}

bool RelayClient::authenticate(const std::vector<uint8_t>& mailbox_id, const std::vector<uint8_t>& access_private_key,
                               std::string& error) {
    relay::Auth a;
    a.mailbox_id = mailbox_id;
    try {
        a.signature = CryptoEngine::sign(relay::auth_signing_input(challenge_, relay_id_, mailbox_id), access_private_key);
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
    bool ok = send_request(MessageType::RELAY_AUTH, relay::encode(a), error) &&
              read_reply(MessageType::RELAY_AUTH_OK, nullptr, error);
    // The relay hangs up after a failed sign-in (one attempt per challenge), so stop pretending otherwise.
    if (!ok) close();
    return ok;
}

bool RelayClient::deposit(const std::vector<uint8_t>& mailbox_id, const std::vector<uint8_t>& send_token,
                          const std::vector<uint8_t>& envelope, uint32_t ttl_seconds,
                          std::vector<uint8_t>* envelope_id, std::string& error) {
    if (envelope.size() > relay::MAX_ENVELOPE_BYTES) {
        error = "That message is too large for the relay";
        return false;
    }
    relay::Deposit d;
    d.mailbox_id = mailbox_id;
    d.send_token = send_token;
    d.envelope = envelope;
    d.ttl_seconds = ttl_seconds;
    std::vector<uint8_t> reply;
    if (!send_request(MessageType::RELAY_DEPOSIT, relay::encode(d), error) ||
        !read_reply(MessageType::RELAY_DEPOSIT_OK, &reply, error))
        return false;
    auto ids = relay::decode_id_list(reply);
    if (envelope_id) *envelope_id = (ids && !ids->ids.empty()) ? ids->ids.front() : std::vector<uint8_t>();
    return true;
}

bool RelayClient::collect(std::string& error) {
    return send_request(MessageType::RELAY_COLLECT, {}, error);  // answers arrive through next_event()
}

RelayClient::Event RelayClient::next_event(int timeout_ms) {
    if (!queue_.empty()) {
        Event e = std::move(queue_.front());
        queue_.pop_front();
        return e;
    }
    Event closed;
    closed.kind = Event::Kind::Closed;
    if (!connected()) {
        closed.text = "Not connected to a relay";
        return closed;
    }
    if (!wait_readable(sock_, timeout_ms)) return Event{};  // Timeout

    auto msg = recv_message(sock_, relay::MAX_MESSAGE_PAYLOAD);
    if (!msg) {
        closed.text = "Lost the connection to the relay";
        close();
        return closed;
    }
    switch (msg->type) {
        case MessageType::RELAY_ENVELOPE:
            queue_envelope(msg->payload);
            break;
        case MessageType::RELAY_COLLECT_END: {
            Event e;
            e.kind = Event::Kind::CollectEnd;
            return e;
        }
        case MessageType::RELAY_PONG:
            break;
        case MessageType::ERROR_MSG:
            closed.text = "Relay: " + clean(msg->payload);
            close();
            return closed;
        default:
            closed.text = "The relay sent something unexpected";
            close();
            return closed;
    }
    if (!queue_.empty()) {
        Event e = std::move(queue_.front());
        queue_.pop_front();
        return e;
    }
    return Event{};  // nothing deliverable yet (a duplicate, or a pong): the caller polls again
}

bool RelayClient::acknowledge(const std::vector<std::vector<uint8_t>>& envelope_ids, size_t* deleted, std::string& error) {
    if (deleted) *deleted = 0;
    for (size_t start = 0; start < envelope_ids.size() || start == 0; start += relay::MAX_ACK_IDS) {
        relay::IdList list;
        for (size_t i = start; i < envelope_ids.size() && i < start + relay::MAX_ACK_IDS; i++) list.ids.push_back(envelope_ids[i]);
        std::vector<uint8_t> reply;
        if (!send_request(MessageType::RELAY_ACK, relay::encode(list), error) ||
            !read_reply(MessageType::RELAY_ACK_OK, &reply, error))
            return false;
        size_t off = 0;
        auto count = read_u32(reply.data(), reply.size(), off);
        if (deleted && count) *deleted += *count;
        for (const auto& id : list.ids) seen_.erase(id);
        if (envelope_ids.empty()) break;
    }
    return true;
}

bool RelayClient::add_token(const std::vector<uint8_t>& token_hash, std::string& error) {
    return send_request(MessageType::RELAY_TOKEN_ADD, relay::encode(relay::HashOp{token_hash}), error) &&
           read_reply(MessageType::RELAY_TOKEN_OK, nullptr, error);
}

bool RelayClient::revoke_token(const std::vector<uint8_t>& token_hash, std::string& error) {
    return send_request(MessageType::RELAY_TOKEN_REVOKE, relay::encode(relay::HashOp{token_hash}), error) &&
           read_reply(MessageType::RELAY_TOKEN_OK, nullptr, error);
}

bool RelayClient::ping(std::string& error) {
    return send_request(MessageType::RELAY_PING, {}, error) && read_reply(MessageType::RELAY_PONG, nullptr, error);
}
