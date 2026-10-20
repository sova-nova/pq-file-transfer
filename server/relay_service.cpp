#include "relay_service.h"

#include "crypto_engine.h"
#include "messages.h"
#include "protocol.h"
#include "relay_protocol.h"
#include "scope_exit.h"

#include <ctime>
#include <fstream>
#include <stdexcept>

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace relay {

namespace {

int64_t unix_now() { return static_cast<int64_t>(std::time(nullptr)); }

std::string hex_of(const Bytes& b) { return bytes_to_hex(b); }
std::string short_id(const Bytes& b) { return hex_of(b).substr(0, 8); }

void send_error(socket_t sock, const std::string& text) { send_text_message(sock, MessageType::ERROR_MSG, text); }

// Writes via a temporary file and rename; the file is owner-only before any secret bytes land.
void write_file_private(const fs::path& path, const Bytes& data, bool secret) {
    fs::path tmp = path;
    tmp += ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) throw std::runtime_error("Cannot write " + path.string());
        if (secret) {
            std::error_code ec;
            fs::permissions(tmp, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace, ec);
        }
        f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        f.close();
        if (f.fail()) throw std::runtime_error("Cannot write " + path.string());
    }
    std::error_code ec;
    fs::rename(tmp, path, ec);
    if (ec) throw std::runtime_error("Cannot write " + path.string() + ": " + ec.message());
}

Bytes read_file_all(const fs::path& path) {
    std::ifstream f(path, std::ios::binary);
    return Bytes(std::istreambuf_iterator<char>(f), {});
}

}  // namespace

// --- Rate limiting ---

bool RelayService::RateLimiter::allow(const std::string& key, int limit, int64_t now) {
    std::lock_guard<std::mutex> lock(mutex_);
    Window& w = windows_[key];
    if (now - w.start >= 60) {
        w.start = now;
        w.count = 0;
    }
    return ++w.count <= limit;
}

void RelayService::RateLimiter::prune(int64_t now) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = windows_.begin(); it != windows_.end();) {
        if (now - it->second.start >= 300) it = windows_.erase(it);
        else ++it;
    }
}

// --- Construction and identity ---

unsigned long RelayService::current_uid() {
#ifdef _WIN32
    return 0;
#else
    return static_cast<unsigned long>(geteuid());
#endif
}

void RelayService::check_owner(const fs::path& path, const std::string& what, unsigned long expected_uid) {
#ifdef _WIN32
    (void)path; (void)what; (void)expected_uid;
#else
    struct stat st {};
    if (lstat(path.c_str(), &st) != 0) return;  // not there yet: we will create it
    if (static_cast<unsigned long>(st.st_uid) == expected_uid) return;
    throw std::runtime_error(what + " " + path.string() + " belongs to user id " + std::to_string(st.st_uid) +
                             ", but this program is running as user id " + std::to_string(expected_uid) +
                             ". Run it as the user that owns it (for example: sudo -u <that user> ...), or hand the"
                             " folder over with: sudo chown -R <user> " + path.string());
#endif
}

bool RelayService::identity_exists(const fs::path& data_dir) {
    std::error_code ec;
    return fs::exists(data_dir / "relay_public.key", ec) && fs::exists(data_dir / "relay_private.key", ec);
}

RelayService::RelayService(const fs::path& data_dir, const RelayLimits& limits) : limits_(limits) {
    const unsigned long me = current_uid();
    check_owner(data_dir, "The relay's state folder", me);
    for (const char* name : {"relay_private.key", "relay_public.key", "relay.db"})
        check_owner(data_dir / name, "The relay's file", me);

    std::error_code ec;
    fs::create_directories(data_dir, ec);
    if (ec) throw std::runtime_error("Cannot create " + data_dir.string() + ": " + ec.message());
    fs::permissions(data_dir, fs::perms::owner_all, fs::perm_options::replace, ec);

    load_or_create_identity(data_dir);
    store_ = std::make_unique<RelayStore>(data_dir / "relay.db");
}

RelayService::~RelayService() {
    stop_sweeper();
    CryptoEngine::secure_wipe(private_key_);
}

std::string RelayService::relay_id_hex() const { return hex_of(relay_id_); }

void RelayService::load_or_create_identity(const fs::path& data_dir) {
    fs::path pub_path = data_dir / "relay_public.key";
    fs::path priv_path = data_dir / "relay_private.key";
    std::error_code ec;
    bool have_pub = fs::exists(pub_path, ec), have_priv = fs::exists(priv_path, ec);

    if (have_pub != have_priv)
        throw std::runtime_error("Only one of the relay's key files exists in " + data_dir.string() +
                                 ". Restore the missing file from a backup. Not generating a new identity.");

    if (have_pub) {
        public_key_ = read_file_all(pub_path);
        private_key_ = read_file_all(priv_path);
        if (public_key_.size() != CryptoEngine::sig_public_key_size() ||
            private_key_.size() != CryptoEngine::sig_secret_key_size())
            throw std::runtime_error("The relay's key files in " + data_dir.string() + " are damaged");
    } else {
        auto kp = CryptoEngine::generate_sig_keypair();
        write_file_private(priv_path, kp.private_key, true);
        write_file_private(pub_path, kp.public_key, false);
        public_key_ = kp.public_key;
        private_key_ = kp.private_key;
        identity_created_ = true;
        CryptoEngine::secure_wipe(kp.private_key);
    }
    relay_id_ = CryptoEngine::sha256(public_key_);
}

std::string RelayService::create_invite() {
    Bytes invite = CryptoEngine::random_bytes(INVITE_BYTES);
    store_->add_invite(CryptoEngine::sha256(invite), unix_now() + limits_.invite_lifetime_seconds);
    return hex_of(invite);
}

// --- Maintenance ---

size_t RelayService::sweep_once() {
    auto swept = store_->sweep(unix_now());
    rate_.prune(unix_now());
    if (swept.envelopes || swept.invites)
        log("Expired " + std::to_string(swept.envelopes) + " envelope(s), " + std::to_string(swept.invites) + " invite(s)");
    return swept.envelopes;
}

void RelayService::start_sweeper() {
    stop_sweeper_ = false;
    sweeper_ = std::thread([this] {
        while (!stop_sweeper_) {
            for (int i = 0; i < limits_.sweep_seconds * 10 && !stop_sweeper_; i++)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (stop_sweeper_) return;
            try { sweep_once(); } catch (const std::exception& e) { log(std::string("Sweep failed: ") + e.what()); }
        }
    });
}

void RelayService::stop_sweeper() {
    stop_sweeper_ = true;
    if (sweeper_.joinable()) sweeper_.join();
}

// --- Owners: one connection per mailbox ---

void RelayService::install_owner(const Bytes& mailbox, const std::shared_ptr<std::atomic<bool>>& kick) {
    std::lock_guard<std::mutex> lock(owners_mutex_);
    auto& slot = owners_[hex_of(mailbox)];
    if (slot) slot->store(true);  // a newer, authenticated connection replaces the old one
    slot = kick;
}

void RelayService::release_owner(const Bytes& mailbox, const std::shared_ptr<std::atomic<bool>>& kick) {
    std::lock_guard<std::mutex> lock(owners_mutex_);
    auto it = owners_.find(hex_of(mailbox));
    if (it != owners_.end() && it->second == kick) owners_.erase(it);
}

// Sends envelopes newer than last_seq until none are left. False if the connection failed.
bool RelayService::push_pending(socket_t sock, const Bytes& mailbox, int64_t& last_seq) {
    while (true) {
        auto batch = store_->fetch(mailbox, last_seq, unix_now(), 32);
        if (batch.empty()) return true;
        for (auto& e : batch) {
            StoredEnvelope out{e.id, static_cast<uint64_t>(e.deposited_at), e.token_hash, e.envelope};
            if (!send_message(sock, MessageType::RELAY_ENVELOPE, encode(out))) return false;
            last_seq = e.seq;
        }
    }
}

// --- One client session ---

void RelayService::handle_session(socket_t sock, const Bytes& hello_payload, const std::string& peer_ip) {
    auto hello = decode_hello(hello_payload);
    if (!hello || hello->version != WIRE_VERSION) {
        send_error(sock, "Unsupported or malformed hello (this relay speaks protocol version 3)");
        return;
    }

    // Prove we hold the relay key the client has pinned, bound to its nonce and to this session's challenge.
    Bytes challenge = CryptoEngine::random_bytes(NONCE_BYTES);
    HelloReply reply;
    reply.relay_public_key = public_key_;
    reply.auth_challenge = challenge;
    reply.signature = CryptoEngine::sign(hello_signing_input(hello->client_nonce, relay_id_, WIRE_VERSION, challenge), private_key_);
    if (!send_message(sock, MessageType::RELAY_HELLO_REPLY, encode(reply))) return;

    std::optional<Bytes> mailbox;  // set once the client has proven it owns one
    auto kick = std::make_shared<std::atomic<bool>>(false);
    bool challenge_used = false, collecting = false, is_owner = false;
    auto release = make_scope_exit([&] { if (mailbox && is_owner) release_owner(*mailbox, kick); });
    int64_t last_seq = 0;
    auto last_activity = std::chrono::steady_clock::now();

    while (true) {
        if (kick->load()) {
            send_error(sock, "Another client signed in to this mailbox");
            return;
        }
        if (std::chrono::steady_clock::now() - last_activity > std::chrono::seconds(limits_.idle_timeout_seconds)) return;

        if (wait_readable(sock, limits_.poll_millis)) {
            auto msg = recv_message(sock, MAX_MESSAGE_PAYLOAD);
            if (!msg) return;
            last_activity = std::chrono::steady_clock::now();
            const int64_t now = unix_now();

            switch (msg->type) {
                case MessageType::RELAY_PING:
                    if (!send_message(sock, MessageType::RELAY_PONG, {})) return;
                    break;

                case MessageType::RELAY_REGISTER: {
                    auto m = decode_register(msg->payload);
                    if (!m) { send_error(sock, "Malformed register request"); return; }
                    if (!rate_.allow("reg:" + peer_ip, 10, now)) { send_error(sock, "Too many attempts, try again later"); break; }
                    if (m->access_public_key.size() != CryptoEngine::sig_public_key_size()) { send_error(sock, "Invalid access key"); break; }
                    // Proof that the client holds the private half, so nobody can register someone else's key.
                    if (!CryptoEngine::verify(register_signing_input(relay_id_, m->mailbox_id, m->access_public_key, m->send_token_hash),
                                              m->signature, m->access_public_key)) {
                        send_error(sock, "Invalid proof of key ownership");
                        break;
                    }
                    switch (store_->register_mailbox(CryptoEngine::sha256(m->invite), m->mailbox_id, m->access_public_key,
                                                     m->send_token_hash, now, limits_.max_mailboxes)) {
                        case RelayStore::RegisterResult::Ok:
                            log("Mailbox registered: " + short_id(m->mailbox_id));
                            if (!send_message(sock, MessageType::RELAY_REGISTER_OK, {})) return;
                            break;
                        case RelayStore::RegisterResult::BadInvite: send_error(sock, "Invalid, used or expired invite"); break;
                        case RelayStore::RegisterResult::MailboxExists: send_error(sock, "That mailbox already exists"); break;
                        case RelayStore::RegisterResult::LimitReached: send_error(sock, "This relay is full"); break;
                    }
                    break;
                }

                case MessageType::RELAY_AUTH: {
                    auto m = decode_auth(msg->payload);
                    if (!m) { send_error(sock, "Malformed auth request"); return; }
                    // One attempt per connection, then the challenge is spent: no grinding, no replay.
                    if (challenge_used) { send_error(sock, "Reconnect to authenticate again"); return; }
                    challenge_used = true;
                    auto key = store_->access_key(m->mailbox_id);
                    if (!key || !CryptoEngine::verify(auth_signing_input(challenge, relay_id_, m->mailbox_id), m->signature, *key)) {
                        log("Authentication failed from " + peer_ip);
                        send_error(sock, "Authentication failed");
                        return;
                    }
                    mailbox = m->mailbox_id;
                    if (!send_message(sock, MessageType::RELAY_AUTH_OK, {})) return;
                    break;
                }

                case MessageType::RELAY_DEPOSIT: {
                    auto m = decode_deposit(msg->payload);
                    if (!m) { send_error(sock, "Malformed deposit"); return; }
                    if (m->ttl_seconds < MIN_TTL_SECONDS) { send_error(sock, "Invalid lifetime"); break; }
                    if (!rate_.allow("dep-ip:" + peer_ip, limits_.rate_limit_per_minute, now)) { send_error(sock, "Too many deposits, slow down"); break; }
                    Bytes token_hash = CryptoEngine::sha256(m->send_token);
                    // The same answer for "no such mailbox" and "wrong token", so mailbox IDs can't be probed.
                    if (!store_->token_valid(m->mailbox_id, token_hash)) { send_error(sock, "Unknown mailbox or token"); break; }
                    if (!rate_.allow("dep-tok:" + hex_of(token_hash), limits_.rate_limit_per_minute, now)) { send_error(sock, "Too many deposits with this token"); break; }

                    Bytes envelope_id = CryptoEngine::random_bytes(ENVELOPE_ID_BYTES);
                    uint32_t ttl = m->ttl_seconds > MAX_TTL_SECONDS ? MAX_TTL_SECONDS : m->ttl_seconds;
                    if (store_->deposit(m->mailbox_id, envelope_id, m->envelope, token_hash, now, ttl, limits_.mailbox_quota_bytes) ==
                        RelayStore::DepositResult::MailboxFull) {
                        send_error(sock, "Mailbox is full");
                        break;
                    }
                    if (!send_message(sock, MessageType::RELAY_DEPOSIT_OK, encode(IdList{{envelope_id}}))) return;
                    break;
                }

                case MessageType::RELAY_COLLECT:
                    if (!mailbox) { send_error(sock, "Sign in first"); break; }
                    // Only the connection that receives deliveries is "the" owner connection: a newer one
                    // replaces it. Other signed-in connections (acknowledging, managing tokens) coexist.
                    if (!is_owner) { install_owner(*mailbox, kick); is_owner = true; }
                    collecting = true;
                    last_seq = 0;  // a new collect re-sends anything not yet acknowledged
                    if (!push_pending(sock, *mailbox, last_seq)) return;
                    if (!send_message(sock, MessageType::RELAY_COLLECT_END, {})) return;
                    break;

                case MessageType::RELAY_ACK: {
                    if (!mailbox) { send_error(sock, "Sign in first"); break; }
                    auto m = decode_id_list(msg->payload);
                    if (!m) { send_error(sock, "Malformed acknowledgement"); return; }
                    std::vector<uint8_t> count;
                    write_u32(count, static_cast<uint32_t>(store_->ack(*mailbox, m->ids)));  // only this mailbox's envelopes
                    if (!send_message(sock, MessageType::RELAY_ACK_OK, count)) return;
                    break;
                }

                case MessageType::RELAY_TOKEN_ADD:
                case MessageType::RELAY_TOKEN_REVOKE: {
                    if (!mailbox) { send_error(sock, "Sign in first"); break; }
                    auto m = decode_hash_op(msg->payload);
                    if (!m) { send_error(sock, "Malformed token request"); return; }
                    if (msg->type == MessageType::RELAY_TOKEN_ADD) {
                        if (store_->add_token(*mailbox, m->token_hash, now, limits_.max_tokens_per_mailbox) !=
                            RelayStore::TokenResult::Ok) {
                            send_error(sock, "Too many send tokens on this mailbox");
                            break;
                        }
                    } else {
                        store_->revoke_token(*mailbox, m->token_hash);
                    }
                    if (!send_message(sock, MessageType::RELAY_TOKEN_OK, {})) return;
                    break;
                }

                default:
                    send_error(sock, "Unexpected message");
                    return;
            }
        }

        // Push anything that arrived since we last looked.
        if (collecting && mailbox && !push_pending(sock, *mailbox, last_seq)) return;
    }
}

}  // namespace relay
