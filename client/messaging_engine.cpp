#include "messaging_engine.h"

#include "crypto_engine.h"
#include "protocol.h"
#include "scope_exit.h"

#include <algorithm>
#include <ctime>
#include <map>
#include <thread>

namespace fs = std::filesystem;

namespace {

int64_t unix_now() { return static_cast<int64_t>(std::time(nullptr)); }

constexpr size_t MAX_PENDING_REQUESTS = 100;
constexpr size_t MAX_PENDING_GROUP_INVITES = 50;
// Introduced bundles (about 6.5 KB each) that ride in one invitation envelope. The first envelope to someone
// also carries our own bundle and a token grant, so this is kept well under what fits in 64 KiB.
constexpr size_t INTRODUCED_PER_ENVELOPE = 6;
constexpr int OUTBOX_KIND_MESSAGE = 0;
constexpr int OUTBOX_KIND_RECEIPT = 1;
constexpr int OUTBOX_KIND_GRANTS = 2;  // a job to make send tokens for group members, then Forward records to the creator
constexpr int OUTBOX_KIND_ATTACHMENT = 5;  // a message with a file: the record, then this recipient's file ID, key and token
constexpr int OUTBOX_KIND_UPLOAD = 6;      // a file to upload (the item's contact_fp holds the file's ID in hex)
constexpr int OUTBOX_KIND_ARCHIVE = 4;

// One recipient's file ID, key and token, as queued next to the message record until the envelope is sealed.
static std::vector<uint8_t> encode_grant(const std::vector<uint8_t>& file_id, const std::vector<uint8_t>& key, const std::vector<uint8_t>& token) {
    std::vector<uint8_t> b;
    write_blob(b, file_id);
    write_blob(b, key);
    write_blob(b, token);
    return b;
}
static std::optional<chat::AttachmentGrant> decode_grant(const std::vector<uint8_t>& b) {
    size_t off = 0;
    auto id = read_blob(b.data(), b.size(), off, 16);
    auto key = read_blob(b.data(), b.size(), off, 32);
    auto token = read_blob(b.data(), b.size(), off, 32);
    if (!id || !key || !token || id->size() != 16 || key->size() != 32 || token->size() != 32 || off != b.size()) return std::nullopt;
    return chat::AttachmentGrant{std::move(*id), std::move(*key), std::move(*token)};
}  // a record to add to a chat's archive (the item's contact_fp holds the chat's ID in hex)
constexpr int OUTBOX_KIND_RELAY = 3;   // an already-sealed envelope to deposit as it is (the creator passing one on)
constexpr size_t FORWARDS_PER_ENVELOPE = 4;  // each carries a sealed envelope of about 5 KB

bool all_zero(const std::vector<uint8_t>& b) {
    return std::all_of(b.begin(), b.end(), [](uint8_t x) { return x == 0; });
}

std::string short_fp(const std::string& fp) { return fp.substr(0, 16); }

}  // namespace

int64_t MessagingEngine::retry_delay(int attempts) const {
    int64_t delay = std::max(1, options_.retry_base_seconds);
    for (int i = 0; i < attempts && delay < 600; i++) delay *= 2;
    return std::min<int64_t>(delay, 600);
}

MessagingEngine::MessagingEngine(KeyStore& keys, const fs::path& history_path, const Options& options)
    : keys_(keys), options_(options) {
    if (keys_.private_keys_locked()) throw std::runtime_error("Your keys are locked. Unlock them first");
    kem_private_ = keys_.load_private_kem();
    dsa_private_ = keys_.load_private_dsa();
    if (kem_private_.size() != CryptoEngine::kem_secret_key_size() || dsa_private_.size() != CryptoEngine::sig_secret_key_size())
        throw std::runtime_error("Your keys could not be loaded");

    Bytes history_key = keys_.derive_local_key("history key");
    auto wipe = make_scope_exit([&] { CryptoEngine::secure_wipe(history_key); });
    if (history_key.empty()) throw std::runtime_error("Your keys could not be loaded");
    history_ = std::make_unique<HistoryStore>(history_path, history_key);
    // The first look for chats that need an archive comes one interval after start, not at once: starting up
    // has enough to do already.
    next_archive_check_ = std::chrono::steady_clock::now() + std::chrono::seconds(std::max(1, options_.archive_check_seconds));
    next_keyring_check_ = std::chrono::steady_clock::now() + std::chrono::seconds(std::max(1, options_.keyring_check_seconds));
    next_deletion_check_ = std::chrono::steady_clock::now() + std::chrono::seconds(std::max(1, options_.archive_sync_seconds));
    next_attachment_check_ = std::chrono::steady_clock::now() + std::chrono::seconds(std::max(1, options_.archive_sync_seconds));
    history_->reset_downloading();  // nothing is being fetched after a restart

    my_fp_hex_ = keys_.own_fingerprint();
    auto fp = hex_to_bytes(my_fp_hex_);
    if (!fp || fp->size() != 32) throw std::runtime_error("Your keys could not be loaded");
    my_fp_ = std::move(*fp);
}

MessagingEngine::~MessagingEngine() {
    stop_transfers();
    CryptoEngine::secure_wipe(kem_private_);
    CryptoEngine::secure_wipe(dsa_private_);
}

// --- small shared pieces ---

void MessagingEngine::notify(const std::string& line) {
    std::lock_guard<std::mutex> lock(mutex_);
    notices_.push_back(line);
    if (notices_.size() > 200) notices_.erase(notices_.begin());
}

void MessagingEngine::set_status(const std::string& s) {
    std::lock_guard<std::mutex> lock(mutex_);
    status_ = s;
}

std::string MessagingEngine::status() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return status_;
}

std::vector<std::string> MessagingEngine::take_notices() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> out;
    out.swap(notices_);
    return out;
}

void MessagingEngine::set_display_name(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    display_name_ = name.substr(0, IdentityBundle::MAX_DISPLAY_NAME_BYTES);
}

bool MessagingEngine::is_set_up() const { return keys_.has_access_key() && keys_.load_mailbox_config().has_value(); }

// Connects to our relay and signs in to our mailbox, with a fresh connection that is not collecting.
bool MessagingEngine::connect_authenticated(RelayClient& client, std::string& error) {
    auto config = keys_.load_mailbox_config();
    if (!config || !keys_.has_access_key()) {
        error = "Messaging is not set up yet";
        return false;
    }
    Bytes access_private = keys_.load_access_private();
    auto wipe = make_scope_exit([&] { CryptoEngine::secure_wipe(access_private); });
    if (access_private.empty()) {
        error = "Your mailbox key could not be read (are your keys unlocked?)";
        return false;
    }
    return client.connect(config->host, config->port, config->relay_id, options_.connect_timeout_seconds, error) &&
           client.authenticate(config->mailbox_id, access_private, error);
}

MessagingEngine::Bytes MessagingEngine::own_bundle_raw() {
    auto config = keys_.load_mailbox_config();
    BundleAddress address;
    std::string name;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        name = display_name_;
    }
    if (config) {
        address.relay_hint = format_server_address(ServerAddress{config->host, config->port});
        address.relay_id = config->relay_id;
        address.mailbox_id = config->mailbox_id;
    }
    return keys_.make_own_bundle(name, address);
}

// --- People we can verify and write to ---

MessagingEngine::Peer MessagingEngine::peer_from_contact(const KeyStore::Contact& c) {
    Peer p;
    p.fp = c.fingerprint;
    p.name = c.name;
    p.pub_dsa = c.pub_dsa;
    p.pub_kem = c.pub_kem;
    p.relay_address = c.relay_address;
    p.relay_id = c.relay_id;
    p.mailbox_id = c.mailbox_id;
    p.send_token = c.send_token;
    p.is_contact = true;
    p.keys_verified = c.kem_verified;
    p.can_send = c.can_message();
    return p;
}

// A contact, or failing that someone a group creator introduced (their bundle is self-signed, so
// their keys can be checked, but nobody has given us a send token for them yet).
std::optional<MessagingEngine::Peer> MessagingEngine::resolve_peer(const std::string& fp, const Bytes& conversation_id) {
    std::optional<Peer> found;
    if (auto contact = keys_.find_contact_by_fingerprint(fp)) found = peer_from_contact(*contact);
    else found = [&]() -> std::optional<Peer> {
    auto row = history_->introduced(fp);
    if (!row) return std::nullopt;
    auto bundle = parse_identity_bundle(row->bundle);
    if (!bundle || bundle->fingerprint() != fp) return std::nullopt;
    Peer p;
    p.fp = fp;
    p.name = bundle->display_name.empty() ? short_fp(fp) + "..." : bundle->display_name;
    p.pub_dsa = bundle->signing_key;
    p.pub_kem = bundle->encryption_key;
    if (bundle->has_mailbox()) {
        p.relay_address = bundle->relay_hint;
        p.relay_id = bundle->relay_id;
        p.mailbox_id = bundle->mailbox_id;
    }
    p.is_contact = false;
    p.keys_verified = true;  // a bundle is self-signed
    p.can_send = false;      // until a member gives us a token (below)
    return p;
    }();
    if (!found) return std::nullopt;

    // A token a member gave us for this group lets us write to them even if we have no other way to.
    if (!found->can_send && !conversation_id.empty() && found->keys_verified && !found->relay_address.empty() &&
        found->relay_id.size() == 32 && found->mailbox_id.size() == 16) {
        if (auto token = history_->member_token(conversation_id, fp); token && token->size() == relay::SEND_TOKEN_BYTES) {
            found->send_token = *token;
            found->can_send = true;
        }
    }
    return found;
}

std::string MessagingEngine::person_name(const std::string& fp) {
    if (auto contact = keys_.find_contact_by_fingerprint(fp)) return contact->name;
    return short_fp(fp) + "...";
}

MessagingEngine::GroupMember MessagingEngine::member_info(const std::string& fp, const Bytes& conversation_id) {
    GroupMember m;
    m.fp = fp;
    const bool verified = history_->is_verified(fp);
    if (auto peer = resolve_peer(fp, conversation_id)) {
        m.name = peer->name;
        m.is_contact = peer->is_contact;
        m.can_send = peer->can_send;
        if (!peer->is_contact) {
            if (auto row = history_->introduced(fp)) m.introduced_by = person_name(row->introduced_by);
        }
        m.trust = verified ? Trust::Verified : (peer->is_contact ? Trust::Contact : Trust::Introduced);
    } else {
        m.name = short_fp(fp) + "...";
    }
    switch (m.trust) {
        case Trust::Verified: m.label = "Verified by you"; break;
        case Trust::Contact: m.label = "Contact"; break;
        case Trust::Introduced: m.label = "Introduced by " + (m.introduced_by.empty() ? std::string("the group's creator") : m.introduced_by); break;
        case Trust::Unknown: m.label = "Unknown"; break;
    }
    return m;
}

bool MessagingEngine::set_verified(const std::string& fp, bool verified) {
    if (!keys_.find_contact_by_fingerprint(fp) && !history_->introduced(fp)) return false;  // we don't know them
    history_->set_verified(fp, verified, unix_now());
    bump();
    return true;
}

bool MessagingEngine::is_verified(const std::string& fp) { return history_->is_verified(fp); }

// --- Setting up and cards ---

bool MessagingEngine::setup(const RelayInvite& invite, std::string& error) {
    if (is_set_up()) {
        error = "Messaging is already set up";
        return false;
    }
    RelayClient client;
    if (!client.connect(invite.server.host, invite.server.port, invite.relay_id, options_.connect_timeout_seconds, error)) return false;

    try {
        if (!keys_.has_access_key()) keys_.create_access_key();
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
    CryptoEngine::SigKeyPair access{keys_.load_access_public(), keys_.load_access_private()};
    auto wipe = make_scope_exit([&] { CryptoEngine::secure_wipe(access.private_key); });
    if (access.public_key.empty() || access.private_key.empty()) {
        error = "Your mailbox key could not be created";
        return false;
    }

    Bytes mailbox_id = CryptoEngine::random_bytes(relay::MAILBOX_ID_BYTES);
    Bytes first_token = CryptoEngine::random_bytes(relay::SEND_TOKEN_BYTES);  // not handed to anyone
    if (!client.register_mailbox(invite.invite, mailbox_id, access, first_token, error)) return false;

    KeyStore::MailboxConfig config{invite.server.host, invite.server.port, invite.relay_id, mailbox_id};
    keys_.save_mailbox_config(config);

    // The receive connection belongs to the pump thread, which notices the new configuration on
    // its next turn. Nothing here touches it.
    set_status("Not connected");
    bump();
    return true;
}

bool MessagingEngine::create_relay_invite(std::string& invite, std::string& error) {
    auto config = keys_.load_mailbox_config();
    if (!config) {
        error = "Set up messaging first";
        return false;
    }
    RelayClient client;
    Bytes code;
    if (!connect_authenticated(client, error) || !client.create_invite(code, error)) return false;
    RelayInvite result;
    result.server = ServerAddress{config->host, config->port};
    result.relay_id = config->relay_id;
    result.invite = std::move(code);
    invite = build_relay_invite(result);
    return true;
}

bool MessagingEngine::relay_invite_status(RelayInviteStatus& status, std::string& error) {
    if (!keys_.load_mailbox_config()) {
        error = "Set up messaging first";
        return false;
    }
    RelayClient client;
    relay::InviteStatus raw;
    if (!connect_authenticated(client, error) || !client.list_invites(raw, error)) return false;
    status = RelayInviteStatus();
    status.max_unused = raw.max_unused;
    status.max_total = raw.max_total;
    for (const auto& u : raw.unused) status.unused.push_back({bytes_to_hex(u.hash), static_cast<int64_t>(u.expires_at)});
    for (const auto& j : raw.joined) status.joined.push_back({bytes_to_hex(j.mailbox_id).substr(0, 8), static_cast<int64_t>(j.joined_at)});
    return true;
}

bool MessagingEngine::cancel_relay_invite(const std::string& id, std::string& error) {
    auto hash = hex_to_bytes(id);
    if (!hash || hash->size() != relay::HASH_BYTES) {
        error = "That isn't an invite";
        return false;
    }
    RelayClient client;
    return connect_authenticated(client, error) && client.cancel_invite(*hash, error);
}

bool MessagingEngine::make_card(const std::string& label, std::string& card, std::string& error) {
    auto config = keys_.load_mailbox_config();
    if (!config) {
        error = "Set up messaging first";
        return false;
    }
    Bytes token = CryptoEngine::random_bytes(relay::SEND_TOKEN_BYTES);
    Bytes hash = CryptoEngine::sha256(token);

    RelayClient client;
    if (!connect_authenticated(client, error) || !client.add_token(hash, error)) return false;
    history_->add_issued_token(hash, label.empty() ? "unnamed card" : label, "", unix_now());

    try {
        card = encode_contact_card_v3(own_bundle_raw(), token);
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
    bump();
    return true;
}

std::vector<MessagingEngine::IssuedToken> MessagingEngine::issued_tokens() {
    std::vector<IssuedToken> out;
    for (auto& t : history_->issued_tokens()) out.push_back({t.hash, t.label, t.created_at, t.bound_fp, t.revoked});
    return out;
}

bool MessagingEngine::revoke_token(const Bytes& hash, std::string& error) {
    RelayClient client;
    if (!connect_authenticated(client, error) || !client.revoke_token(hash, error)) return false;
    history_->mark_token_revoked(hash);
    bump();
    return true;
}

int MessagingEngine::revoke_tokens_for(const std::string& contact_fp, std::string& error) {
    std::vector<IssuedToken> mine;
    for (auto& t : history_->issued_tokens())
        if (t.bound_fp == contact_fp && !t.revoked) mine.push_back({t.hash, t.label, t.created_at, t.bound_fp, t.revoked});
    if (mine.empty()) return 0;

    RelayClient client;
    if (!connect_authenticated(client, error)) return -1;
    int revoked = 0;
    for (const auto& t : mine) {
        if (!client.revoke_token(t.hash, error)) return -1;
        history_->mark_token_revoked(t.hash);
        revoked++;
    }
    bump();
    return revoked;
}

// --- Reading ---

std::vector<MessagingEngine::ChatSummary> MessagingEngine::chats() {
    std::vector<ChatSummary> out;
    for (const auto& name : keys_.list_contacts()) {
        auto contact = keys_.load_contact(name);
        if (!contact) continue;
        ChatSummary s;
        s.contact_name = name;
        s.contact_fp = contact->fingerprint;
        s.can_send = contact->can_message();
        s.verified = history_->is_verified(contact->fingerprint);
        if (!contact->kem_verified) s.cannot_send_reason = "Their encryption key isn't verified. Ask them for a new contact card.";
        else if (contact->relay_address.empty()) s.cannot_send_reason = "They haven't shared a messaging address. Ask them for a new contact card.";
        else if (contact->send_token.size() != 32) s.cannot_send_reason = "You don't have permission to message them yet. Ask them for a new contact card.";
        if (auto conv = history_->conversation_for(contact->fingerprint)) {
            s.unread = history_->unread_count(conv->id);
            s.last_activity = conv->last_activity;
        }
        out.push_back(std::move(s));
    }
    std::sort(out.begin(), out.end(), [](const ChatSummary& a, const ChatSummary& b) {
        if (a.last_activity != b.last_activity) return a.last_activity > b.last_activity;
        return a.contact_name < b.contact_name;
    });
    return out;
}

std::vector<MessagingEngine::ChatMessage> MessagingEngine::messages(const std::string& contact_fp, size_t limit) {
    std::vector<ChatMessage> out;
    auto conv = history_->conversation_for(contact_fp);
    if (!conv) return out;
    for (auto& m : history_->messages(conv->id, limit)) {
        if (m.deleted) {  // removed by agreement: its place stays, its content is gone
            ChatMessage gone;
            gone.row = m.row;
            gone.outgoing = m.outgoing;
            gone.sent_at = m.sent_at;
            gone.status = m.status;
            gone.deleted = true;
            out.push_back(std::move(gone));
            continue;
        }
        auto record = chat::parse_record(m.record);
        if (!record || (record->record.type != chat::RecordType::Text && record->record.type != chat::RecordType::Attachment)) continue;
        ChatMessage cm;
        cm.row = m.row;
        cm.outgoing = m.outgoing;
        cm.sent_at = m.sent_at;
        cm.text.assign(record->record.payload.begin(), record->record.payload.end());
        if (record->record.type == chat::RecordType::Attachment) {
            auto info = chat::parse_attachment_payload(record->record.payload);
            if (!info) continue;
            cm.is_attachment = true;
            cm.attachment = attachment_view(*info);
            cm.text = info->caption;
        }
        cm.status = m.status;
        cm.gap = m.gap;
        out.push_back(std::move(cm));
    }
    std::stable_sort(out.begin(), out.end(), [](const ChatMessage& a, const ChatMessage& b) {
        return a.sent_at != b.sent_at ? a.sent_at < b.sent_at : a.row < b.row;
    });
    return out;
}

bool MessagingEngine::receipts_enabled(const std::string& contact_fp, bool* delivery, bool* read) {
    auto conv = history_->conversation_for(contact_fp);
    if (delivery) *delivery = conv ? conv->send_delivery_receipts : true;
    if (read) *read = conv ? conv->send_read_receipts : true;
    return conv.has_value();
}

void MessagingEngine::set_receipts(const std::string& contact_fp, bool delivery, bool read) {
    auto fp = hex_to_bytes(contact_fp);
    if (!fp || fp->size() != 32) return;
    auto conv = history_->ensure_conversation(chat::conversation_id_for(my_fp_, *fp), contact_fp, unix_now());
    history_->set_receipt_settings(conv.id, delivery, read);
}

// --- Writing ---

bool MessagingEngine::send_text(const std::string& contact_fp, const std::string& text, std::string& error) {
    if (text.empty()) { error = "There is nothing to send"; return false; }
    if (text.size() > chat::MAX_TEXT_BYTES) { error = "That message is too long (32 KiB at most)"; return false; }
    auto contact = keys_.find_contact_by_fingerprint(contact_fp);
    if (!contact) { error = "That contact isn't in your list"; return false; }
    if (!contact->kem_verified) { error = "Their encryption key isn't verified. Ask them for a new contact card."; return false; }
    if (!contact->can_message()) { error = "You don't have their messaging address yet. Ask them for a new contact card."; return false; }
    auto their_fp = hex_to_bytes(contact_fp);
    if (!their_fp || their_fp->size() != 32) { error = "That contact isn't valid"; return false; }

    const int64_t now = unix_now();
    auto conv = history_->ensure_conversation(chat::conversation_id_for(my_fp_, *their_fp), contact_fp, now);

    chat::Record r;
    r.conversation_id = conv.id;
    r.message_id = CryptoEngine::random_bytes(chat::ID_BYTES);
    r.sender = my_fp_;
    r.recipients_hash = chat::recipients_hash_for({my_fp_, *their_fp});
    r.sent_at = static_cast<uint64_t>(now);
    r.type = chat::RecordType::Text;
    r.payload.assign(text.begin(), text.end());
    r.own_prev = history_->last_entry_hash(conv.id, true).value_or(Bytes());
    if (auto last_received = history_->last_entry_hash(conv.id, false)) r.seen.push_back(*last_received);

    Bytes raw;
    try {
        raw = chat::sign_record(r, dsa_private_);
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
    auto parsed = chat::parse_record(raw);
    if (!parsed) { error = "Could not sign the message"; return false; }

    HistoryStore::Message m;
    m.conversation_id = conv.id;
    m.message_id = r.message_id;
    m.outgoing = true;
    m.sent_at = now;
    m.received_at = now;
    m.status = HistoryStore::Queued;
    m.entry_hash = parsed->entry_hash;
    m.record = raw;
    history_->add_message(m);
    history_->enqueue(contact_fp, OUTBOX_KIND_MESSAGE, r.message_id, {raw}, now, now);
    queue_archive_entry(conv.id, raw, r.message_id);
    bump();
    return true;
}

void MessagingEngine::enqueue_receipt(const std::string& contact_fp, chat::ReceiptKind kind, const std::vector<Bytes>& ids, bool delayed) {
    auto their_fp = hex_to_bytes(contact_fp);
    if (!their_fp || their_fp->size() != 32) return;
    enqueue_receipt_in(chat::conversation_id_for(my_fp_, *their_fp), chat::recipients_hash_for({my_fp_, *their_fp}), contact_fp, kind, ids, delayed);
}

// A receipt goes only to the author of the messages it covers, whatever conversation they are in.
void MessagingEngine::enqueue_receipt_in(const Bytes& conversation_id, const Bytes& recipients_hash, const std::string& to_fp,
                                         chat::ReceiptKind kind, const std::vector<Bytes>& ids, bool delayed) {
    auto peer = resolve_peer(to_fp, conversation_id);
    if (!peer || !peer->can_send || ids.empty()) return;

    // At most 256 messages per receipt record.
    for (size_t start = 0; start < ids.size(); start += 256) {
        std::vector<Bytes> chunk(ids.begin() + static_cast<std::ptrdiff_t>(start),
                                 ids.begin() + static_cast<std::ptrdiff_t>(std::min(ids.size(), start + 256)));
        chat::Record r;
        r.conversation_id = conversation_id;
        r.message_id = CryptoEngine::random_bytes(chat::ID_BYTES);
        r.sender = my_fp_;
        r.recipients_hash = recipients_hash;
        r.sent_at = static_cast<uint64_t>(unix_now());
        r.type = chat::RecordType::Receipt;
        r.payload = chat::receipt_payload(kind, chunk);
        try {
            Bytes raw = chat::sign_record(r, dsa_private_);
            int64_t due = unix_now();
            if (delayed && options_.receipt_delay_max_seconds > 0) {
                Bytes rnd = CryptoEngine::random_bytes(2);
                due += static_cast<int64_t>((rnd[0] * 256 + rnd[1]) % (options_.receipt_delay_max_seconds + 1));
            }
            history_->enqueue(to_fp, OUTBOX_KIND_RECEIPT, r.message_id, {raw}, due, unix_now());
        } catch (const std::exception&) {
        }
    }
}

void MessagingEngine::mark_read(const std::string& contact_fp) {
    auto conv = history_->conversation_for(contact_fp);
    if (!conv) return;
    auto ids = history_->mark_all_read(conv->id);
    if (ids.empty()) return;
    if (conv->send_read_receipts) enqueue_receipt(contact_fp, chat::ReceiptKind::Read, ids, false);
    bump();
}

// --- Receiving ---

void MessagingEngine::note_token_use(const Bytes& token_hash, const std::string& sender_fp) {
    if (token_hash.size() != 32 || all_zero(token_hash)) return;
    auto token = history_->find_issued_token(token_hash);
    if (!token) return;
    if (token->bound_fp.empty()) {
        history_->bind_issued_token(token_hash, sender_fp);
        return;
    }
    if (token->bound_fp == sender_fp) return;

    const std::string key = "forwarded:" + bytes_to_hex(token_hash) + ":" + sender_fp;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!told_about_.insert(key).second) return;
    }
    notify("The contact card you made for \"" + token->label + "\" was first used by one person (" + short_fp(token->bound_fp) +
           "...) and has now been used by someone else (" + short_fp(sender_fp) +
           "...). It may have been passed on. You can revoke it under Cards issued.");
}

bool MessagingEngine::handle_record(const KeyStore::Contact& contact, const chat::SignedRecord& sr, bool delayed_receipt) {
    auto their_fp = hex_to_bytes(contact.fingerprint);
    if (!their_fp || their_fp->size() != 32 || sr.record.sender != *their_fp) return false;

    // Not our one-to-one conversation with them: it may belong to a group we are both in.
    const Bytes conv_id = chat::conversation_id_for(my_fp_, *their_fp);
    if (sr.record.conversation_id != conv_id) return handle_group_record(peer_from_contact(contact), sr, delayed_receipt);
    // Otherwise it must be for exactly us two, or it has been redirected.
    if (sr.record.recipients_hash != chat::recipients_hash_for({my_fp_, *their_fp})) return false;

    const int64_t now = unix_now();
    switch (sr.record.type) {
        case chat::RecordType::Text:
        case chat::RecordType::Attachment: {
            if (sr.record.type == chat::RecordType::Attachment && !chat::parse_attachment_payload(sr.record.payload)) return false;
            history_->ensure_conversation(conv_id, contact.fingerprint, now);
            HistoryStore::Message m;
            m.conversation_id = conv_id;
            m.message_id = sr.record.message_id;
            m.outgoing = false;
            m.sent_at = static_cast<int64_t>(sr.record.sent_at);
            m.received_at = now;
            m.status = 0;
            m.entry_hash = sr.entry_hash;
            m.record = sr.raw;
            // They pointed at an earlier message of theirs that we never saw: something went missing.
            m.gap = !sr.record.own_prev.empty() && !history_->has_entry(conv_id, sr.record.own_prev);
            if (!history_->add_message(m)) {  // a duplicate or replay (but an attachment's envelope may bring the key its archived copy lacked)
                if (sr.record.type == chat::RecordType::Attachment && !envelope_grants_.empty()) note_incoming_attachment(sr, envelope_grants_);
                return false;
            }
            if (m.gap) archive_sync_now_.insert(bytes_to_hex(conv_id));  // the archive may have what went missing
            if (sr.record.type == chat::RecordType::Attachment) note_incoming_attachment(sr, envelope_grants_);
            auto conv = history_->conversation_for(contact.fingerprint);
            if (conv && conv->send_delivery_receipts) enqueue_receipt(contact.fingerprint, chat::ReceiptKind::Delivered, {m.message_id}, delayed_receipt);
            return true;
        }
        case chat::RecordType::Receipt: {
            auto info = chat::parse_receipt_payload(sr.record.payload);
            if (!info) return false;
            const int status = info->kind == chat::ReceiptKind::Read ? HistoryStore::Read : HistoryStore::Delivered;
            bool changed = false;
            for (const auto& id : info->message_ids) changed |= history_->raise_delivery(conv_id, id, contact.fingerprint, status);
            return changed;
        }
        case chat::RecordType::ArchiveGrant:
            return receive_archive_grant(peer_from_contact(contact), sr);
        case chat::RecordType::DeleteRequest:
            return receive_deletion_request(peer_from_contact(contact), sr);
        case chat::RecordType::DeleteAccept:
            return receive_deletion_accept(peer_from_contact(contact), sr);
        case chat::RecordType::Checkpoint:  // these live only in an archive, never in an envelope
        case chat::RecordType::Conversation:
        case chat::RecordType::Forward:
            return false;  // these belong to a group, not to a one-to-one conversation
        case chat::RecordType::TokenGrant: {
            if (sr.record.payload.size() != 32) return false;
            try {
                keys_.save_contact_token(contact.name, sr.record.payload);
            } catch (const std::exception&) {
                return false;
            }
            return true;
        }
    }
    return false;
}

// A token grant sealed by one member for another is deposited by the group's creator, so the send
// token it arrives with is the creator's, and says nothing about who wrote it.
static bool only_group_grants(const std::vector<chat::SignedRecord>& records) {
    for (const auto& sr : records)
        if (sr.record.type != chat::RecordType::TokenGrant) return false;
    return !records.empty();
}

bool MessagingEngine::process_envelope(const relay::StoredEnvelope& envelope) {
    auto inner = chat::open_envelope(envelope.envelope, kem_private_);
    if (!inner) return true;  // not for us, or damaged: nothing to keep, so let the relay delete it
    envelope_grants_ = inner->grants;  // file keys and tokens for any attachments in it, for note_incoming_attachment
    auto forget_grants = make_scope_exit([&] { envelope_grants_.clear(); });

    std::optional<IdentityBundle> bundle;
    if (!inner->sender_bundle.empty()) bundle = parse_identity_bundle(inner->sender_bundle);

    std::vector<chat::SignedRecord> records;
    for (const auto& raw : inner->records)
        if (auto sr = chat::parse_record(raw)) records.push_back(std::move(*sr));
    if (records.empty()) return true;

    const Bytes sender = records.front().record.sender;
    const std::string sender_hex = bytes_to_hex(sender);
    if (sender == my_fp_) return true;  // we never write to ourselves

    auto contact = keys_.find_contact_by_fingerprint(sender_hex);
    if (contact) {
        // A newer bundle from someone we already know updates their keys and address.
        if (bundle && bundle->fingerprint() == sender_hex) {
            auto imported = keys_.import_bundle_for_known_identity(*bundle);
            if (imported.result == KeyStore::BundleImportResult::Updated) {
                contact = keys_.find_contact_by_fingerprint(sender_hex);
                if (imported.encryption_key_changed) notify(contact->name + " is using a new encryption key.");
            }
        }
        bool changed = false;
        for (const auto& sr : records) {
            if (sr.record.sender != sender) continue;
            if (!chat::verify_record(sr, contact->pub_dsa)) continue;  // forged, or not from them
            if (sr.record.type == chat::RecordType::Conversation) changed |= receive_group_invite(*contact, sr, inner->introduced);
            else changed |= handle_record(*contact, sr, true);
        }
        if (!only_group_grants(records)) note_token_use(envelope.token_hash, sender_hex);
        if (changed) bump();
        return true;
    }

    // Not a contact, but maybe someone a group creator introduced, writing to a group we are in
    // or have been invited to. (Anything else they send falls through to the request path below.)
    if (auto member = resolve_peer(sender_hex)) {
        bool for_a_group = false;
        for (const auto& sr : records) {
            auto conv = history_->conversation(sr.record.conversation_id);
            if ((conv && conv->kind == HistoryStore::Group) || history_->group_invite(sr.record.conversation_id)) for_a_group = true;
        }
        if (for_a_group) {
            if (bundle && bundle->fingerprint() == sender_hex) {  // a newer bundle replaces the one we hold
                const Bytes old_key = member->pub_kem;
                history_->save_introduced(sender_hex, bundle->raw, static_cast<int64_t>(bundle->issued_at), std::string(), unix_now());
                member = resolve_peer(sender_hex);
                if (member && member->pub_kem != old_key) notify(member->name + " is using a new encryption key.");
            }
            bool changed = false;
            if (member) {
                for (const auto& sr : records) {
                    if (sr.record.sender != sender || sr.record.type == chat::RecordType::Conversation) continue;
                    if (!chat::verify_record(sr, member->pub_dsa)) continue;
                    changed |= handle_group_record(*member, sr, true);
                }
            }
            if (!only_group_grants(records)) note_token_use(envelope.token_hash, sender_hex);
            if (changed) bump();
            return true;
        }
    }

    // Someone we don't know. They must introduce themselves with a self-signed bundle, and every
    // record must verify against it. What they sent waits as a request until the user decides.
    // (A group invitation rides along: the bundles it introduces are kept after the records.)
    if (!bundle || bundle->fingerprint() != sender_hex) return true;
    std::vector<Bytes> verified;
    bool has_invitation = false;
    for (const auto& sr : records)
        if (sr.record.sender == sender && chat::verify_record(sr, bundle->signing_key)) {
            verified.push_back(sr.raw);
            has_invitation |= sr.record.type == chat::RecordType::Conversation;
        }
    if (verified.empty()) return true;
    if (has_invitation)
        for (const auto& raw : inner->introduced) verified.push_back(raw);
    if (history_->request_count() >= MAX_PENDING_REQUESTS) return true;  // flooded: drop

    history_->add_request(sender_hex, bundle->raw, verified, unix_now());
    note_token_use(envelope.token_hash, sender_hex);
    notify("New message request from " + (bundle->display_name.empty() ? short_fp(sender_hex) + "..." : bundle->display_name) + ".");
    bump();
    return true;
}

std::vector<MessagingEngine::Request> MessagingEngine::requests() {
    std::vector<Request> out;
    for (const auto& row : history_->requests()) {
        if (keys_.find_contact_by_fingerprint(row.sender_fp)) {  // already added; the request is stale
            history_->delete_requests(row.sender_fp);
            continue;
        }
        auto existing = std::find_if(out.begin(), out.end(), [&](const Request& r) { return r.sender_fp == row.sender_fp; });
        if (existing == out.end()) {
            Request r;
            r.sender_fp = row.sender_fp;
            r.received_at = row.received_at;
            if (auto b = parse_identity_bundle(row.bundle)) r.display_name = b->display_name;
            out.push_back(std::move(r));
            existing = out.end() - 1;
        }
        for (const auto& raw : row.records) {
            auto sr = chat::parse_record(raw);
            if (!sr || sr->record.type != chat::RecordType::Text) continue;
            existing->message_count++;
            if (existing->first_text.empty()) existing->first_text.assign(sr->record.payload.begin(), sr->record.payload.end());
        }
    }
    return out;
}

bool MessagingEngine::accept_request(const std::string& sender_fp, const std::string& contact_name, std::string& error) {
    std::vector<HistoryStore::Request> rows;
    for (auto& r : history_->requests())
        if (r.sender_fp == sender_fp) rows.push_back(std::move(r));
    if (rows.empty()) { error = "That request is no longer there"; return false; }

    auto bundle = parse_identity_bundle(rows.front().bundle);
    if (!bundle || bundle->fingerprint() != sender_fp) { error = "Their identity bundle is not valid"; return false; }
    if (!KeyStore::is_valid_contact_name(contact_name)) { error = "Please use 1-64 letters, digits, spaces, '-', '_' or '.' for the name"; return false; }
    if (auto taken = keys_.load_contact(contact_name); taken && taken->fingerprint != sender_fp) {
        error = "You already have a different contact with that name";
        return false;
    }
    try {
        keys_.save_contact_bundle(contact_name, *bundle);
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }

    // Now that they are a contact, handle what they sent exactly as if it had just arrived.
    auto contact = keys_.load_contact(contact_name);
    if (!contact) { error = "Could not save the contact"; return false; }
    history_->set_verified(sender_fp, true, unix_now());  // the caller had the user check their fingerprint
    // A request may carry a group invitation: signed records, then the bundles of the people it introduces.
    std::vector<Bytes> introduced;
    for (const auto& row : rows)
        for (const auto& raw : row.records)
            if (!chat::parse_record(raw)) introduced.push_back(raw);
    for (const auto& row : rows)
        for (const auto& raw : row.records) {
            auto sr = chat::parse_record(raw);
            if (!sr || !chat::verify_record(*sr, contact->pub_dsa)) continue;
            if (sr->record.type == chat::RecordType::Conversation) receive_group_invite(*contact, *sr, introduced);
            else handle_record(*contact, *sr, true);
        }
    history_->delete_requests(sender_fp);
    bump();
    return true;
}

void MessagingEngine::decline_request(const std::string& sender_fp) {
    history_->delete_requests(sender_fp);
    bump();
}

// --- Groups ---

// The latest entry we hold from each of the given members (newest first), for a record's "seen" list.
std::vector<MessagingEngine::Bytes> MessagingEngine::latest_heads(const Bytes& conversation_id, const std::vector<std::string>& members) {
    std::vector<Bytes> out;
    std::set<std::string> remaining(members.begin(), members.end());
    auto messages = history_->messages(conversation_id, 200);  // oldest first
    for (auto it = messages.rbegin(); it != messages.rend() && !remaining.empty() && out.size() < chat::MAX_SEEN; ++it) {
        if (it->outgoing) continue;
        auto sr = chat::parse_record(it->record);
        if (!sr) continue;
        if (remaining.erase(bytes_to_hex(sr->record.sender))) out.push_back(it->entry_hash);
    }
    return out;
}

// Forgets introduced people who are no longer in any group or waiting invitation.
void MessagingEngine::prune_introduced() {
    std::set<std::string> keep;
    for (const auto& conv : history_->conversations())
        if (conv.kind == HistoryStore::Group) keep.insert(conv.members.begin(), conv.members.end());
    for (const auto& invite : history_->group_invites()) {
        auto sr = chat::parse_record(invite.records.front());
        auto info = sr ? chat::conversation_from_record(*sr) : std::nullopt;
        if (!info) continue;
        for (const auto& m : info->members) keep.insert(bytes_to_hex(m));
    }
    history_->delete_introduced_except(keep);
}

std::vector<MessagingEngine::GroupSummary> MessagingEngine::groups() {
    std::vector<GroupSummary> out;
    for (const auto& conv : history_->conversations()) {
        if (conv.kind != HistoryStore::Group) continue;
        GroupSummary g;
        g.id = bytes_to_hex(conv.id);
        g.title = conv.title;
        g.creator_fp = conv.creator_fp;
        g.created_by_me = conv.creator_fp == my_fp_hex_;
        g.unread = history_->unread_count(conv.id);
        g.last_activity = conv.last_activity;
        g.ready = true;
        for (const auto& fp : conv.members) {
            GroupMember m = member_info(fp, conv.id);
            g.ready = g.ready && m.can_send;
            g.members.push_back(std::move(m));
        }
        const int wanted = g.ready ? HistoryStore::Active : HistoryStore::SettingUp;
        if (conv.state != wanted) history_->set_conversation_state(conv.id, wanted);
        out.push_back(std::move(g));
    }
    return out;  // conversations() is already most recent first
}

bool MessagingEngine::create_group(const std::string& title, const std::vector<std::string>& member_fps, std::string& group_id, std::string& error) {
    if (!is_set_up()) { error = "Set up messaging first"; return false; }
    if (title.size() > chat::MAX_TITLE_BYTES) { error = "The group name is too long (64 bytes at most)"; return false; }
    if (member_fps.empty()) { error = "Choose at least one person to invite"; return false; }
    if (member_fps.size() > chat::MAX_GROUP_MEMBERS - 1) { error = "A group can have at most 16 people, including you"; return false; }

    chat::ConversationInfo info;
    info.title = title;
    info.members.push_back(my_fp_);  // the creator first
    std::vector<std::string> others;
    std::vector<Bytes> bundles;  // each other member's signed bundle, to introduce them to one another
    for (const auto& fp : member_fps) {
        auto raw = hex_to_bytes(fp);
        if (!raw || raw->size() != 32) { error = "One of those isn't a valid contact"; return false; }
        if (fp == my_fp_hex_) { error = "You are already in the group"; return false; }
        if (std::find(others.begin(), others.end(), fp) != others.end()) { error = "Someone is listed twice"; return false; }
        auto contact = keys_.find_contact_by_fingerprint(fp);
        if (!contact) { error = "One of those people isn't in your contacts"; return false; }
        if (!contact->can_message()) { error = contact->name + " can't be messaged yet. Ask them for a new contact card."; return false; }
        auto bundle = keys_.load_contact_bundle_raw(contact->name);
        if (!bundle) { error = "You don't have a signed identity bundle for " + contact->name + ". Ask them for a new contact card."; return false; }
        others.push_back(fp);
        info.members.push_back(*raw);
        bundles.push_back(std::move(*bundle));
    }

    const int64_t now = unix_now();
    chat::Record r;
    r.conversation_id = CryptoEngine::random_bytes(chat::ID_BYTES);
    r.message_id = CryptoEngine::random_bytes(chat::ID_BYTES);
    r.sender = my_fp_;
    r.recipients_hash = chat::recipients_hash_for(info.members);
    r.sent_at = static_cast<uint64_t>(now);
    r.type = chat::RecordType::Conversation;
    Bytes raw_record;
    try {
        r.payload = chat::conversation_payload(info);
        raw_record = chat::sign_record(r, dsa_private_);
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
    auto parsed = chat::parse_record(raw_record);
    if (!parsed) { error = "Could not sign the invitation"; return false; }

    try {
        history_->create_group(r.conversation_id, title, my_fp_hex_, HistoryStore::Saved, 0, Bytes(), others, HistoryStore::Active, now);
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
    // The creation record is the first entry of the transcript, and the invitation's delivery is
    // tracked for each member like any message.
    HistoryStore::Message first;
    first.conversation_id = r.conversation_id;
    first.message_id = r.message_id;
    first.outgoing = true;
    first.sent_at = now;
    first.received_at = now;
    first.status = HistoryStore::Queued;
    first.entry_hash = parsed->entry_hash;
    first.record = raw_record;
    history_->add_message(first);

    // Each member gets the record and the others' bundles (not their own, and not ours: they
    // already hold or receive ours). Long lists are split over several envelopes.
    for (size_t i = 0; i < others.size(); i++) {
        std::vector<Bytes> to_introduce;
        for (size_t j = 0; j < others.size(); j++)
            if (j != i) to_introduce.push_back(bundles[j]);
        size_t start = 0;
        do {
            std::vector<Bytes> payload = {raw_record};
            for (size_t k = start; k < to_introduce.size() && k < start + INTRODUCED_PER_ENVELOPE; k++) payload.push_back(to_introduce[k]);
            history_->enqueue(others[i], OUTBOX_KIND_MESSAGE, r.message_id, payload, now, now);
            start += INTRODUCED_PER_ENVELOPE;
        } while (start < to_introduce.size());
    }
    group_id = bytes_to_hex(r.conversation_id);
    bump();
    return true;
}

std::vector<MessagingEngine::GroupMessage> MessagingEngine::group_messages(const std::string& group_id, size_t limit) {
    std::vector<GroupMessage> out;
    auto id = hex_to_bytes(group_id);
    if (!id) return out;
    auto conv = history_->conversation(*id);
    if (!conv || conv->kind != HistoryStore::Group) return out;
    for (auto& m : history_->messages(conv->id, limit)) {
        if (m.deleted) {
            GroupMessage gone;
            gone.row = m.row;
            gone.message_id = bytes_to_hex(m.message_id);
            gone.outgoing = m.outgoing;
            gone.sent_at = m.sent_at;
            gone.status = m.status;
            gone.deleted = true;
            out.push_back(std::move(gone));
            continue;
        }
        auto record = chat::parse_record(m.record);
        if (!record || (record->record.type != chat::RecordType::Text && record->record.type != chat::RecordType::Attachment)) continue;
        GroupMessage gm;
        gm.row = m.row;
        gm.message_id = bytes_to_hex(m.message_id);
        gm.sender_fp = bytes_to_hex(record->record.sender);
        gm.outgoing = m.outgoing;
        if (!gm.outgoing) gm.sender_name = member_info(gm.sender_fp).name;
        gm.sent_at = m.sent_at;
        gm.text.assign(record->record.payload.begin(), record->record.payload.end());
        if (record->record.type == chat::RecordType::Attachment) {
            auto info = chat::parse_attachment_payload(record->record.payload);
            if (!info) continue;
            gm.is_attachment = true;
            gm.attachment = attachment_view(*info);
            gm.text = info->caption;
        }
        gm.status = m.status;
        gm.gap = m.gap;
        out.push_back(std::move(gm));
    }
    std::stable_sort(out.begin(), out.end(), [](const GroupMessage& a, const GroupMessage& b) {
        return a.sent_at != b.sent_at ? a.sent_at < b.sent_at : a.row < b.row;
    });
    return out;
}

std::vector<MessagingEngine::MemberDelivery> MessagingEngine::group_delivery(const std::string& group_id, const std::string& message_id) {
    std::vector<MemberDelivery> out;
    auto id = hex_to_bytes(group_id);
    auto mid = hex_to_bytes(message_id);
    if (!id || !mid) return out;
    for (const auto& d : history_->deliveries(*id, *mid)) out.push_back({d.member_fp, member_info(d.member_fp).name, d.status});
    return out;
}

bool MessagingEngine::send_group_text(const std::string& group_id, const std::string& text, std::string& error) {
    if (text.empty()) { error = "There is nothing to send"; return false; }
    if (text.size() > chat::MAX_TEXT_BYTES) { error = "That message is too long (32 KiB at most)"; return false; }
    auto id = hex_to_bytes(group_id);
    auto conv = id ? history_->conversation(*id) : std::nullopt;
    if (!conv || conv->kind != HistoryStore::Group) { error = "That group isn't in your list"; return false; }

    std::vector<Bytes> everyone = {my_fp_};
    for (const auto& fp : conv->members) {
        auto raw = hex_to_bytes(fp);
        if (!raw) { error = "That group is damaged"; return false; }
        everyone.push_back(std::move(*raw));
    }

    const int64_t now = unix_now();
    chat::Record r;
    r.conversation_id = conv->id;
    r.message_id = CryptoEngine::random_bytes(chat::ID_BYTES);
    r.sender = my_fp_;
    r.recipients_hash = chat::recipients_hash_for(everyone);
    r.sent_at = static_cast<uint64_t>(now);
    r.type = chat::RecordType::Text;
    r.payload.assign(text.begin(), text.end());
    r.own_prev = history_->last_entry_hash(conv->id, true).value_or(Bytes());
    r.seen = latest_heads(conv->id, conv->members);

    Bytes raw;
    try {
        raw = chat::sign_record(r, dsa_private_);
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
    auto parsed = chat::parse_record(raw);
    if (!parsed) { error = "Could not sign the message"; return false; }

    HistoryStore::Message m;
    m.conversation_id = conv->id;
    m.message_id = r.message_id;
    m.outgoing = true;
    m.sent_at = now;
    m.received_at = now;
    m.status = HistoryStore::Queued;
    m.entry_hash = parsed->entry_hash;
    m.record = raw;
    history_->add_message(m);
    // One envelope per member, each queued, retried and tracked on its own.
    for (const auto& fp : conv->members) history_->enqueue(fp, OUTBOX_KIND_MESSAGE, r.message_id, {raw}, now, now);
    queue_archive_entry(conv->id, raw, r.message_id);
    bump();
    return true;
}

void MessagingEngine::mark_group_read(const std::string& group_id) {
    auto id = hex_to_bytes(group_id);
    auto conv = id ? history_->conversation(*id) : std::nullopt;
    if (!conv || conv->kind != HistoryStore::Group) return;
    auto ids = history_->mark_all_read(conv->id);
    if (ids.empty()) return;
    if (conv->send_read_receipts) {
        std::vector<Bytes> everyone = {my_fp_};
        for (const auto& fp : conv->members)
            if (auto raw = hex_to_bytes(fp)) everyone.push_back(std::move(*raw));
        const Bytes recipients = chat::recipients_hash_for(everyone);
        // Each author hears only about their own messages.
        std::map<std::string, std::vector<Bytes>> by_author;
        for (const auto& mid : ids) {
            auto m = history_->find_message(conv->id, mid);
            auto sr = m ? chat::parse_record(m->record) : std::nullopt;
            if (sr) by_author[bytes_to_hex(sr->record.sender)].push_back(mid);
        }
        for (const auto& [author, author_ids] : by_author)
            enqueue_receipt_in(conv->id, recipients, author, chat::ReceiptKind::Read, author_ids, false);
    }
    bump();
}

void MessagingEngine::set_group_receipts(const std::string& group_id, bool delivery, bool read) {
    auto id = hex_to_bytes(group_id);
    auto conv = id ? history_->conversation(*id) : std::nullopt;
    if (!conv || conv->kind != HistoryStore::Group) return;
    history_->set_receipt_settings(conv->id, delivery, read);
}

bool MessagingEngine::group_receipts_enabled(const std::string& group_id, bool* delivery, bool* read) {
    auto id = hex_to_bytes(group_id);
    auto conv = id ? history_->conversation(*id) : std::nullopt;
    const bool found = conv && conv->kind == HistoryStore::Group;
    if (delivery) *delivery = found ? conv->send_delivery_receipts : true;
    if (read) *read = found ? conv->send_read_receipts : true;
    return found;
}

// A signed record in a group conversation, from someone whose signature the caller has already
// checked. It counts only if the sender is a member and the record is bound to exactly this group.
bool MessagingEngine::handle_group_record(const Peer& sender, const chat::SignedRecord& sr, bool delayed_receipt) {
    if (sr.record.sender == my_fp_) return false;
    const Bytes& conv_id = sr.record.conversation_id;

    if (auto conv = history_->conversation(conv_id); conv && conv->kind == HistoryStore::Group) {
        if (std::find(conv->members.begin(), conv->members.end(), sender.fp) == conv->members.end()) return false;  // not a member
        std::vector<Bytes> everyone = {my_fp_};
        for (const auto& fp : conv->members) {
            auto raw = hex_to_bytes(fp);
            if (!raw) return false;
            everyone.push_back(std::move(*raw));
        }
        if (sr.record.recipients_hash != chat::recipients_hash_for(everyone)) return false;  // redirected from another group

        const int64_t now = unix_now();
        switch (sr.record.type) {
            case chat::RecordType::Text:
            case chat::RecordType::Attachment: {
                if (sr.record.type == chat::RecordType::Attachment && !chat::parse_attachment_payload(sr.record.payload)) return false;
                HistoryStore::Message m;
                m.conversation_id = conv_id;
                m.message_id = sr.record.message_id;
                m.outgoing = false;
                m.sent_at = static_cast<int64_t>(sr.record.sent_at);
                m.received_at = now;
                m.status = 0;
                m.entry_hash = sr.entry_hash;
                m.record = sr.raw;
                // They pointed at an earlier message of theirs that we never saw: something went missing.
                m.gap = !sr.record.own_prev.empty() && !history_->has_entry(conv_id, sr.record.own_prev);
                if (!history_->add_message(m)) {  // a duplicate or replay (but an attachment's envelope may bring the key its archived copy lacked)
                    if (sr.record.type == chat::RecordType::Attachment && !envelope_grants_.empty()) note_incoming_attachment(sr, envelope_grants_);
                    return false;
                }
                if (m.gap) archive_sync_now_.insert(bytes_to_hex(conv_id));
                if (sr.record.type == chat::RecordType::Attachment) note_incoming_attachment(sr, envelope_grants_);
                if (conv->send_delivery_receipts)
                    enqueue_receipt_in(conv_id, sr.record.recipients_hash, sender.fp, chat::ReceiptKind::Delivered, {m.message_id}, delayed_receipt);
                return true;
            }
            case chat::RecordType::Receipt: {
                auto info = chat::parse_receipt_payload(sr.record.payload);
                if (!info) return false;
                const int status = info->kind == chat::ReceiptKind::Read ? HistoryStore::Read : HistoryStore::Delivered;
                bool changed = false;
                for (const auto& id : info->message_ids) changed |= history_->raise_delivery(conv_id, id, sender.fp, status);
                return changed;
            }
            case chat::RecordType::TokenGrant: {
                // A member's gift: a token for writing to their mailbox, good for this group only.
                history_->save_member_token(conv_id, sender.fp, sr.record.payload, now);
                return true;
            }
            case chat::RecordType::Forward: {
                // A member asks us, as the creator, to pass a sealed envelope (we can't open it) on to another member.
                if (conv->creator_fp != my_fp_hex_) return false;
                auto info = chat::parse_forward_payload(sr.record.payload);
                if (!info) return false;
                const std::string target = bytes_to_hex(info->target);
                if (target == sender.fp || std::find(conv->members.begin(), conv->members.end(), target) == conv->members.end()) return false;
                history_->enqueue(target, OUTBOX_KIND_RELAY, sr.record.message_id, {info->envelope}, now, now);
                return true;
            }
            case chat::RecordType::ArchiveGrant:
                return receive_archive_grant(sender, sr);
            case chat::RecordType::DeleteRequest:
                return receive_deletion_request(sender, sr);
            case chat::RecordType::DeleteAccept:
                return receive_deletion_accept(sender, sr);
            case chat::RecordType::Checkpoint:     // only ever found in an archive
            case chat::RecordType::Conversation:   // the group already exists: a replay changes nothing
                return false;
        }
        return false;
    }

    // A group we have been invited to but haven't answered: keep what its members send until we do.
    if (auto invite = history_->group_invite(conv_id)) {
        // Tokens members send before we answer are kept too, so that writing to them works once we join. So is
        // the grant to the chat's archive.
        if (sr.record.type != chat::RecordType::Text && sr.record.type != chat::RecordType::TokenGrant && sr.record.type != chat::RecordType::ArchiveGrant) return false;
        auto creation = chat::parse_record(invite->records.front());
        auto info = creation ? chat::conversation_from_record(*creation) : std::nullopt;
        if (!info) return false;
        const Bytes sender_raw = hex_to_bytes(sender.fp).value_or(Bytes());
        if (std::find(info->members.begin(), info->members.end(), sender_raw) == info->members.end()) return false;
        if (sr.record.recipients_hash != chat::recipients_hash_for(info->members)) return false;
        return history_->hold_for_invite(conv_id, sr.raw);
    }
    return false;  // not a group we know of
}

bool MessagingEngine::receive_group_invite(const KeyStore::Contact& creator, const chat::SignedRecord& sr, const std::vector<Bytes>& introduced) {
    auto info = chat::conversation_from_record(sr);
    auto creator_raw = hex_to_bytes(creator.fingerprint);
    if (!info || !creator_raw || sr.record.sender != *creator_raw) return false;
    // It must name us, or it isn't for us.
    if (std::find(info->members.begin(), info->members.end(), my_fp_) == info->members.end()) return false;

    const Bytes& id = sr.record.conversation_id;
    if (id == chat::conversation_id_for(my_fp_, *creator_raw)) return false;  // that ID is our one-to-one chat

    // Is this a group we already hold, or an invitation already waiting? A long list of introductions
    // is split over several envelopes, each repeating the creation record, so the same record may
    // arrive again. That adds its introduced bundles but changes nothing else. Anything that
    // doesn't match what we hold is ignored (a replay can't rewrite a group).
    bool already_known = false;
    if (auto conv = history_->conversation(id)) {
        std::vector<std::string> others;
        for (const auto& m : info->members)
            if (m != my_fp_) others.push_back(bytes_to_hex(m));
        std::sort(others.begin(), others.end());
        std::vector<std::string> held = conv->members;
        std::sort(held.begin(), held.end());
        if (conv->kind != HistoryStore::Group || conv->creator_fp != creator.fingerprint || held != others) return false;
        already_known = true;
    } else if (auto pending = history_->group_invite(id)) {
        if (pending->records.front() != sr.raw) return false;
        already_known = true;
    }

    const int64_t now = unix_now();
    if (!already_known) {
        if (history_->group_invite_count() >= MAX_PENDING_GROUP_INVITES) return false;
        if (!history_->add_group_invite(id, creator.fingerprint, sr.raw, now)) return false;
    }

    // Remember the people it introduces. Their bundles are self-signed, so a swapped key or a
    // person the record doesn't name is simply ignored.
    bool saved_any = false;
    for (const auto& raw : introduced) {
        auto bundle = parse_identity_bundle(raw);
        if (!bundle) continue;
        const std::string fp = bundle->fingerprint();
        auto fp_raw = hex_to_bytes(fp);
        if (!fp_raw || *fp_raw == my_fp_ || *fp_raw == *creator_raw) continue;
        if (std::find(info->members.begin(), info->members.end(), *fp_raw) == info->members.end()) continue;
        if (keys_.find_contact_by_fingerprint(fp)) continue;  // already someone we know
        history_->save_introduced(fp, raw, static_cast<int64_t>(bundle->issued_at), creator.fingerprint, now);
        saved_any = true;
    }
    if (!already_known)
        notify(creator.name + " invited you to the group " + (info->title.empty() ? std::string("(no name)") : "\"" + info->title + "\"") + ".");
    if (!already_known || saved_any) bump();
    return !already_known;
}

std::vector<MessagingEngine::GroupInvite> MessagingEngine::group_invites() {
    std::vector<GroupInvite> out;
    for (const auto& invite : history_->group_invites()) {
        auto sr = chat::parse_record(invite.records.front());
        auto info = sr ? chat::conversation_from_record(*sr) : std::nullopt;
        if (!info) continue;
        GroupInvite gi;
        gi.id = bytes_to_hex(invite.conversation_id);
        gi.title = info->title;
        gi.creator_fp = invite.creator_fp;
        gi.creator_name = member_info(invite.creator_fp).name;
        for (const auto& m : info->members)
            if (m != my_fp_) gi.members.push_back(member_info(bytes_to_hex(m)));
        gi.received_at = invite.received_at;
        // Only what the person would read counts: not the grants that ride along (tokens, the chat's archive).
        gi.held_messages = 0;
        for (size_t i = 1; i < invite.records.size(); i++)
            if (auto held = chat::parse_record(invite.records[i]); held && held->record.type == chat::RecordType::Text) gi.held_messages++;
        out.push_back(std::move(gi));
    }
    return out;
}

bool MessagingEngine::accept_group_invite(const std::string& group_id, std::string& error) {
    auto id = hex_to_bytes(group_id);
    auto invite = id ? history_->group_invite(*id) : std::nullopt;
    if (!invite) { error = "That invitation is no longer there"; return false; }
    auto creator = keys_.find_contact_by_fingerprint(invite->creator_fp);
    if (!creator) { error = "The person who invited you is no longer one of your contacts"; return false; }
    auto sr = chat::parse_record(invite->records.front());
    auto info = sr ? chat::conversation_from_record(*sr) : std::nullopt;
    if (!sr || !info || !chat::verify_record(*sr, creator->pub_dsa)) { error = "That invitation is not valid"; return false; }

    std::vector<std::string> others;  // everyone but us, in the creator's order
    bool ready = true;
    for (const auto& m : info->members) {
        if (m == my_fp_) continue;
        others.push_back(bytes_to_hex(m));
        auto peer = resolve_peer(others.back());
        ready = ready && peer && peer->can_send;
    }

    const int64_t now = unix_now();
    try {
        history_->create_group(*id, info->title, invite->creator_fp, HistoryStore::Saved, 0, info->previous_id, others,
                               ready ? HistoryStore::Active : HistoryStore::SettingUp, now);
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
    // The creation record is the first entry of the group's transcript.
    HistoryStore::Message first;
    first.conversation_id = *id;
    first.message_id = sr->record.message_id;
    first.outgoing = false;
    first.sent_at = static_cast<int64_t>(sr->record.sent_at);
    first.received_at = now;
    first.status = 1;  // read: there is nothing to read in it
    first.entry_hash = sr->entry_hash;
    first.record = sr->raw;
    history_->add_message(first);

    // What arrived while the invitation waited is handled now, in the order it came.
    for (size_t i = 1; i < invite->records.size(); i++) {
        auto held = chat::parse_record(invite->records[i]);
        if (!held) continue;
        auto sender = resolve_peer(bytes_to_hex(held->record.sender));
        if (!sender || !chat::verify_record(*held, sender->pub_dsa)) continue;
        handle_group_record(*sender, *held, true);
    }
    history_->delete_group_invite(*id);
    prune_introduced();
    queue_group_grants(*id, invite->creator_fp, others);
    bump();
    return true;
}

void MessagingEngine::decline_group_invite(const std::string& group_id) {
    auto id = hex_to_bytes(group_id);
    if (!id) return;
    history_->delete_group_invite(*id);
    prune_introduced();
    bump();
}

// --- Giving other members a way to write to us ---

// Everyone but the creator needs a token from us, unless they are a contact who has already used
// one of ours (so they can write to us anyway). The tokens are made later, on the relay thread.
void MessagingEngine::queue_group_grants(const Bytes& conversation_id, const std::string& creator_fp, const std::vector<std::string>& others) {
    auto issued = history_->issued_tokens();
    Bytes job = conversation_id;
    std::vector<Bytes> targets;
    for (const auto& fp : others) {
        if (fp == creator_fp) continue;
        auto raw = hex_to_bytes(fp);
        if (!raw || raw->size() != 32) continue;
        bool can_already = false;
        if (keys_.find_contact_by_fingerprint(fp))
            for (const auto& t : issued) can_already |= t.bound_fp == fp && !t.revoked;
        if (!can_already) targets.push_back(std::move(*raw));
    }
    if (targets.empty()) return;
    write_u32(job, static_cast<uint32_t>(targets.size()));
    for (const auto& t : targets) job.insert(job.end(), t.begin(), t.end());
    const int64_t now = unix_now();
    history_->enqueue(creator_fp, OUTBOX_KIND_GRANTS, CryptoEngine::random_bytes(chat::ID_BYTES), {job}, now, now);
}

// For each member in the job: a fresh send token (registered with our relay, bound to that member),
// sealed for them inside an envelope only they can open, wrapped in a Forward record for the creator.
bool MessagingEngine::build_grant_forwards(const HistoryStore::OutboxItem& job, std::vector<Bytes>& forwards) {
    const Bytes& data = job.records.front();
    if (data.size() < chat::ID_BYTES + 4) return true;  // malformed: nothing to do
    const Bytes conv_id(data.begin(), data.begin() + chat::ID_BYTES);
    size_t off = chat::ID_BYTES;
    auto count = read_u32(data.data(), data.size(), off);
    if (!count || *count > chat::MAX_GROUP_MEMBERS || data.size() != off + static_cast<size_t>(*count) * 32) return true;
    auto conv = history_->conversation(conv_id);
    if (!conv || conv->kind != HistoryStore::Group) return true;  // we left, or never joined: nothing to do

    std::vector<Bytes> everyone = {my_fp_};
    for (const auto& fp : conv->members)
        if (auto raw = hex_to_bytes(fp)) everyone.push_back(std::move(*raw));
    const Bytes recipients = chat::recipients_hash_for(everyone);
    const int64_t now = unix_now();

    for (uint32_t i = 0; i < *count; i++) {
        const Bytes target_raw(data.begin() + static_cast<std::ptrdiff_t>(off + i * 32), data.begin() + static_cast<std::ptrdiff_t>(off + (i + 1) * 32));
        const std::string target_fp = bytes_to_hex(target_raw);
        auto target = resolve_peer(target_fp);
        if (!target || !target->keys_verified || target->pub_kem.size() != CryptoEngine::kem_public_key_size()) continue;  // can't seal to them

        Bytes token = CryptoEngine::random_bytes(relay::SEND_TOKEN_BYTES);
        std::string err;
        if (!owner_.add_token(CryptoEngine::sha256(token), err)) return false;  // the relay isn't reachable: try again later
        history_->add_issued_token(CryptoEngine::sha256(token),
                                   "group " + (conv->title.empty() ? std::string("(no name)") : "\"" + conv->title + "\"") + ", for " + target->name,
                                   target_fp, now);
        try {
            chat::Record grant;
            grant.conversation_id = conv_id;
            grant.message_id = CryptoEngine::random_bytes(chat::ID_BYTES);
            grant.sender = my_fp_;
            grant.recipients_hash = recipients;
            grant.sent_at = static_cast<uint64_t>(now);
            grant.type = chat::RecordType::TokenGrant;
            grant.payload = token;
            chat::Inner inner;
            inner.records = {chat::sign_record(grant, dsa_private_)};
            Bytes sealed = chat::seal_envelope(inner, target->pub_kem);  // only the target can open this

            chat::Record forward;
            forward.conversation_id = conv_id;
            forward.message_id = CryptoEngine::random_bytes(chat::ID_BYTES);
            forward.sender = my_fp_;
            forward.recipients_hash = recipients;
            forward.sent_at = static_cast<uint64_t>(now);
            forward.type = chat::RecordType::Forward;
            forward.payload = chat::forward_payload(target_raw, sealed);
            forwards.push_back(chat::sign_record(forward, dsa_private_));
        } catch (const std::exception&) {
            continue;
        }
    }
    return true;
}

// --- Chat archive ---

std::optional<std::string> MessagingEngine::direct_conversation_id(const std::string& contact_fp) {
    auto their = hex_to_bytes(contact_fp);
    if (!their || their->size() != 32) return std::nullopt;
    return bytes_to_hex(chat::conversation_id_for(my_fp_, *their));
}

std::optional<MessagingEngine::ArchiveContext> MessagingEngine::archive_context(const Bytes& conversation_id) {
    auto conv = history_->conversation(conversation_id);
    if (!conv) return std::nullopt;
    ArchiveContext ctx;
    std::vector<Bytes> everyone = {my_fp_};
    for (const auto& fp : conv->members) {
        auto raw = hex_to_bytes(fp);
        if (!raw) return std::nullopt;
        everyone.push_back(std::move(*raw));
        ctx.others.push_back(fp);
    }
    ctx.recipients_hash = chat::recipients_hash_for(everyone);
    if (conv->kind == HistoryStore::Direct) {
        if (ctx.others.size() != 1) return std::nullopt;
        ctx.direct = true;
        ctx.maker_fp = std::min(my_fp_hex_, ctx.others[0]);  // the smaller fingerprint makes it: no race, no tie-break
    } else {
        ctx.maker_fp = conv->creator_fp;
    }
    return ctx;
}

MessagingEngine::ArchiveStatus MessagingEngine::archive_status(const std::string& conversation_id) {
    ArchiveStatus st;
    auto id = hex_to_bytes(conversation_id);
    auto a = id ? history_->archive(*id) : std::nullopt;
    if (!a) return st;
    st.exists = true;
    st.joined = a->state == HistoryStore::ArchiveJoined;
    st.failed = a->state == HistoryStore::ArchiveFailed;
    st.note = a->note;
    st.is_creator = a->role == HistoryStore::ArchiveCreator;
    st.entries = a->head_number;
    st.checkpoint_seen = a->checkpoint_seen;
    st.warning = a->warning;
    st.relay = a->relay_address;
    return st;
}

bool MessagingEngine::create_archive(const std::string& conversation_id, std::string& error) {
    auto id = hex_to_bytes(conversation_id);
    auto ctx = id ? archive_context(*id) : std::nullopt;
    if (!ctx) { error = "That conversation isn't in your list"; return false; }
    if (ctx->maker_fp != my_fp_hex_) { error = "Someone else makes this chat's archive; you will be given access"; return false; }
    if (history_->archive(*id)) { error = "This chat already has an archive"; return false; }
    auto config = keys_.load_mailbox_config();
    if (!config) { error = "Set up messaging first"; return false; }

    // Everything the others will need, and the relay's record of who may join: it keeps only token hashes.
    const Bytes archive_key = CryptoEngine::random_bytes(archive::KEY_BYTES);
    const Bytes my_token = CryptoEngine::random_bytes(relay::JOIN_TOKEN_BYTES);
    std::vector<Bytes> tokens;
    std::vector<Bytes> hashes = {CryptoEngine::sha256(my_token)};
    for (size_t i = 0; i < ctx->others.size(); i++) {
        tokens.push_back(CryptoEngine::random_bytes(relay::JOIN_TOKEN_BYTES));
        hashes.push_back(CryptoEngine::sha256(tokens.back()));
    }
    auto chat_key = CryptoEngine::generate_sig_keypair();

    RelayClient client;
    if (!connect_authenticated(client, error) || !client.create_archive(*id, hashes, error) || !client.join_archive(*id, my_token, chat_key, error)) return false;

    const int64_t now = unix_now();
    HistoryStore::Archive a;
    a.conversation_id = *id;
    a.relay_address = format_server_address(ServerAddress{config->host, config->port});
    a.relay_id = config->relay_id;
    a.role = HistoryStore::ArchiveCreator;
    a.state = HistoryStore::ArchiveJoined;
    a.archive_key = archive_key;
    a.chat_public_key = chat_key.public_key;
    a.chat_private_key = chat_key.private_key;
    a.created_at = now;
    if (!history_->add_archive(a)) { error = "This chat already has an archive"; return false; }

    // Each other member gets their own token, sealed in their own envelope.
    for (size_t i = 0; i < ctx->others.size(); i++) {
        chat::ArchiveGrantInfo info;
        info.relay_address = a.relay_address;
        info.relay_id = a.relay_id;
        info.archive_key = archive_key;
        info.join_token = tokens[i];
        chat::Record r;
        r.conversation_id = *id;
        r.message_id = CryptoEngine::random_bytes(chat::ID_BYTES);
        r.sender = my_fp_;
        r.recipients_hash = ctx->recipients_hash;
        r.sent_at = static_cast<uint64_t>(now);
        r.type = chat::RecordType::ArchiveGrant;
        try {
            r.payload = chat::archive_grant_payload(info);
            history_->enqueue(ctx->others[i], OUTBOX_KIND_MESSAGE, r.message_id, {chat::sign_record(r, dsa_private_)}, now, now);
        } catch (const std::exception& e) {
            error = e.what();
            return false;
        }
    }
    // A group's creation record is the archive's first entry: it says who is in the group, which restoring needs.
    if (auto conv = history_->conversation(*id); conv && conv->kind == HistoryStore::Group)
        if (auto first = history_->first_message(*id))
            if (auto parsed = chat::parse_record(first->record); parsed && parsed->record.type == chat::RecordType::Conversation)
                queue_archive_entry(*id, first->record, first->message_id);
    bump();
    return true;
}

// A grant from the person whose job it is to make the archive: remember it, and join when pump() next runs.
bool MessagingEngine::receive_archive_grant(const Peer& sender, const chat::SignedRecord& sr) {
    const Bytes& id = sr.record.conversation_id;
    auto ctx = archive_context(id);
    if (!ctx || ctx->maker_fp == my_fp_hex_ || sender.fp != ctx->maker_fp) return false;  // not ours to receive, or not from the right person
    if (history_->archive(id)) return false;                                            // already have one: a replay changes nothing
    auto info = chat::parse_archive_grant_payload(sr.record.payload);
    if (!info || !parse_server_address(info->relay_address)) return false;
    auto chat_key = CryptoEngine::generate_sig_keypair();
    HistoryStore::Archive a;
    a.conversation_id = id;
    a.relay_address = info->relay_address;
    a.relay_id = info->relay_id;
    a.role = HistoryStore::ArchiveMember;
    a.state = HistoryStore::ArchiveGranted;
    a.archive_key = info->archive_key;
    a.chat_public_key = chat_key.public_key;
    a.chat_private_key = chat_key.private_key;
    a.join_token = info->join_token;
    a.created_at = unix_now();
    return history_->add_archive(a);
}

// Registers this device's key for every archive it has been granted but not yet joined.
void MessagingEngine::join_pending_archives() {
    const auto now = std::chrono::steady_clock::now();
    for (const auto& a : history_->archives_in_state(HistoryStore::ArchiveGranted)) {
        const std::string key = bytes_to_hex(a.conversation_id);
        auto due = archive_join_retry_.find(key);
        if (due != archive_join_retry_.end() && now < due->second) continue;
        auto address = parse_server_address(a.relay_address);
        std::string err;
        if (!address) {
            history_->set_archive_failed(a.conversation_id, "The archive's relay address is not valid");
            continue;
        }
        RelayClient client;
        CryptoEngine::SigKeyPair chat_key{a.chat_public_key, a.chat_private_key};
        if (client.connect(address->host, address->port, a.relay_id, options_.connect_timeout_seconds, err) &&
            client.join_archive(a.conversation_id, a.join_token, chat_key, err)) {
            history_->set_archive_joined(a.conversation_id);
            archive_join_retry_.erase(key);
            bump();
            continue;
        }
        // A refusal is final; anything else (the relay is down) is tried again shortly.
        if (err.find("closed") != std::string::npos || err.find("Unknown archive or join token") != std::string::npos ||
            err.find("does not match") != std::string::npos) {
            history_->set_archive_failed(a.conversation_id, err);
            notify("Could not join a chat's archive: " + err);
            bump();
        } else {
            archive_join_retry_[key] = now + std::chrono::seconds(std::max(1, options_.retry_base_seconds) * 3);
        }
    }
}

bool MessagingEngine::open_archive_session(const HistoryStore::Archive& a, RelayClient& client, std::string& error) {
    if (a.state != HistoryStore::ArchiveJoined) {
        error = a.state == HistoryStore::ArchiveFailed ? "This chat's archive could not be joined: " + a.note : "This device has not joined the chat's archive yet";
        return false;
    }
    auto address = parse_server_address(a.relay_address);
    if (!address) { error = "The archive's relay address is not valid"; return false; }
    CryptoEngine::SigKeyPair chat_key{a.chat_public_key, a.chat_private_key};
    return client.connect(address->host, address->port, a.relay_id, options_.connect_timeout_seconds, error) &&
           client.authenticate_archive(a.conversation_id, chat_key, error);
}

// Takes entries from the relay until this device is level with it, checking the chain from where it left off.
bool MessagingEngine::archive_catch_up(RelayClient& client, const HistoryStore::Archive& a, archive::Head& head,
                                       std::vector<ArchivedRecord>& fresh, std::string& error) {
    while (true) {
        std::vector<relay::ArchiveEntry> entries;
        relay::ArchiveHead relay_head;
        if (!client.fetch_entries(head.number + 1, 100, entries, relay_head, error)) return false;
        auto next = archive::verify_chain(a.conversation_id, head, entries);
        if (!next) {
            error = "The relay's copy of this chat doesn't match what it held before: it may have been altered";
            warn_archive(a.conversation_id, error);
            return false;
        }
        std::vector<std::pair<uint64_t, Bytes>> hashes;
        uint64_t activity = 0;
        for (const auto& e : entries) {
            ArchivedRecord r;
            r.number = e.number;
            if (e.tombstone) {  // removed by agreement: nothing to read, the hash holds its place in the chain
                history_->mark_archive_redacted(a.conversation_id, e.number);
                hashes.emplace_back(e.number, e.hash);
                fresh.push_back(std::move(r));
                continue;
            }
            if (auto record = archive::open_entry(a.archive_key, a.conversation_id, e.number, e.ciphertext)) r.record = std::move(*record);
            auto parsed = r.record.empty() ? std::nullopt : chat::parse_record(r.record);
            if (parsed && (parsed->record.type == chat::RecordType::Text || parsed->record.type == chat::RecordType::Conversation))
                history_->save_archive_message(a.conversation_id, parsed->record.message_id, e.number);  // so the message can be named by its entry
            if (!parsed || parsed->record.type != chat::RecordType::Checkpoint) activity++;  // checkpoints don't count towards the next one
            hashes.emplace_back(e.number, e.hash);
            fresh.push_back(std::move(r));
        }
        head = *next;
        history_->save_archive_hashes(a.conversation_id, hashes);
        if (activity) history_->add_archive_activity(a.conversation_id, activity);
        history_->set_archive_head(a.conversation_id, head.number, head.hash);
        if (entries.empty() || head.number >= relay_head.number) {
            // What the relay says its end is must be the end of the entries it actually gave us.
            if (relay_head.number != head.number || relay_head.hash != head.hash) {
                error = "The relay reports a different end to this chat than the entries it sent add up to";
                warn_archive(a.conversation_id, error);
                return false;
            }
            return true;
        }
    }
}

bool MessagingEngine::archive_sync(const std::string& conversation_id, std::vector<ArchivedRecord>& fresh, std::string& error) {
    fresh.clear();
    auto id = hex_to_bytes(conversation_id);
    auto a = id ? history_->archive(*id) : std::nullopt;
    if (!a) { error = "This chat has no archive"; return false; }
    RelayClient client;
    if (!open_archive_session(*a, client, error)) return false;
    archive::Head head{a->head_number, a->head_hash.empty() ? archive::genesis_hash(a->conversation_id) : a->head_hash};
    return archive_catch_up(client, *a, head, fresh, error);
}

bool MessagingEngine::archive_append(const std::string& conversation_id, const std::vector<uint8_t>& record, uint64_t& number,
                                     std::vector<ArchivedRecord>& others, std::string& error) {
    others.clear();
    auto id = hex_to_bytes(conversation_id);
    auto a = id ? history_->archive(*id) : std::nullopt;
    if (!a) { error = "This chat has no archive"; return false; }
    RelayClient client;
    if (!open_archive_session(*a, client, error)) return false;
    archive::Head head{a->head_number, a->head_hash.empty() ? archive::genesis_hash(a->conversation_id) : a->head_hash};
    for (int attempt = 0; attempt < 10; attempt++) {
        if (!archive_catch_up(client, *a, head, others, error)) return false;
        Bytes blob;
        try {
            blob = archive::seal_entry(a->archive_key, a->conversation_id, head.number + 1, record);
        } catch (const std::exception& e) {
            error = e.what();
            return false;
        }
        relay::ArchiveHead new_head;
        switch (client.append_entry(head.number, head.hash, blob, new_head, error)) {
            case RelayClient::AppendOutcome::Appended: {
                // The relay's answer must be the entry we made, on the head we named.
                if (new_head.number != head.number + 1 || new_head.hash != archive::entry_hash(a->conversation_id, head.number + 1, head.hash, blob)) {
                    error = "The relay's answer doesn't match the entry it stored";
                    return false;
                }
                number = new_head.number;
                history_->save_archive_hashes(a->conversation_id, {{number, new_head.hash}});
                if (auto own = chat::parse_record(record); own && (own->record.type == chat::RecordType::Text || own->record.type == chat::RecordType::Conversation))
                    history_->save_archive_message(a->conversation_id, own->record.message_id, number);
                history_->set_archive_head(a->conversation_id, new_head.number, new_head.hash);
                if (auto own = chat::parse_record(record); !own || own->record.type != chat::RecordType::Checkpoint) history_->add_archive_activity(a->conversation_id, 1);
                return true;
            }
            case RelayClient::AppendOutcome::Stale: break;  // someone got in first: catch up on theirs and go again
            case RelayClient::AppendOutcome::Failed: return false;
        }
    }
    error = "This chat's archive is too busy right now; try again";
    return false;
}

// --- Chat archive: keeping it up to date ---

void MessagingEngine::warn_archive(const Bytes& conversation_id, const std::string& what) {
    // Say it once: a warning that's already set stays as it is until someone looks into it.
    auto a = history_->archive(conversation_id);
    if (!a || !a->warning.empty()) return;
    history_->set_archive_warning(conversation_id, what);
    notify("Warning about a chat's archive: " + what);
    bump();
}

// A message we have just sent also goes into the chat's archive, but never holds up the message itself.
void MessagingEngine::queue_archive_entry(const Bytes& conversation_id, const Bytes& record, const Bytes& message_id) {
    if (!history_->has_archive(conversation_id)) return;  // older history isn't backfilled
    const int64_t now = unix_now();
    history_->enqueue(bytes_to_hex(conversation_id), OUTBOX_KIND_ARCHIVE, message_id, {record}, now, now);
}

void MessagingEngine::flush_archive_item(const HistoryStore::OutboxItem& item, int64_t now) {
    auto id = hex_to_bytes(item.contact_fp);
    if (!id || item.records.size() != 1) {
        history_->outbox_done(item.id);  // malformed: nothing to send
        return;
    }
    auto a = history_->archive(*id);
    if (!a || a->state == HistoryStore::ArchiveFailed) {
        history_->outbox_done(item.id);  // the chat has no usable archive: nothing to add to
        return;
    }
    if (a->state != HistoryStore::ArchiveJoined) {
        history_->outbox_failed(item.id, now + std::max(1, options_.retry_base_seconds));  // still waiting to join
        return;
    }
    uint64_t number = 0;
    std::vector<ArchivedRecord> others;
    std::string err;
    if (!archive_append(item.contact_fp, item.records[0], number, others, err)) {
        history_->outbox_failed(item.id, now + retry_delay(item.attempts));
        return;
    }
    // What others added while we caught up is theirs to be read, exactly as if it had come by envelope.
    if (handle_archived_records(*id, others)) bump();
    history_->outbox_done(item.id);
}

// Records found in an archive are treated like ones that came in an envelope: the same signature,
// membership and recipients checks, and nothing already held is added twice.
bool MessagingEngine::handle_archived_records(const Bytes& conversation_id, const std::vector<ArchivedRecord>& records) {
    auto conv = history_->conversation(conversation_id);
    if (!conv) return false;
    bool changed = false;
    for (const auto& ar : records) {
        if (ar.record.empty()) continue;  // unreadable under the archive key
        auto sr = chat::parse_record(ar.record);
        if (!sr || sr->record.conversation_id != conversation_id || sr->record.sender == my_fp_) continue;
        const std::string sender_hex = bytes_to_hex(sr->record.sender);
        auto peer = resolve_peer(sender_hex, conversation_id);
        if (!peer || !chat::verify_record(*sr, peer->pub_dsa)) continue;
        if (sr->record.type == chat::RecordType::Checkpoint) {
            changed |= process_checkpoint(conversation_id, *sr, sender_hex);
        } else if (sr->record.type == chat::RecordType::DeleteRequest) {
            changed |= receive_deletion_request(*peer, *sr);
        } else if (sr->record.type == chat::RecordType::DeleteAccept) {
            changed |= receive_deletion_accept(*peer, *sr);
        } else if (sr->record.type == chat::RecordType::Text || sr->record.type == chat::RecordType::Attachment) {
            if (conv->kind == HistoryStore::Direct) {
                if (auto contact = keys_.find_contact_by_fingerprint(sender_hex)) changed |= handle_record(*contact, *sr, true);
            } else {
                changed |= handle_group_record(*peer, *sr, true);
            }
        }
    }
    return changed;
}

// A member's signed "I have seen the archive up to entry n, whose hash is h". If our own checked chain has a
// different hash at n, the relay has shown that member something other than it showed us.
bool MessagingEngine::process_checkpoint(const Bytes& conversation_id, const chat::SignedRecord& sr, const std::string& sender_fp) {
    auto ctx = archive_context(conversation_id);
    if (!ctx || std::find(ctx->others.begin(), ctx->others.end(), sender_fp) == ctx->others.end()) return false;
    if (sr.record.recipients_hash != ctx->recipients_hash) return false;
    auto info = chat::parse_checkpoint_payload(sr.record.payload);
    if (!info) return false;
    history_->note_checkpoint_seen(conversation_id, info->number);
    auto ours = history_->archive_hash(conversation_id, info->number);
    if (ours && *ours != info->hash) {
        warn_archive(conversation_id, "A member's checkpoint contradicts the relay's copy of this chat at entry " + std::to_string(info->number) +
                                          ": the relay may be showing different members different histories");
        return true;
    }
    return false;
}

// Adds a checkpoint once enough has happened since the last one: a number of entries, or some activity and a day.
void MessagingEngine::maybe_post_checkpoint(const Bytes& conversation_id) {
    auto a = history_->archive(conversation_id);
    if (!a || a->state != HistoryStore::ArchiveJoined || a->head_number == 0 || a->activity == 0) return;
    const int64_t now = unix_now();
    const bool enough = a->activity >= static_cast<uint64_t>(std::max(1, options_.archive_checkpoint_every));
    const bool stale = now - std::max(a->checkpoint_at, a->created_at) >= options_.archive_checkpoint_max_age_seconds;
    if (!enough && !stale) return;
    auto ctx = archive_context(conversation_id);
    if (!ctx) return;
    chat::Record r;
    r.conversation_id = conversation_id;
    r.message_id = CryptoEngine::random_bytes(chat::ID_BYTES);
    r.sender = my_fp_;
    r.recipients_hash = ctx->recipients_hash;
    r.sent_at = static_cast<uint64_t>(now);
    r.type = chat::RecordType::Checkpoint;
    try {
        r.payload = chat::checkpoint_payload(a->head_number, a->head_hash);
        history_->enqueue(bytes_to_hex(conversation_id), OUTBOX_KIND_ARCHIVE, r.message_id, {chat::sign_record(r, dsa_private_)}, now, now);
    } catch (const std::exception&) {
        return;
    }
    history_->note_checkpoint_posted(conversation_id, now);
}

// Makes the archive for every chat where that is our job and none exists yet.
void MessagingEngine::ensure_archives() {
    const auto now = std::chrono::steady_clock::now();
    if (now < next_archive_check_) return;
    next_archive_check_ = now + std::chrono::seconds(std::max(1, options_.archive_check_seconds));
    for (const auto& conv : history_->conversations()) {
        if (history_->has_archive(conv.id)) continue;
        {
            bool deleted_by_agreement = false;
            for (const auto& d : history_->deletions())
                if (d.conversation_id == conv.id && d.scope == 1 && d.state == HistoryStore::DeletionDone) deleted_by_agreement = true;
            if (deleted_by_agreement) continue;
        }
        if (conv.kind == HistoryStore::Direct) {
            // The smaller fingerprint makes a one-to-one chat's archive, once the chat has something in it.
            if (!(my_fp_hex_ < conv.contact_fp) || !history_->first_message(conv.id)) continue;
        } else if (conv.creator_fp != my_fp_hex_) {
            continue;
        }
        const std::string hex = bytes_to_hex(conv.id);
        auto due = archive_create_retry_.find(hex);
        if (due != archive_create_retry_.end() && now < due->second) continue;
        std::string err;
        if (create_archive(hex, err)) {
            archive_create_retry_.erase(hex);
        } else {
            archive_create_retry_[hex] = now + std::chrono::seconds(std::max(1, options_.retry_base_seconds) * 6);
        }
    }
}

// Catches up on each joined archive now and then, and straight away when a message showed a gap.
void MessagingEngine::sync_archives() {
    const auto now = std::chrono::steady_clock::now();
    for (const auto& id : history_->archive_ids(HistoryStore::ArchiveJoined)) {
        const std::string hex = bytes_to_hex(id);
        const bool asked = archive_sync_now_.erase(hex) > 0;
        auto due = archive_next_sync_.find(hex);
        if (!asked && due != archive_next_sync_.end() && now < due->second) continue;
        archive_next_sync_[hex] = now + std::chrono::seconds(std::max(1, options_.archive_sync_seconds));
        std::vector<ArchivedRecord> fresh;
        std::string err;
        if (!archive_sync(hex, fresh, err)) continue;  // not reachable, or inconsistent (already warned about)
        if (handle_archived_records(id, fresh)) bump();
        maybe_post_checkpoint(id);
    }
}

// --- The keyring, and restoring from it ---

keyring::Contents MessagingEngine::build_keyring() {
    keyring::Contents c;
    for (const auto& a : history_->archives()) {
        keyring::ArchiveItem item;
        item.conversation_id = a.conversation_id;
        item.relay_address = a.relay_address;
        item.relay_id = a.relay_id;
        item.role = a.role;
        item.state = a.state;
        item.archive_key = a.archive_key;
        item.chat_public_key = a.chat_public_key;
        item.chat_private_key = a.chat_private_key;
        item.join_token = a.join_token;
        c.archives.push_back(std::move(item));
    }
    c.verified = history_->verified_people();
    for (const auto& t : history_->all_member_tokens()) c.member_tokens.push_back({t.conversation_id, t.member_fp, t.token});
    for (const auto& m : history_->introduced_members()) c.introduced.push_back({m.fp, m.bundle, m.issued_at, m.introduced_by, m.first_seen});
    for (const auto& t : history_->issued_tokens()) c.issued_tokens.push_back({t.hash, t.label, t.created_at, t.bound_fp, t.revoked});
    for (const auto& conv : history_->conversations()) c.receipts.push_back({conv.id, conv.send_delivery_receipts, conv.send_read_receipts});
    // The same state always gives the same bytes, whatever order the store happened to list it in.
    std::sort(c.receipts.begin(), c.receipts.end(), [](const keyring::Receipts& x, const keyring::Receipts& y) { return x.conversation_id < y.conversation_id; });
    std::sort(c.verified.begin(), c.verified.end());
    return c;
}

bool MessagingEngine::store_keyring(const Bytes& plaintext, std::string& error) {
    auto config = keys_.load_mailbox_config();
    if (!config) { error = "Set up messaging first"; return false; }
    Bytes key = keys_.derive_local_key("archive keyring");
    auto wipe = make_scope_exit([&] { CryptoEngine::secure_wipe(key); });
    if (key.size() != 32) { error = "Your keys could not be read (are they unlocked?)"; return false; }
    RelayClient client;
    return connect_authenticated(client, error) && client.put_keyring(keyring::seal(key, config->mailbox_id, plaintext), error);
}

bool MessagingEngine::save_keyring(std::string& error) {
    Bytes plain;
    try {
        plain = keyring::serialize(build_keyring());
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
    if (!store_keyring(plain, error)) return false;
    keyring_uploaded_hash_ = CryptoEngine::sha256(plain);
    return true;
}

// Keeps the keyring on the relay in step with this device: stored again only when something in it changed.
void MessagingEngine::maintain_keyring() {
    const auto now = std::chrono::steady_clock::now();
    if (now < next_keyring_check_) return;
    next_keyring_check_ = now + std::chrono::seconds(std::max(1, options_.keyring_check_seconds));
    auto contents = build_keyring();
    if (contents.empty()) return;  // nothing worth keeping yet
    Bytes plain;
    try {
        plain = keyring::serialize(contents);
    } catch (const std::exception&) {
        return;
    }
    const Bytes hash = CryptoEngine::sha256(plain);
    if (hash == keyring_uploaded_hash_) return;
    std::string err;
    if (store_keyring(plain, err)) keyring_uploaded_hash_ = hash;  // if the relay can't be reached, the next look tries again
}

// A one-to-one chat: its ID is derived from the two fingerprints, so it can be recognised among the contacts.
bool MessagingEngine::rebuild_direct_chat(const Bytes& conversation_id) {
    for (const auto& name : keys_.list_contacts()) {
        auto contact = keys_.load_contact(name);
        auto their = contact ? hex_to_bytes(contact->fingerprint) : std::nullopt;
        if (their && chat::conversation_id_for(my_fp_, *their) == conversation_id) {
            history_->ensure_conversation(conversation_id, contact->fingerprint, unix_now());
            return true;
        }
    }
    return false;
}

// A group: its creation record is the archive's first entry, signed by its creator.
bool MessagingEngine::rebuild_group_chat(const Bytes& conversation_id, const std::vector<ArchivedRecord>& records, std::string& why) {
    if (records.empty() || records.front().number != 1 || records.front().record.empty()) { why = "its archive does not start with the group's record"; return false; }
    auto sr = chat::parse_record(records.front().record);
    if (!sr || sr->record.type != chat::RecordType::Conversation || sr->record.conversation_id != conversation_id) { why = "its archive does not start with the group's record"; return false; }
    auto info = chat::conversation_from_record(*sr);
    if (!info) { why = "the group's record is not valid"; return false; }
    const std::string creator_hex = bytes_to_hex(sr->record.sender);
    bool verified = false;
    if (sr->record.sender == my_fp_) {
        verified = chat::verify_record(*sr, keys_.load_public_dsa());
    } else if (auto creator = resolve_peer(creator_hex, conversation_id)) {
        verified = chat::verify_record(*sr, creator->pub_dsa);
    }
    if (!verified) { why = "the group's creator could not be verified (they may not be in your contacts)"; return false; }
    std::vector<std::string> others;
    bool me_in = false;
    for (const auto& m : info->members) {
        if (m == my_fp_) me_in = true;
        else others.push_back(bytes_to_hex(m));
    }
    if (!me_in || others.empty()) { why = "you are not one of the group's members"; return false; }
    try {
        history_->create_group(conversation_id, info->title, creator_hex, HistoryStore::Saved, 0, info->previous_id, others, HistoryStore::Active,
                               static_cast<int64_t>(sr->record.sent_at));
    } catch (const std::exception& e) {
        why = e.what();
        return false;
    }
    return true;
}

// Messages read back from an archive: checked exactly as when they arrived, then stored as read.
size_t MessagingEngine::restore_records(const Bytes& conversation_id, const std::vector<ArchivedRecord>& records) {
    auto ctx = archive_context(conversation_id);
    if (!ctx) return 0;
    size_t added = 0;
    for (const auto& ar : records) {
        if (ar.record.empty()) continue;
        auto sr = chat::parse_record(ar.record);
        if (!sr || sr->record.conversation_id != conversation_id || sr->record.recipients_hash != ctx->recipients_hash) continue;
        const bool mine = sr->record.sender == my_fp_;
        const std::string sender_hex = bytes_to_hex(sr->record.sender);
        if (mine) {
            if (!chat::verify_record(*sr, keys_.load_public_dsa())) continue;
        } else {
            if (std::find(ctx->others.begin(), ctx->others.end(), sender_hex) == ctx->others.end()) continue;
            auto peer = resolve_peer(sender_hex, conversation_id);
            if (!peer || !chat::verify_record(*sr, peer->pub_dsa)) continue;
        }
        if (sr->record.type == chat::RecordType::Checkpoint) {
            if (!mine) process_checkpoint(conversation_id, *sr, sender_hex);
            continue;
        }
        if (sr->record.type != chat::RecordType::Text && sr->record.type != chat::RecordType::Conversation && sr->record.type != chat::RecordType::Attachment) continue;
        if (sr->record.type == chat::RecordType::Attachment && !chat::parse_attachment_payload(sr->record.payload)) continue;
        HistoryStore::Message m;
        m.conversation_id = conversation_id;
        m.message_id = sr->record.message_id;
        m.outgoing = mine;
        m.sent_at = static_cast<int64_t>(sr->record.sent_at);
        m.received_at = m.sent_at;
        m.status = mine ? HistoryStore::Sent : 1;  // what we sent is sent; what we received is already read
        m.entry_hash = sr->entry_hash;
        m.record = ar.record;
        if (history_->add_message(m)) {
            added++;
            if (sr->record.type == chat::RecordType::Attachment) note_incoming_attachment(*sr, {});  // the archive never holds the key: it will show as unavailable
        }
    }
    return added;
}

bool MessagingEngine::restore_from_relay(RestoreReport& report, std::string& error) {
    report = RestoreReport();
    auto config = keys_.load_mailbox_config();
    if (!config) { error = "Set up messaging first"; return false; }

    Bytes blob;
    bool exists = false;
    {
        RelayClient client;
        if (!connect_authenticated(client, error) || !client.get_keyring(blob, exists, error)) return false;
    }
    if (!exists) {
        error = "The relay holds no saved keyring for this mailbox. It was never saved, or this isn't the mailbox your chats used.";
        return false;
    }
    Bytes key = keys_.derive_local_key("archive keyring");
    auto wipe = make_scope_exit([&] { CryptoEngine::secure_wipe(key); });
    auto plain = key.size() == 32 ? keyring::open(key, config->mailbox_id, blob) : std::nullopt;
    if (!plain) { error = "The saved keyring could not be opened. Your keys must be the ones this mailbox was set up with."; return false; }
    auto contents = keyring::parse(*plain);
    if (!contents) { error = "The saved keyring is damaged, or was made by a newer version of this app"; return false; }
    report.found = true;

    // The small facts that can't be rebuilt from archives.
    const int64_t now = unix_now();
    for (const auto& fp : contents->verified) history_->set_verified(fp, true, now);
    for (const auto& t : contents->member_tokens) history_->save_member_token(t.conversation_id, t.member_fp, t.token, now);
    for (const auto& i : contents->introduced) history_->save_introduced(i.fp, i.bundle, i.issued_at, i.introduced_by, i.first_seen);
    for (const auto& t : contents->issued_tokens) {
        if (!history_->find_issued_token(t.hash)) history_->add_issued_token(t.hash, t.label, t.bound_fp, t.created_at);
        if (t.revoked) history_->mark_token_revoked(t.hash);
    }
    for (const auto& a : contents->archives) {
        HistoryStore::Archive row;
        row.conversation_id = a.conversation_id;
        row.relay_address = a.relay_address;
        row.relay_id = a.relay_id;
        row.role = a.role;
        row.state = a.state;
        row.archive_key = a.archive_key;
        row.chat_public_key = a.chat_public_key;
        row.chat_private_key = a.chat_private_key;
        row.join_token = a.join_token;
        row.created_at = now;
        if (history_->add_archive(row)) report.archives++;
    }

    // Each chat: read its archive from the start (checking the chain), rebuild the chat, read the messages back.
    for (const auto& a : contents->archives) {
        const std::string hex = bytes_to_hex(a.conversation_id);
        const std::string name = hex.substr(0, 8);
        if (a.state != HistoryStore::ArchiveJoined) {
            report.chats_skipped++;
            report.notes.push_back("Chat " + name + ": this device had not finished joining its archive, so there is nothing to read yet.");
            continue;
        }
        std::vector<ArchivedRecord> records;
        std::string err;
        if (!archive_sync(hex, records, err)) {
            report.chats_skipped++;
            report.notes.push_back("Chat " + name + ": its archive could not be read: " + err);
            continue;
        }
        if (!history_->conversation(a.conversation_id)) {
            std::string why = "it is not one of your contacts' chats";
            if (!rebuild_direct_chat(a.conversation_id) && !rebuild_group_chat(a.conversation_id, records, why)) {
                report.chats_skipped++;
                report.notes.push_back("Chat " + name + ": could not be rebuilt: " + why + ".");
                continue;
            }
        }
        report.messages += restore_records(a.conversation_id, records);
        report.chats_restored++;
    }
    for (const auto& r : contents->receipts)
        if (history_->conversation(r.conversation_id)) history_->set_receipt_settings(r.conversation_id, r.delivery, r.read);
    keyring_uploaded_hash_.clear();  // the next look at the keyring may store it again
    bump();
    return true;
}

// --- Deleting by agreement ---

// What each member signs: the exact order the relay will check.
MessagingEngine::Bytes MessagingEngine::sign_deletion(const HistoryStore::Archive& a, const HistoryStore::Deletion& d) {
    return CryptoEngine::sign(relay::archive_delete_signing_input(a.relay_id, a.conversation_id, static_cast<uint32_t>(d.scope), d.op_id,
                                                                  static_cast<uint64_t>(d.expires_at), d.entries),
                              a.chat_private_key);
}

bool MessagingEngine::start_deletion(const Bytes& conversation_id, uint32_t scope, const std::vector<Bytes>& entries, std::string& error) {
    auto ctx = archive_context(conversation_id);
    auto a = history_->archive(conversation_id);
    if (!ctx || !a) { error = "This chat has no archive, so there is nothing to ask everyone to delete"; return false; }
    if (a->state != HistoryStore::ArchiveJoined) { error = "This device has not joined the chat's archive yet"; return false; }
    for (const auto& d : history_->deletions())
        if (d.conversation_id == conversation_id && scope == 1 && d.scope == 1 && (d.state == HistoryStore::DeletionPending || d.state == HistoryStore::DeletionAccepted) && d.expires_at > unix_now()) {
            error = "There is already a request to delete this chat, waiting for answers";
            return false;
        }
    const int64_t now = unix_now();
    HistoryStore::Deletion d;
    d.op_id = CryptoEngine::random_bytes(16);
    d.conversation_id = conversation_id;
    d.scope = static_cast<int>(scope);
    d.expires_at = now + chat::DELETE_REQUEST_LIFETIME_SECONDS;
    d.requester_fp = my_fp_hex_;
    d.entries = entries;
    d.state = HistoryStore::DeletionAccepted;  // whoever asks has agreed
    d.created_at = now;

    chat::DeleteRequestInfo info{scope, d.op_id, static_cast<uint64_t>(d.expires_at), entries};
    Bytes signature, request_raw, accept_raw, request_id = CryptoEngine::random_bytes(chat::ID_BYTES), accept_id = CryptoEngine::random_bytes(chat::ID_BYTES);
    try {
        signature = sign_deletion(*a, d);
        chat::Record rq;
        rq.conversation_id = conversation_id;
        rq.message_id = request_id;
        rq.sender = my_fp_;
        rq.recipients_hash = ctx->recipients_hash;
        rq.sent_at = static_cast<uint64_t>(now);
        rq.type = chat::RecordType::DeleteRequest;
        rq.payload = chat::delete_request_payload(info);
        request_raw = chat::sign_record(rq, dsa_private_);
        chat::Record ac = rq;
        ac.message_id = accept_id;
        ac.type = chat::RecordType::DeleteAccept;
        ac.payload = chat::delete_accept_payload({d.op_id, CryptoEngine::sha256(a->chat_public_key), signature});
        accept_raw = chat::sign_record(ac, dsa_private_);
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
    if (!history_->add_deletion(d)) { error = "That request already exists"; return false; }
    history_->add_deletion_accept(d.op_id, CryptoEngine::sha256(a->chat_public_key), signature, my_fp_hex_);
    // In the archive, where every member will find it; and straight to each member, so they hear at once.
    queue_archive_entry(conversation_id, request_raw, request_id);
    queue_archive_entry(conversation_id, accept_raw, accept_id);
    for (const auto& fp : ctx->others) history_->enqueue(fp, OUTBOX_KIND_MESSAGE, request_id, {request_raw}, now, now);
    bump();
    return true;
}

bool MessagingEngine::request_chat_deletion(const std::string& conversation_id, std::string& error) {
    auto id = hex_to_bytes(conversation_id);
    if (!id) { error = "That chat isn't in your list"; return false; }
    return start_deletion(*id, relay::DELETE_SCOPE_CHAT, {}, error);
}

bool MessagingEngine::request_message_deletion(const std::string& conversation_id, const std::vector<std::string>& message_ids, std::string& error) {
    auto id = hex_to_bytes(conversation_id);
    if (!id) { error = "That chat isn't in your list"; return false; }
    if (message_ids.empty() || message_ids.size() > relay::MAX_DELETE_ENTRIES) { error = "Choose between 1 and 64 messages"; return false; }
    std::vector<Bytes> entries;
    for (const auto& hex : message_ids) {
        auto mid = hex_to_bytes(hex);
        auto number = mid ? history_->archive_message_number(*id, *mid) : std::nullopt;
        auto hash = number ? history_->archive_hash(*id, *number) : std::nullopt;
        if (!hash) { error = "A message you chose isn't in the chat's archive (it was sent before the archive was made), so it can't be deleted for everyone"; return false; }
        if (std::find(entries.begin(), entries.end(), *hash) == entries.end()) entries.push_back(*hash);
    }
    return start_deletion(*id, relay::DELETE_SCOPE_ENTRIES, entries, error);
}

std::vector<MessagingEngine::DeletionInfo> MessagingEngine::deletions() {
    std::vector<DeletionInfo> out;
    for (const auto& d : history_->deletions()) {
        DeletionInfo info;
        info.op_id = bytes_to_hex(d.op_id);
        info.conversation_id = bytes_to_hex(d.conversation_id);
        info.whole_chat = d.scope == 1;
        info.entries = d.entries.size();
        info.requester_fp = d.requester_fp;
        info.requester_name = d.requester_fp == my_fp_hex_ ? std::string("You") : person_name(d.requester_fp);
        info.mine = d.requester_fp == my_fp_hex_;
        info.expires_at = d.expires_at;
        info.state = d.state;
        info.accepted = history_->deletion_accepts(d.op_id).size();
        if (auto ctx = archive_context(d.conversation_id)) info.members = ctx->others.size() + 1;
        out.push_back(std::move(info));
    }
    return out;
}

// Someone in the chat asks to delete it, or some messages of it. Nothing happens unless this user, and
// everyone else, accepts.
bool MessagingEngine::receive_deletion_request(const Peer& sender, const chat::SignedRecord& sr) {
    const Bytes& id = sr.record.conversation_id;
    auto ctx = archive_context(id);
    if (!ctx || std::find(ctx->others.begin(), ctx->others.end(), sender.fp) == ctx->others.end() || sr.record.recipients_hash != ctx->recipients_hash) return false;
    auto info = chat::parse_delete_request_payload(sr.record.payload);
    const int64_t now = unix_now();
    // It must still be live, and not claim to last longer than a request may.
    if (!info || static_cast<int64_t>(info->expires_at) <= now || static_cast<int64_t>(info->expires_at) > now + chat::DELETE_REQUEST_LIFETIME_SECONDS + 3600) return false;
    if (!history_->has_archive(id)) return false;  // without the chat's archive there is nothing to delete
    HistoryStore::Deletion d;
    d.op_id = info->op_id;
    d.conversation_id = id;
    d.scope = static_cast<int>(info->scope);
    d.expires_at = static_cast<int64_t>(info->expires_at);
    d.requester_fp = sender.fp;
    d.entries = info->entries;
    d.state = HistoryStore::DeletionPending;
    d.created_at = now;
    if (!history_->add_deletion(d)) return false;  // already known
    notify(sender.name + " asked to delete " + (info->scope == 1 ? std::string("a whole chat") : std::to_string(info->entries.size()) + " message(s)") +
           " for everyone. It only happens if you all agree.");
    return true;
}

// One member's agreement, with the signature that lets the relay check it.
bool MessagingEngine::receive_deletion_accept(const Peer& sender, const chat::SignedRecord& sr) {
    const Bytes& id = sr.record.conversation_id;
    auto ctx = archive_context(id);
    if (!ctx || std::find(ctx->others.begin(), ctx->others.end(), sender.fp) == ctx->others.end() || sr.record.recipients_hash != ctx->recipients_hash) return false;
    auto info = chat::parse_delete_accept_payload(sr.record.payload);
    auto d = info ? history_->deletion(info->op_id) : std::nullopt;
    if (!d || d->conversation_id != id || d->state == HistoryStore::DeletionDone || d->state == HistoryStore::DeletionExpired) return false;
    history_->add_deletion_accept(d->op_id, info->key_hash, info->signature, sender.fp);
    try_submit_deletion(d->op_id);
    return true;
}

bool MessagingEngine::accept_deletion(const std::string& op_id, std::string& error) {
    auto op = hex_to_bytes(op_id);
    auto d = op ? history_->deletion(*op) : std::nullopt;
    if (!d) { error = "That request isn't known"; return false; }
    if (d->state != HistoryStore::DeletionPending) { error = "That request is no longer waiting for your answer"; return false; }
    if (d->expires_at <= unix_now()) { error = "That request has expired"; return false; }
    auto a = history_->archive(d->conversation_id);
    auto ctx = archive_context(d->conversation_id);
    if (!a || !ctx || a->state != HistoryStore::ArchiveJoined) { error = "This device has not joined the chat's archive, so it can't sign"; return false; }
    const int64_t now = unix_now();
    Bytes accept_id = CryptoEngine::random_bytes(chat::ID_BYTES), accept_raw;
    const Bytes key_hash = CryptoEngine::sha256(a->chat_public_key);
    Bytes signature;
    try {
        signature = sign_deletion(*a, *d);
        chat::Record ac;
        ac.conversation_id = d->conversation_id;
        ac.message_id = accept_id;
        ac.sender = my_fp_;
        ac.recipients_hash = ctx->recipients_hash;
        ac.sent_at = static_cast<uint64_t>(now);
        ac.type = chat::RecordType::DeleteAccept;
        ac.payload = chat::delete_accept_payload({d->op_id, key_hash, signature});
        accept_raw = chat::sign_record(ac, dsa_private_);
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
    history_->add_deletion_accept(d->op_id, key_hash, signature, my_fp_hex_);
    history_->set_deletion_state(d->op_id, HistoryStore::DeletionAccepted);
    queue_archive_entry(d->conversation_id, accept_raw, accept_id);
    history_->enqueue(d->requester_fp, OUTBOX_KIND_MESSAGE, accept_id, {accept_raw}, now, now);  // the one who asked is the one to submit
    bump();
    try_submit_deletion(d->op_id);
    return true;
}

bool MessagingEngine::decline_deletion(const std::string& op_id) {
    auto op = hex_to_bytes(op_id);
    auto d = op ? history_->deletion(*op) : std::nullopt;
    if (!d || d->state != HistoryStore::DeletionPending) return false;
    history_->set_deletion_state(d->op_id, HistoryStore::DeletionDeclined);  // nothing is sent: not answering means no
    bump();
    return true;
}

// The message's content (or the whole chat) is erased here, for good.
void MessagingEngine::apply_deletion_locally(const HistoryStore::Deletion& d) {
    if (d.scope == 1) {
        history_->erase_conversation_messages(d.conversation_id);
        history_->remove_archive(d.conversation_id);
    } else {
        for (const auto& hash : d.entries) {
            auto number = history_->archive_number_of(d.conversation_id, hash);
            if (!number) continue;
            for (const auto& mid : history_->archive_messages_at(d.conversation_id, *number)) history_->erase_message(d.conversation_id, mid);
            history_->mark_archive_redacted(d.conversation_id, *number);
        }
    }
    history_->set_deletion_state(d.op_id, HistoryStore::DeletionDone);
    notify(d.scope == 1 ? "A chat was deleted, by agreement of everyone in it." : "Messages were deleted, by agreement of everyone in the chat.");
    bump();
}

// Once the acceptances are all in, send the order to the relay. The relay checks that every member signed;
// if some haven't, it says so, and this is tried again when another acceptance arrives.
void MessagingEngine::try_submit_deletion(const Bytes& op_id) {
    auto d = history_->deletion(op_id);
    if (!d || d->state != HistoryStore::DeletionAccepted) return;
    auto accepts = history_->deletion_accepts(op_id);
    const std::string key = bytes_to_hex(op_id);
    auto last = deletion_submit_attempts_.find(key);
    if (accepts.size() < 2 || (last != deletion_submit_attempts_.end() && last->second >= accepts.size())) return;
    deletion_submit_attempts_[key] = accepts.size();
    auto a = history_->archive(d->conversation_id);
    if (!a) return;
    relay::ArchiveDelete order;
    order.scope = static_cast<uint32_t>(d->scope);
    order.op_id = d->op_id;
    order.expires_at = static_cast<uint64_t>(d->expires_at);
    order.entry_hashes = d->entries;
    for (const auto& acc : accepts) order.signatures.push_back({acc.key_hash, acc.signature});
    RelayClient client;
    std::string err;
    if (!open_archive_session(*a, client, err)) return;
    if (client.delete_in_archive(order, err)) {
        apply_deletion_locally(*d);
    } else if (err.find("not valid") != std::string::npos) {
        notify("A signature on a deletion request didn't check out, so nothing was deleted.");
    } else if (err.find("expired") != std::string::npos) {
        history_->set_deletion_state(op_id, HistoryStore::DeletionExpired);
    }
    // "Not every member has agreed" is expected until the last acceptance arrives.
}

// Housekeeping: requests lapse; and one this user accepted may have been carried out by someone else.
void MessagingEngine::check_deletions() {
    const auto now = std::chrono::steady_clock::now();
    if (now < next_deletion_check_) return;
    next_deletion_check_ = now + std::chrono::seconds(std::max(1, options_.archive_sync_seconds));
    const int64_t wall = unix_now();
    for (const auto& d : history_->deletions()) {
        if (d.state != HistoryStore::DeletionPending && d.state != HistoryStore::DeletionAccepted) continue;
        if (d.expires_at <= wall) {
            history_->set_deletion_state(d.op_id, HistoryStore::DeletionExpired);
            continue;
        }
        if (d.state != HistoryStore::DeletionAccepted) continue;
        auto a = history_->archive(d.conversation_id);
        if (!a) continue;
        RelayClient client;
        std::string err;
        if (!open_archive_session(*a, client, err)) {
            // The archive is gone and our key with it: the order was carried out.
            if (d.scope == 1 && err.find("Authentication failed") != std::string::npos) apply_deletion_locally(d);
            continue;
        }
        if (d.scope == 2) {
            bool all = true;
            for (const auto& hash : d.entries) {
                auto number = history_->archive_number_of(d.conversation_id, hash);
                if (!number) { all = false; continue; }
                if (history_->archive_redacted(d.conversation_id, *number)) continue;
                std::vector<relay::ArchiveEntry> got;
                relay::ArchiveHead head;
                if (client.fetch_entries(*number, 1, got, head, err) && !got.empty() && got[0].number == *number && got[0].tombstone && got[0].hash == hash)
                    history_->mark_archive_redacted(d.conversation_id, *number);
                else
                    all = false;
            }
            if (all) apply_deletion_locally(d);
        }
        try_submit_deletion(d.op_id);
    }
}

// --- Attachments ---

MessagingEngine::AttachmentView MessagingEngine::attachment_view(const chat::AttachmentInfo& info) {
    AttachmentView v;
    v.file_id = bytes_to_hex(info.file_id);
    v.name = info.name;
    v.size = info.size;
    v.caption = info.caption;
    v.expires_at = info.expires_at;
    v.state = HistoryStore::AttachUnavailable;
    if (auto a = history_->attachment(info.file_id)) {
        v.state = a->state;
        v.outgoing = a->outgoing;
        v.recipients = a->recipients;
        v.redeemed = a->redeemed;
        v.saved_path = a->outgoing ? std::string() : a->path;
        v.note = a->note;
    }
    // The relay's time may have run out since this was last looked at.
    if ((v.state == HistoryStore::AttachAvailable || v.state == HistoryStore::AttachUploading) && unix_now() >= static_cast<int64_t>(info.expires_at)) v.state = HistoryStore::AttachExpired;
    return v;
}

// An attachment arrives: remember how to fetch it. The key and our own token came in the same envelope; if they didn't
// (it was read back from an archive, which never holds them), the file can't be fetched and is shown as such.
void MessagingEngine::note_incoming_attachment(const chat::SignedRecord& sr, const std::vector<chat::AttachmentGrant>& grants) {
    auto info = chat::parse_attachment_payload(sr.record.payload);
    if (!info) return;
    const int64_t now = unix_now();
    HistoryStore::Attachment a;
    a.file_id = info->file_id;
    a.conversation_id = sr.record.conversation_id;
    a.message_id = sr.record.message_id;
    a.outgoing = sr.record.sender == my_fp_;  // one of ours, read back from an archive
    a.name = info->name;
    a.size = info->size;
    a.sha256 = info->sha256;
    a.expires_at = static_cast<int64_t>(info->expires_at);
    a.relay_address = info->relay_address;
    a.relay_id = info->relay_id;
    a.created_at = now;
    a.state = HistoryStore::AttachUnavailable;
    for (const auto& g : grants)
        if (g.file_id == info->file_id) {
            a.key = g.key;
            a.token = g.token;
            a.state = HistoryStore::AttachAvailable;
        }
    if (!parse_server_address(info->relay_address)) a.state = HistoryStore::AttachUnavailable;
    // A record can reach us (by archive catch-up) before the file is fully uploaded and its key sent. If it is recent, say that:
    // it is not "can't be fetched", it is "not ready yet", and the key's arrival will make it available.
    if (a.state == HistoryStore::AttachUnavailable && !a.outgoing && now - static_cast<int64_t>(sr.record.sent_at) < 3600) a.note = "Waiting for the sender's upload to finish";
    // A sender's file is on the sender's own relay. A record that names some other address would make this app connect to
    // wherever a sender chooses (a server of theirs, or one on this machine's own network), so it is not fetched.
    if (a.state == HistoryStore::AttachAvailable && !a.outgoing) {
        auto sender = resolve_peer(bytes_to_hex(sr.record.sender), sr.record.conversation_id);
        auto named = parse_server_address(info->relay_address);
        auto theirs = sender ? parse_server_address(sender->relay_address) : std::nullopt;
        if (!sender || !named || !theirs || named->host != theirs->host || named->port != theirs->port || info->relay_id != sender->relay_id) {
            a.state = HistoryStore::AttachUnavailable;
            a.note = "The file is on a relay that isn't the sender's own, so it will not be fetched";
        }
    }
    if (a.state == HistoryStore::AttachAvailable && a.expires_at <= now) a.state = HistoryStore::AttachExpired;
    if (!history_->add_attachment(a)) {
        // Already known. If it came first from an archive, without its key, and this envelope has it, now it can be fetched.
        auto existing = history_->attachment(a.file_id);
        if (existing && !existing->outgoing && existing->state == HistoryStore::AttachUnavailable && existing->key.empty() && a.state != HistoryStore::AttachUnavailable)
            history_->grant_attachment(a.file_id, a.key, a.token, a.state, a.note);
    }
}

bool MessagingEngine::start_attachment_send(const Bytes& conversation_id, const std::vector<std::string>& recipients, const Bytes& recipients_hash,
                                            const std::vector<Bytes>& seen, const std::filesystem::path& file, const std::string& caption, int days, std::string& error) {
    namespace fs = std::filesystem;
    std::error_code ec;
    if (!fs::is_regular_file(file, ec)) { error = "That isn't a file"; return false; }
    const uint64_t size = fs::file_size(file, ec);
    if (ec) { error = "That file could not be read"; return false; }
    if (size > options_.max_attachment_bytes || size > attachment::MAX_PLAINTEXT_BYTES) {
        error = "That file is too large (" + std::to_string(std::min<uint64_t>(options_.max_attachment_bytes, attachment::MAX_PLAINTEXT_BYTES) / (1024 * 1024)) + " MiB at most)";
        return false;
    }
    if (days < 1 || days > 30) { error = "Choose how long to keep it: 1 to 30 days"; return false; }
    if (recipients.empty() || recipients.size() > relay::MAX_FILE_TOKENS) { error = "There is no one to send it to"; return false; }
    auto config = keys_.load_mailbox_config();
    if (!config) { error = "Set up messaging first"; return false; }
    auto fingerprint = attachment::fingerprint_file(file, error);  // reads the file once; the upload reads it again
    if (!fingerprint) return false;

    const int64_t now = unix_now();
    chat::AttachmentInfo info;
    info.file_id = CryptoEngine::random_bytes(relay::FILE_ID_BYTES);
    info.name = attachment::sanitize_filename(file.filename().u8string());
    info.size = fingerprint->size;
    info.sha256 = fingerprint->sha256;
    info.expires_at = static_cast<uint64_t>(now + static_cast<int64_t>(days) * 86400);
    info.relay_address = format_server_address(ServerAddress{config->host, config->port});
    info.relay_id = config->relay_id;
    info.caption = caption;

    chat::Record r;
    r.conversation_id = conversation_id;
    r.message_id = CryptoEngine::random_bytes(chat::ID_BYTES);
    r.sender = my_fp_;
    r.recipients_hash = recipients_hash;
    r.sent_at = static_cast<uint64_t>(now);
    r.type = chat::RecordType::Attachment;
    r.own_prev = history_->last_entry_hash(conversation_id, true).value_or(Bytes());
    r.seen = seen;
    Bytes raw;
    try {
        r.payload = chat::attachment_payload(info);
        raw = chat::sign_record(r, dsa_private_);
    } catch (const std::exception& e) {
        error = std::string("That can't be sent: ") + e.what();
        return false;
    }
    auto parsed = chat::parse_record(raw);
    if (!parsed) { error = "Could not sign the message"; return false; }

    HistoryStore::Message m;
    m.conversation_id = conversation_id;
    m.message_id = r.message_id;
    m.outgoing = true;
    m.sent_at = now;
    m.received_at = now;
    m.status = HistoryStore::Queued;
    m.entry_hash = parsed->entry_hash;
    m.record = raw;

    HistoryStore::Attachment a;
    a.file_id = info.file_id;
    a.conversation_id = conversation_id;
    a.message_id = r.message_id;
    a.outgoing = true;
    a.name = info.name;
    a.size = info.size;
    a.sha256 = info.sha256;
    a.expires_at = static_cast<int64_t>(info.expires_at);
    a.relay_address = info.relay_address;
    a.relay_id = info.relay_id;
    a.state = HistoryStore::AttachUploading;
    a.key = CryptoEngine::random_bytes(attachment::KEY_BYTES);
    for (const auto& fp : recipients) a.recipient_tokens.emplace_back(fp, CryptoEngine::random_bytes(relay::FILE_TOKEN_BYTES));
    a.path = fs::absolute(file, ec).string();
    a.recipients = static_cast<uint32_t>(recipients.size());
    a.created_at = now;

    history_->add_message(m);
    history_->add_attachment(a);
    // Nothing goes to the recipients until the file is on the relay: the upload job does that when it succeeds.
    history_->enqueue(bytes_to_hex(info.file_id), OUTBOX_KIND_UPLOAD, r.message_id, {raw}, now, now);
    queue_archive_entry(conversation_id, raw, r.message_id);  // the record (never the key or tokens) is archived like any message
    bump();
    return true;
}

bool MessagingEngine::send_attachment(const std::string& contact_fp, const std::filesystem::path& file, const std::string& caption, int days, std::string& error) {
    auto contact = keys_.find_contact_by_fingerprint(contact_fp);
    if (!contact) { error = "That contact isn't in your list"; return false; }
    if (!contact->kem_verified) { error = "Their encryption key isn't verified. Ask them for a new contact card."; return false; }
    if (!contact->can_message()) { error = "You don't have their messaging address yet. Ask them for a new contact card."; return false; }
    auto their_fp = hex_to_bytes(contact_fp);
    if (!their_fp || their_fp->size() != 32) { error = "That contact isn't valid"; return false; }
    auto conv = history_->ensure_conversation(chat::conversation_id_for(my_fp_, *their_fp), contact_fp, unix_now());
    std::vector<Bytes> seen;
    if (auto last_received = history_->last_entry_hash(conv.id, false)) seen.push_back(*last_received);
    return start_attachment_send(conv.id, {contact_fp}, chat::recipients_hash_for({my_fp_, *their_fp}), seen, file, caption, days, error);
}

bool MessagingEngine::send_group_attachment(const std::string& group_id, const std::filesystem::path& file, const std::string& caption, int days, std::string& error) {
    auto id = hex_to_bytes(group_id);
    auto conv = id ? history_->conversation(*id) : std::nullopt;
    if (!conv || conv->kind != HistoryStore::Group) { error = "That group isn't in your list"; return false; }
    std::vector<Bytes> everyone = {my_fp_};
    for (const auto& fp : conv->members) {
        auto raw = hex_to_bytes(fp);
        if (!raw) { error = "That group is damaged"; return false; }
        everyone.push_back(std::move(*raw));
    }
    return start_attachment_send(conv->id, conv->members, chat::recipients_hash_for(everyone), latest_heads(conv->id, conv->members), file, caption, days, error);
}

// --- Transfers: one background thread for uploads and downloads, so a big file never holds up messages ---

void MessagingEngine::queue_transfer(TransferJob job) {
    std::lock_guard<std::mutex> lock(xfer_mutex_);
    if (job.file_id.empty()) return;
    const std::string key = std::string(job.kind == TransferJob::Upload ? "u:" : "d:") + bytes_to_hex(job.file_id);
    if (!xfer_active_.insert(key).second) return;  // already queued or running
    xfer_queue_.push_back(std::move(job));
    if (!xfer_thread_.joinable()) xfer_thread_ = std::thread([this] { transfer_loop(); });
    xfer_cv_.notify_one();
}

void MessagingEngine::transfer_loop() {
    while (true) {
        TransferJob job;
        {
            std::unique_lock<std::mutex> lock(xfer_mutex_);
            xfer_cv_.wait(lock, [&] { return xfer_stop_ || !xfer_queue_.empty(); });
            if (xfer_stop_) return;
            job = std::move(xfer_queue_.front());
            xfer_queue_.pop_front();
        }
        try {
            if (job.kind == TransferJob::Upload) run_upload(job);
            else run_download(job);
        } catch (const std::exception& e) {
            // Whatever went wrong must not end this thread: an upload is tried again from its queue entry, a download can be started again.
            if (job.kind == TransferJob::Download) history_->set_attachment_state(job.file_id, HistoryStore::AttachAvailable, std::string("The download failed: ") + e.what());
        }
        {
            std::lock_guard<std::mutex> lock(xfer_mutex_);
            xfer_active_.erase(std::string(job.kind == TransferJob::Upload ? "u:" : "d:") + bytes_to_hex(job.file_id));
            xfer_progress_.erase(bytes_to_hex(job.file_id));
        }
        bump();
    }
}

void MessagingEngine::stop_transfers() {
    xfer_cancel_ = true;
    {
        std::lock_guard<std::mutex> lock(xfer_mutex_);
        xfer_stop_ = true;
    }
    xfer_cv_.notify_all();
    if (xfer_thread_.joinable()) xfer_thread_.join();
}

bool MessagingEngine::attachment_progress(const std::string& file_id, uint64_t& done, uint64_t& total) {
    std::lock_guard<std::mutex> lock(xfer_mutex_);
    auto it = xfer_progress_.find(file_id);
    if (it == xfer_progress_.end()) return false;
    done = it->second.first;
    total = it->second.second;
    return true;
}

void MessagingEngine::run_upload(const TransferJob& job) {
    auto a = history_->attachment(job.file_id);
    const int64_t now = unix_now();
    auto finish_queue_entry = [&] { if (job.outbox_id) history_->outbox_done(job.outbox_id); };
    auto retry_later = [&] { if (job.outbox_id) history_->outbox_failed(job.outbox_id, now + std::max(1, options_.retry_base_seconds) * 4); };
    auto give_up = [&](const std::string& why) {
        history_->set_attachment_state(job.file_id, HistoryStore::AttachFailed, why);
        finish_queue_entry();
        notify("An attachment could not be sent: " + why);
    };
    if (!a || !a->outgoing || a->state != HistoryStore::AttachUploading) { finish_queue_entry(); return; }  // withdrawn, or already done
    if (a->expires_at <= now + 60) { give_up("it took too long to upload, and its time on the relay has run out"); return; }

    // It must still be the file that was attached.
    std::string err;
    auto fingerprint = attachment::fingerprint_file(a->path, err);
    if (!fingerprint) { give_up(err); return; }
    if (fingerprint->size != a->size || fingerprint->sha256 != a->sha256) { give_up("the file changed after it was attached"); return; }

    attachment::Encryptor encryptor(a->path, a->key, a->file_id, a->size);
    relay::FileBegin begin;
    begin.file_id = a->file_id;
    begin.total_size = encryptor.plan().ciphertext_size;
    begin.chunk_size = encryptor.plan().chunk_size;
    begin.chunk_count = encryptor.plan().chunk_count;
    begin.expires_at = static_cast<uint64_t>(a->expires_at);
    for (const auto& [fp, token] : a->recipient_tokens) begin.token_hashes.push_back(CryptoEngine::sha256(token));

    RelayClient client;
    if (!connect_authenticated(client, err)) { retry_later(); return; }  // the relay is down: wait and try again
    const std::string key = bytes_to_hex(job.file_id);
    {
        std::lock_guard<std::mutex> lock(xfer_mutex_);
        xfer_progress_[key] = {0, begin.total_size};
    }
    std::string source_error;
    bool uploaded = client.upload_file(begin, [&](uint32_t index, Bytes& out) {
        if (xfer_cancel_) return false;
        if (!encryptor.chunk(index, out, source_error)) return false;
        std::lock_guard<std::mutex> lock(xfer_mutex_);
        xfer_progress_[key].first = std::min<uint64_t>(begin.total_size, static_cast<uint64_t>(index + 1) * begin.chunk_size);
        return true;
    }, err);
    if (!uploaded && err.find("already exists") != std::string::npos) {
        // An earlier try got all the way there but its confirmation never reached us: if the file is complete, that will do.
        RelayClient check;
        relay::FileStatus status;
        std::string e2;
        if (connect_authenticated(check, e2) && check.file_status(a->file_id, status, e2) && status.ready) uploaded = true;
    }
    if (!uploaded) {
        if (xfer_cancel_) return;  // shutting down: the queue entry stays, and it starts again next time
        if (!source_error.empty()) { give_up(source_error); return; }
        const bool permanent = err.find("larger than this relay allows") != std::string::npos || err.find("would go over this relay's limit") != std::string::npos ||
                               err.find("expiry must be") != std::string::npos;
        if (permanent) give_up(err);
        else retry_later();
        return;
    }

    // It is on the relay. If it was withdrawn while it uploaded, take it down again.
    auto latest = history_->attachment(job.file_id);
    if (!latest || latest->state != HistoryStore::AttachUploading) {
        RelayClient c;
        std::string e;
        if (connect_authenticated(c, e)) c.cancel_file(job.file_id, e);
        finish_queue_entry();
        return;
    }
    // Now each recipient is told, in their own envelope: the record, and their own file key and token.
    auto message = history_->find_message(a->conversation_id, a->message_id);
    if (!message) { give_up("the message is gone"); return; }
    for (const auto& [fp, token] : a->recipient_tokens)
        history_->enqueue(fp, OUTBOX_KIND_ATTACHMENT, a->message_id, {message->record, encode_grant(a->file_id, a->key, token)}, now, now);
    history_->set_attachment_state(job.file_id, HistoryStore::AttachAvailable, std::string());
    history_->drop_attachment_secrets(job.file_id);  // the tokens are in the queued envelopes now, and nowhere else
    finish_queue_entry();
}

std::optional<MessagingEngine::AttachmentView> MessagingEngine::attachment(const std::string& file_id) {
    auto id = hex_to_bytes(file_id);
    auto a = id ? history_->attachment(*id) : std::nullopt;
    if (!a) return std::nullopt;
    AttachmentView v;
    v.file_id = file_id;
    v.name = a->name;
    v.size = a->size;
    v.expires_at = a->expires_at;
    v.state = a->state;
    v.outgoing = a->outgoing;
    v.recipients = a->recipients;
    v.redeemed = a->redeemed;
    v.saved_path = a->outgoing ? std::string() : a->path;
    v.note = a->note;
    if ((v.state == HistoryStore::AttachAvailable || v.state == HistoryStore::AttachUploading) && unix_now() >= a->expires_at) v.state = HistoryStore::AttachExpired;
    return v;
}

bool MessagingEngine::download_attachment(const std::string& file_id, const std::filesystem::path& directory, std::string& error) {
    auto id = hex_to_bytes(file_id);
    auto a = id ? history_->attachment(*id) : std::nullopt;
    if (!a || a->outgoing) { error = "That attachment isn't one you can download"; return false; }
    switch (a->state) {
        case HistoryStore::AttachAvailable: break;
        case HistoryStore::AttachDownloading: error = "It is already being downloaded"; return false;
        case HistoryStore::AttachTransferred: error = "You have already downloaded it"; return false;
        case HistoryStore::AttachExpired: error = "It has expired: the relay no longer holds it"; return false;
        case HistoryStore::AttachWithdrawn: error = "The sender took it back"; return false;
        default:
            error = a->note.rfind("Waiting", 0) == 0 ? "It isn't ready yet: the sender is still uploading it. Try again in a moment."
                                                     : "It can't be downloaded: it reached you without the key it needs";
            return false;
    }
    if (unix_now() >= a->expires_at) {
        history_->set_attachment_state(*id, HistoryStore::AttachExpired, std::string());
        error = "It has expired: the relay no longer holds it";
        return false;
    }
    std::error_code ec;
    if (!std::filesystem::is_directory(directory, ec)) { error = "That folder doesn't exist"; return false; }
    history_->set_attachment_state(*id, HistoryStore::AttachDownloading, std::string());
    {
        std::lock_guard<std::mutex> lock(xfer_mutex_);
        xfer_progress_[file_id] = {0, a->size};
    }
    queue_transfer({TransferJob::Download, *id, 0, directory.string()});
    bump();
    return true;
}

void MessagingEngine::run_download(const TransferJob& job) {
    auto a = history_->attachment(job.file_id);
    if (!a || a->outgoing || a->state != HistoryStore::AttachDownloading) return;
    const std::string key = bytes_to_hex(job.file_id);
    auto back = [&](const std::string& why) { history_->set_attachment_state(job.file_id, HistoryStore::AttachAvailable, why); };
    std::string err;
    auto address = parse_server_address(a->relay_address);
    if (!address) { history_->set_attachment_state(job.file_id, HistoryStore::AttachUnavailable, "The relay's address isn't valid"); return; }

    attachment::Decryptor decryptor(job.directory, a->name, a->key, a->file_id, a->size, a->sha256);
    if (!decryptor.begin(true, err)) { back(err); return; }  // carries on from what an earlier attempt left
    {
        std::lock_guard<std::mutex> lock(xfer_mutex_);
        xfer_progress_[key] = {std::min<uint64_t>(a->size, static_cast<uint64_t>(decryptor.next_chunk()) * attachment::CHUNK_PLAINTEXT_BYTES), a->size};
    }
    RelayClient client;
    if (!client.connect(address->host, address->port, a->relay_id, options_.connect_timeout_seconds, err)) { back("Could not reach the relay: " + err); return; }

    std::string sink_error;
    relay::FileInfo info;
    bool ok = true;
    if (decryptor.next_chunk() < decryptor.chunk_count()) {
        ok = client.download_file(a->file_id, a->token, decryptor.next_chunk(), info, [&](uint32_t index, const Bytes& chunk) {
            if (xfer_cancel_) { sink_error = "interrupted"; return false; }
            if (!decryptor.accept(index, chunk, sink_error)) return false;
            std::lock_guard<std::mutex> lock(xfer_mutex_);
            xfer_progress_[key].first = std::min<uint64_t>(a->size, static_cast<uint64_t>(index + 1) * attachment::CHUNK_PLAINTEXT_BYTES);
            return true;
        }, err);
    }
    if (!ok) {
        if (xfer_cancel_) { back("The download was interrupted; start it again to carry on"); return; }
        if (!sink_error.empty()) {  // what the relay sent didn't open or didn't fit: throw it away
            decryptor.abort();
            back("The file could not be received intact (" + sink_error + "); try again");
            return;
        }
        // When the file is gone for good, the partial file it started is no use to anyone: remove it. (For anything a retry
        // could fix, such as the relay being unreachable, it stays so the download can carry on from there.)
        if (err.find("expired") != std::string::npos) { decryptor.abort(); history_->set_attachment_state(job.file_id, HistoryStore::AttachExpired, std::string()); }
        else if (err.find("already downloaded") != std::string::npos) { decryptor.abort(); history_->set_attachment_state(job.file_id, HistoryStore::AttachTransferred, "It was already downloaded with this token, before"); }
        else if (err.find("No such file") != std::string::npos) {  // gone: its time ran out, or the sender took it back (the relay says the same either way)
            decryptor.abort();
            history_->set_attachment_state(job.file_id, unix_now() >= a->expires_at ? HistoryStore::AttachExpired : HistoryStore::AttachWithdrawn, std::string());
        } else back("Could not download it: " + err);  // the relay couldn't be reached, say: it can be tried again
        return;
    }

    // Every chunk opened. Now the whole thing is checked against the fingerprint the sender signed, and only then saved.
    std::filesystem::path saved;
    if (!decryptor.finish(saved, err)) { back(err); return; }
    // The file is safe and checked: only now is the one-time token used up.
    std::string redeem_error;
    if (!client.redeem_file(a->file_id, a->token, redeem_error)) {
        RelayClient again;
        std::string e;
        if (again.connect(address->host, address->port, a->relay_id, options_.connect_timeout_seconds, e)) again.redeem_file(a->file_id, a->token, e);
    }
    history_->set_attachment_path(job.file_id, saved.string());
    history_->set_attachment_state(job.file_id, HistoryStore::AttachTransferred, std::string());
    notify("Saved " + a->name + " to " + saved.string());
}

bool MessagingEngine::withdraw_attachment(const std::string& file_id, std::string& error) {
    auto id = hex_to_bytes(file_id);
    auto a = id ? history_->attachment(*id) : std::nullopt;
    if (!a || !a->outgoing) { error = "That isn't an attachment you sent"; return false; }
    if (a->state == HistoryStore::AttachUploading) {
        // Not on the relay yet (or only just): the upload job notices and takes down whatever got there.
        history_->set_attachment_state(*id, HistoryStore::AttachWithdrawn, std::string());
        bump();
        return true;
    }
    if (a->state != HistoryStore::AttachAvailable) { error = "It is no longer on the relay"; return false; }
    RelayClient client;
    if (!connect_authenticated(client, error)) return false;
    std::string cancel_error;
    if (!client.cancel_file(*id, cancel_error) && cancel_error.find("isn't one of your files") == std::string::npos) {
        error = cancel_error;
        return false;
    }
    history_->set_attachment_state(*id, HistoryStore::AttachWithdrawn, std::string());
    bump();
    return true;
}

// Housekeeping: time runs out, and a sender finds out how many have fetched their file.
void MessagingEngine::check_attachments() {
    const auto now = std::chrono::steady_clock::now();
    if (now < next_attachment_check_) return;
    next_attachment_check_ = now + std::chrono::seconds(std::max(1, options_.archive_sync_seconds));
    const int64_t wall = unix_now();
    for (const auto& a : history_->attachments_in_state(HistoryStore::AttachAvailable)) {
        if (wall >= a.expires_at) {
            history_->set_attachment_state(a.file_id, HistoryStore::AttachExpired, std::string());
            bump();
            continue;
        }
        if (!a.outgoing) continue;
        RelayClient client;
        relay::FileStatus status;
        std::string err;
        if (!connect_authenticated(client, err)) continue;
        if (client.file_status(a.file_id, status, err)) {
            if (status.tokens_redeemed != a.redeemed) {
                history_->set_attachment_redeemed(a.file_id, status.tokens_redeemed);
                bump();
            }
        } else if (err.find("isn't one of your files") != std::string::npos) {
            // Gone from the relay before its time, and we didn't withdraw it: every recipient has fetched it.
            history_->set_attachment_redeemed(a.file_id, a.recipients);
            history_->set_attachment_state(a.file_id, HistoryStore::AttachTransferred, std::string());
            bump();
        }
    }
}

// --- Sending ---

void MessagingEngine::flush_outbox() {
    const int64_t now = unix_now();
    for (auto& item : history_->due_items(now, 20)) {
        try {
        // An entry for a chat's archive: added when the archive can be reached, whatever happens to the envelopes.
        if (item.kind == OUTBOX_KIND_ARCHIVE) {
            flush_archive_item(item, now);
            continue;
        }
        // A file waiting to be uploaded: that is done on the transfer thread. Look again later, in case it fails.
        if (item.kind == OUTBOX_KIND_UPLOAD) {
            history_->outbox_failed(item.id, now + 30);
            queue_transfer({TransferJob::Upload, hex_to_bytes(item.contact_fp).value_or(Bytes()), item.id, std::string()});
            continue;
        }
        // What is this item about? Tokens a member gave us for one group only work for that group's items.
        Bytes item_conv;
        for (const auto& raw : item.records)
            if (auto parsed = chat::parse_record(raw)) { item_conv = parsed->record.conversation_id; break; }
        auto peer = resolve_peer(item.contact_fp, item_conv);
        if (!peer || !peer->can_send) {  // no way to reach them (yet): try again later
            history_->outbox_failed(item.id, now + retry_delay(item.attempts));
            continue;
        }
        // An envelope someone sealed for another member, passed on as it is (we are the group's creator).
        if (item.kind == OUTBOX_KIND_RELAY) {
            if (item.records.size() != 1) { history_->outbox_done(item.id); continue; }  // malformed: nothing to send
            auto address = parse_server_address(peer->relay_address);
            RelayClient depositor;
            std::string err;
            if (!address || !depositor.connect(address->host, address->port, peer->relay_id, options_.connect_timeout_seconds, err) ||
                !depositor.deposit(peer->mailbox_id, peer->send_token, item.records[0], options_.envelope_ttl_seconds, nullptr, err)) {
                history_->outbox_failed(item.id, now + retry_delay(item.attempts));
                continue;
            }
            history_->outbox_done(item.id);
            continue;
        }

        std::vector<Bytes> records = item.records;
        // A job to make tokens becomes signed Forward records for the creator (once; a retry reuses them).
        if (item.kind == OUTBOX_KIND_GRANTS && !records.empty() && !chat::parse_record(records.front())) {
            std::vector<Bytes> forwards;
            if (!build_grant_forwards(item, forwards)) {
                history_->outbox_failed(item.id, now + 15);
                continue;
            }
            if (forwards.empty()) { history_->outbox_done(item.id); continue; }  // nobody needed one after all
            records.assign(forwards.begin(), forwards.begin() + static_cast<std::ptrdiff_t>(std::min(forwards.size(), FORWARDS_PER_ENVELOPE)));
            history_->update_outbox_records(item.id, records);
            for (size_t start = FORWARDS_PER_ENVELOPE; start < forwards.size(); start += FORWARDS_PER_ENVELOPE) {
                std::vector<Bytes> more(forwards.begin() + static_cast<std::ptrdiff_t>(start),
                                        forwards.begin() + static_cast<std::ptrdiff_t>(std::min(forwards.size(), start + FORWARDS_PER_ENVELOPE)));
                history_->enqueue(item.contact_fp, OUTBOX_KIND_GRANTS, CryptoEngine::random_bytes(chat::ID_BYTES), more, now, now);
            }
        }
        // Someone we know only from a group is not a contact: no first-message introduction for them.
        const bool first_message = (item.kind == OUTBOX_KIND_MESSAGE || item.kind == OUTBOX_KIND_ATTACHMENT) && peer->is_contact && !history_->bundle_sent(item.contact_fp);

        // First message to someone: give them a token for writing back, and introduce ourselves.
        if (first_message) {
            bool has_grant = false;
            for (const auto& raw : records)
                if (auto sr = chat::parse_record(raw)) has_grant |= sr->record.type == chat::RecordType::TokenGrant;
            if (!has_grant) {
                Bytes token = CryptoEngine::random_bytes(relay::SEND_TOKEN_BYTES);
                std::string err;
                if (!owner_.add_token(CryptoEngine::sha256(token), err)) {
                    history_->outbox_failed(item.id, now + 15);
                    continue;
                }
                history_->add_issued_token(CryptoEngine::sha256(token), "first message to " + peer->name, item.contact_fp, now);

                auto their_fp = hex_to_bytes(item.contact_fp);
                chat::Record g;
                g.conversation_id = chat::conversation_id_for(my_fp_, *their_fp);
                g.message_id = CryptoEngine::random_bytes(chat::ID_BYTES);
                g.sender = my_fp_;
                g.recipients_hash = chat::recipients_hash_for({my_fp_, *their_fp});
                g.sent_at = static_cast<uint64_t>(now);
                g.type = chat::RecordType::TokenGrant;
                g.payload = token;
                records.insert(records.begin(), chat::sign_record(g, dsa_private_));
                history_->update_outbox_records(item.id, records);
            }
        }

        // The queued items are signed records, plus (for a group invitation) bundles to introduce.
        chat::Inner inner;
        for (const auto& raw : records) {
            if (chat::parse_record(raw)) inner.records.push_back(raw);
            else if (item.kind == OUTBOX_KIND_ATTACHMENT) {
                if (auto grant = decode_grant(raw)) inner.grants.push_back(std::move(*grant));  // this recipient's file key and token
            } else inner.introduced.push_back(raw);
        }
        try {
            if (first_message) inner.sender_bundle = own_bundle_raw();
            Bytes envelope = chat::seal_envelope(inner, peer->pub_kem);

            auto address = parse_server_address(peer->relay_address);
            if (!address) throw std::runtime_error("Their relay address is not valid");
            RelayClient depositor;
            std::string err;
            if (!depositor.connect(address->host, address->port, peer->relay_id, options_.connect_timeout_seconds, err) ||
                !depositor.deposit(peer->mailbox_id, peer->send_token, envelope, options_.envelope_ttl_seconds, nullptr, err)) {
                if (err.find("Unknown mailbox or token") != std::string::npos) {
                    const std::string key = "dead-token:" + item.contact_fp;
                    bool first_time;
                    { std::lock_guard<std::mutex> lock(mutex_); first_time = told_about_.insert(key).second; }
                    if (first_time)
                        notify(peer->name + "'s contact card no longer works, so your messages to them are waiting. Ask them for a new card.");
                }
                history_->outbox_failed(item.id, now + retry_delay(item.attempts));
                continue;
            }
        } catch (const std::exception& e) {
            history_->outbox_failed(item.id, now + retry_delay(item.attempts));
            continue;
        }

        history_->outbox_done(item.id);
        if (first_message) history_->set_bundle_sent(item.contact_fp);
        if (item.kind == OUTBOX_KIND_MESSAGE || item.kind == OUTBOX_KIND_ATTACHMENT) {
            if (auto conv = history_->conversation_of_outgoing(item.message_id))
                history_->raise_delivery(*conv, item.message_id, item.contact_fp, HistoryStore::Sent);
            {
                std::lock_guard<std::mutex> lock(mutex_);
                told_about_.erase("dead-token:" + item.contact_fp);
            }
        }
        bump();
        } catch (const std::exception&) {
            // Whatever went wrong, it must not escape the pump thread: try this item again later.
            history_->outbox_failed(item.id, now + retry_delay(item.attempts));
        }
    }
}

// --- The loop ---

bool MessagingEngine::try_connect_owner() {
    auto config = keys_.load_mailbox_config();
    if (!config) return false;
    std::string err;
    owner_.close();
    if (connect_authenticated(owner_, err) && owner_.collect(err)) {
        connected_ = true;
        backoff_seconds_ = 0;
        last_ping_ = std::chrono::steady_clock::now();
        set_status("Connected");
        bump();
        return true;
    }
    owner_.close();
    backoff_seconds_ = backoff_seconds_ == 0 ? options_.reconnect_min_seconds
                                             : std::min(backoff_seconds_ * 2, options_.reconnect_max_seconds);
    next_attempt_ = std::chrono::steady_clock::now() + std::chrono::seconds(backoff_seconds_);
    set_status("Can't reach the relay: " + err);
    return false;
}

void MessagingEngine::pump(int wait_ms) {
    if (!is_set_up()) {
        set_status("Messaging is not set up");
        std::this_thread::sleep_for(std::chrono::milliseconds(std::min(wait_ms, 250)));
        return;
    }

    if (!owner_.connected()) {
        if (connected_.exchange(false)) bump();
        if (std::chrono::steady_clock::now() >= next_attempt_) try_connect_owner();
        if (!owner_.connected()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(std::min(wait_ms, 250)));
            return;
        }
    }

    // Take what the relay has for us, then tell it what we have safely stored.
    std::vector<Bytes> to_ack;
    auto event = owner_.next_event(wait_ms);
    for (int handled = 0; handled < 32; handled++) {
        if (event.kind == RelayClient::Event::Kind::Envelope) {
            try {
                if (process_envelope(event.envelope)) to_ack.push_back(event.envelope.id);
            } catch (const std::exception& e) {
                notify(std::string("Could not process a message: ") + e.what());  // not acknowledged, so it is retried
            }
        } else if (event.kind == RelayClient::Event::Kind::Closed) {
            set_status("Disconnected: " + event.text);
            connected_ = false;
            backoff_seconds_ = options_.reconnect_min_seconds;
            next_attempt_ = std::chrono::steady_clock::now() + std::chrono::seconds(backoff_seconds_);
            bump();
            break;
        } else if (event.kind == RelayClient::Event::Kind::Timeout) {
            break;
        }
        event = owner_.next_event(0);
    }
    if (!to_ack.empty() && owner_.connected()) {
        std::string err;
        if (!owner_.acknowledge(to_ack, nullptr, err)) set_status("Disconnected: " + err);
    }
    if (!owner_.connected()) return;

    if (std::chrono::steady_clock::now() - last_ping_ > std::chrono::seconds(options_.ping_seconds)) {
        std::string err;
        last_ping_ = std::chrono::steady_clock::now();
        if (!owner_.ping(err)) set_status("Disconnected: " + err);
    }
    if (owner_.connected()) {
        flush_outbox();
        join_pending_archives();
        ensure_archives();
        sync_archives();
        check_deletions();
        check_attachments();
        maintain_keyring();
    }
}
