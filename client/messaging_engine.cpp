#include "messaging_engine.h"

#include "crypto_engine.h"
#include "protocol.h"
#include "scope_exit.h"

#include <algorithm>
#include <ctime>
#include <thread>

namespace fs = std::filesystem;

namespace {

int64_t unix_now() { return static_cast<int64_t>(std::time(nullptr)); }

constexpr size_t MAX_PENDING_REQUESTS = 100;
constexpr int OUTBOX_KIND_MESSAGE = 0;
constexpr int OUTBOX_KIND_RECEIPT = 1;

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

    my_fp_hex_ = keys_.own_fingerprint();
    auto fp = hex_to_bytes(my_fp_hex_);
    if (!fp || fp->size() != 32) throw std::runtime_error("Your keys could not be loaded");
    my_fp_ = std::move(*fp);
}

MessagingEngine::~MessagingEngine() {
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
        auto record = chat::parse_record(m.record);
        if (!record || record->record.type != chat::RecordType::Text) continue;
        ChatMessage cm;
        cm.row = m.row;
        cm.outgoing = m.outgoing;
        cm.sent_at = m.sent_at;
        cm.text.assign(record->record.payload.begin(), record->record.payload.end());
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
    bump();
    return true;
}

void MessagingEngine::enqueue_receipt(const std::string& contact_fp, chat::ReceiptKind kind, const std::vector<Bytes>& ids, bool delayed) {
    auto contact = keys_.find_contact_by_fingerprint(contact_fp);
    auto their_fp = hex_to_bytes(contact_fp);
    if (!contact || !contact->can_message() || !their_fp || their_fp->size() != 32 || ids.empty()) return;

    // At most 256 messages per receipt record.
    for (size_t start = 0; start < ids.size(); start += 256) {
        std::vector<Bytes> chunk(ids.begin() + static_cast<std::ptrdiff_t>(start),
                                 ids.begin() + static_cast<std::ptrdiff_t>(std::min(ids.size(), start + 256)));
        chat::Record r;
        r.conversation_id = chat::conversation_id_for(my_fp_, *their_fp);
        r.message_id = CryptoEngine::random_bytes(chat::ID_BYTES);
        r.sender = my_fp_;
        r.recipients_hash = chat::recipients_hash_for({my_fp_, *their_fp});
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
            history_->enqueue(contact_fp, OUTBOX_KIND_RECEIPT, r.message_id, {raw}, due, unix_now());
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

    // The record must be for exactly this conversation and exactly us two, or it has been redirected.
    const Bytes conv_id = chat::conversation_id_for(my_fp_, *their_fp);
    if (sr.record.conversation_id != conv_id) return false;
    if (sr.record.recipients_hash != chat::recipients_hash_for({my_fp_, *their_fp})) return false;

    const int64_t now = unix_now();
    switch (sr.record.type) {
        case chat::RecordType::Text: {
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
            if (!history_->add_message(m)) return false;  // a duplicate or replay
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
        case chat::RecordType::Conversation:
            return false;  // groups are handled in a later step
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

bool MessagingEngine::process_envelope(const relay::StoredEnvelope& envelope) {
    auto inner = chat::open_envelope(envelope.envelope, kem_private_);
    if (!inner) return true;  // not for us, or damaged: nothing to keep, so let the relay delete it

    std::optional<IdentityBundle> bundle;
    if (!inner->sender_bundle.empty()) bundle = parse_identity_bundle(inner->sender_bundle);

    std::vector<chat::SignedRecord> records;
    for (const auto& raw : inner->records)
        if (auto sr = chat::parse_record(raw)) records.push_back(std::move(*sr));
    if (records.empty()) return true;

    const Bytes sender = records.front().record.sender;
    const std::string sender_hex = bytes_to_hex(sender);

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
            changed |= handle_record(*contact, sr, true);
        }
        note_token_use(envelope.token_hash, sender_hex);
        if (changed) bump();
        return true;
    }

    // Someone we don't know. They must introduce themselves with a self-signed bundle, and every
    // record must verify against it. What they sent waits as a request until the user decides.
    if (!bundle || bundle->fingerprint() != sender_hex) return true;
    std::vector<Bytes> verified;
    for (const auto& sr : records)
        if (sr.record.sender == sender && chat::verify_record(sr, bundle->signing_key)) verified.push_back(sr.raw);
    if (verified.empty()) return true;
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
    for (const auto& row : rows)
        for (const auto& raw : row.records)
            if (auto sr = chat::parse_record(raw))
                if (chat::verify_record(*sr, contact->pub_dsa)) handle_record(*contact, *sr, true);
    history_->delete_requests(sender_fp);
    bump();
    return true;
}

void MessagingEngine::decline_request(const std::string& sender_fp) {
    history_->delete_requests(sender_fp);
    bump();
}

// --- Sending ---

void MessagingEngine::flush_outbox() {
    const int64_t now = unix_now();
    for (auto& item : history_->due_items(now, 20)) {
        try {
        auto contact = keys_.find_contact_by_fingerprint(item.contact_fp);
        if (!contact || !contact->can_message()) {
            history_->outbox_failed(item.id, now + retry_delay(item.attempts));
            continue;
        }
        const bool first_message = item.kind == OUTBOX_KIND_MESSAGE && !history_->bundle_sent(item.contact_fp);
        std::vector<Bytes> records = item.records;

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
                history_->add_issued_token(CryptoEngine::sha256(token), "first message to " + contact->name, item.contact_fp, now);

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

        chat::Inner inner;
        inner.records = records;
        try {
            if (first_message) inner.sender_bundle = own_bundle_raw();
            Bytes envelope = chat::seal_envelope(inner, contact->pub_kem);

            auto address = parse_server_address(contact->relay_address);
            if (!address) throw std::runtime_error("Their relay address is not valid");
            RelayClient depositor;
            std::string err;
            if (!depositor.connect(address->host, address->port, contact->relay_id, options_.connect_timeout_seconds, err) ||
                !depositor.deposit(contact->mailbox_id, contact->send_token, envelope, options_.envelope_ttl_seconds, nullptr, err)) {
                if (err.find("Unknown mailbox or token") != std::string::npos) {
                    const std::string key = "dead-token:" + item.contact_fp;
                    bool first_time;
                    { std::lock_guard<std::mutex> lock(mutex_); first_time = told_about_.insert(key).second; }
                    if (first_time)
                        notify(contact->name + "'s contact card no longer works, so your messages to them are waiting. Ask them for a new card.");
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
        if (item.kind == OUTBOX_KIND_MESSAGE) {
            auto their_fp = hex_to_bytes(item.contact_fp);
            history_->raise_delivery(chat::conversation_id_for(my_fp_, *their_fp), item.message_id, item.contact_fp, HistoryStore::Sent);
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
    if (owner_.connected()) flush_outbox();
}
