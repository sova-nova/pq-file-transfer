#include "relay_protocol.h"

#include "protocol.h"

namespace relay {

namespace {

// A blob that must be exactly `size` bytes.
std::optional<std::vector<uint8_t>> fixed_blob(const std::vector<uint8_t>& in, size_t& off, size_t size) {
    auto blob = read_blob(in.data(), in.size(), off, size);
    if (!blob || blob->size() != size) return std::nullopt;
    return blob;
}

bool at_end(const std::vector<uint8_t>& in, size_t off) { return off == in.size(); }

const char HELLO_LABEL[] = "pq-suite v3 relay hello";
const char REGISTER_LABEL[] = "pq-suite v3 relay register";
const char AUTH_LABEL[] = "pq-suite v3 relay auth";
const char ARCHIVE_JOIN_LABEL[] = "pq-suite v3 archive join";
const char ARCHIVE_AUTH_LABEL[] = "pq-suite v3 archive auth";
const char ARCHIVE_GENESIS_LABEL[] = "pq-suite v3 archive genesis";
const char ARCHIVE_ENTRY_LABEL[] = "pq-suite v3 archive entry";
const char ARCHIVE_DELETE_LABEL[] = "pq-suite v3 archive delete";

}  // namespace

// --- encode ---

std::vector<uint8_t> encode(const Hello& m) {
    std::vector<uint8_t> b;
    write_u32(b, m.version);
    write_blob(b, m.client_nonce);
    return b;
}

std::vector<uint8_t> encode(const HelloReply& m) {
    std::vector<uint8_t> b;
    write_blob(b, m.relay_public_key);
    write_blob(b, m.signature);
    write_blob(b, m.auth_challenge);
    return b;
}

std::vector<uint8_t> encode(const Register& m) {
    std::vector<uint8_t> b;
    write_blob(b, m.invite);
    write_blob(b, m.mailbox_id);
    write_blob(b, m.access_public_key);
    write_blob(b, m.send_token_hash);
    write_blob(b, m.signature);
    return b;
}

std::vector<uint8_t> encode(const Auth& m) {
    std::vector<uint8_t> b;
    write_blob(b, m.mailbox_id);
    write_blob(b, m.signature);
    return b;
}

std::vector<uint8_t> encode(const Deposit& m) {
    std::vector<uint8_t> b;
    write_blob(b, m.mailbox_id);
    write_blob(b, m.send_token);
    write_u32(b, m.ttl_seconds);
    write_blob(b, m.envelope);
    return b;
}

std::vector<uint8_t> encode(const StoredEnvelope& m) {
    std::vector<uint8_t> b;
    write_blob(b, m.id);
    write_u64(b, m.deposited_at);
    write_blob(b, m.token_hash);
    write_blob(b, m.envelope);
    return b;
}

std::vector<uint8_t> encode(const IdList& m) {
    std::vector<uint8_t> b;
    write_u32(b, static_cast<uint32_t>(m.ids.size()));
    for (const auto& id : m.ids) write_blob(b, id);
    return b;
}

std::vector<uint8_t> encode(const InviteStatus& m) {
    std::vector<uint8_t> b;
    write_u32(b, m.max_unused);
    write_u32(b, m.max_total);
    write_u32(b, static_cast<uint32_t>(m.unused.size()));
    for (const auto& u : m.unused) {
        write_blob(b, u.hash);
        write_u64(b, u.expires_at);
    }
    write_u32(b, static_cast<uint32_t>(m.joined.size()));
    for (const auto& j : m.joined) {
        write_blob(b, j.mailbox_id);
        write_u64(b, j.joined_at);
    }
    return b;
}

std::vector<uint8_t> encode(const ArchiveCreate& m) {
    std::vector<uint8_t> b;
    write_blob(b, m.archive_id);
    write_u32(b, static_cast<uint32_t>(m.join_token_hashes.size()));
    for (const auto& h : m.join_token_hashes) write_blob(b, h);
    return b;
}
std::vector<uint8_t> encode(const ArchiveJoin& m) {
    std::vector<uint8_t> b;
    write_blob(b, m.archive_id);
    write_blob(b, m.join_token);
    write_blob(b, m.public_key);
    write_blob(b, m.signature);
    return b;
}
std::vector<uint8_t> encode(const ArchiveAuth& m) {
    std::vector<uint8_t> b;
    write_blob(b, m.archive_id);
    write_blob(b, m.key_hash);
    write_blob(b, m.signature);
    return b;
}
std::vector<uint8_t> encode(const ArchiveAppend& m) {
    std::vector<uint8_t> b;
    write_u64(b, m.expected_number);
    write_blob(b, m.expected_hash);
    write_blob(b, m.ciphertext);
    return b;
}
std::vector<uint8_t> encode(const ArchiveHead& m) {
    std::vector<uint8_t> b;
    write_u64(b, m.number);
    write_blob(b, m.hash);
    return b;
}
std::vector<uint8_t> encode(const ArchiveFetch& m) {
    std::vector<uint8_t> b;
    write_u64(b, m.from_number);
    write_u32(b, m.limit);
    return b;
}
std::vector<uint8_t> encode(const ArchiveEntry& m) {
    std::vector<uint8_t> b;
    write_u64(b, m.number);
    write_blob(b, m.hash);
    write_blob(b, m.ciphertext);
    write_u32(b, m.tombstone ? 1 : 0);
    return b;
}

std::vector<uint8_t> encode(const ArchiveDelete& m) {
    std::vector<uint8_t> b;
    write_u32(b, m.scope);
    write_blob(b, m.op_id);
    write_u64(b, m.expires_at);
    write_u32(b, static_cast<uint32_t>(m.entry_hashes.size()));
    for (const auto& h : m.entry_hashes) write_blob(b, h);
    write_u32(b, static_cast<uint32_t>(m.signatures.size()));
    for (const auto& s : m.signatures) {
        write_blob(b, s.key_hash);
        write_blob(b, s.signature);
    }
    return b;
}

std::vector<uint8_t> encode(const KeyringChunk& m) {
    std::vector<uint8_t> b;
    write_u32(b, m.total_size);
    write_u32(b, m.index);
    write_u32(b, m.count);
    write_blob(b, m.data);
    return b;
}

std::vector<uint8_t> encode(const FileBegin& m) {
    std::vector<uint8_t> b;
    write_blob(b, m.file_id);
    write_u64(b, m.total_size);
    write_u32(b, m.chunk_size);
    write_u32(b, m.chunk_count);
    write_u64(b, m.expires_at);
    write_u32(b, static_cast<uint32_t>(m.token_hashes.size()));
    for (const auto& h : m.token_hashes) write_blob(b, h);
    return b;
}
std::vector<uint8_t> encode(const FileChunk& m) {
    std::vector<uint8_t> b;
    write_u32(b, m.index);
    write_blob(b, m.data);
    return b;
}
std::vector<uint8_t> encode(const FileDownload& m) {
    std::vector<uint8_t> b;
    write_blob(b, m.file_id);
    write_blob(b, m.token);
    write_u32(b, m.from_chunk);
    return b;
}
std::vector<uint8_t> encode(const FileInfo& m) {
    std::vector<uint8_t> b;
    write_u64(b, m.total_size);
    write_u32(b, m.chunk_size);
    write_u32(b, m.chunk_count);
    write_u64(b, m.expires_at);
    return b;
}
std::vector<uint8_t> encode(const FileRedeem& m) {
    std::vector<uint8_t> b;
    write_blob(b, m.file_id);
    write_blob(b, m.token);
    return b;
}
std::vector<uint8_t> encode(const FileRef& m) {
    std::vector<uint8_t> b;
    write_blob(b, m.file_id);
    return b;
}
std::vector<uint8_t> encode(const FileStatus& m) {
    std::vector<uint8_t> b;
    write_u32(b, m.tokens_total);
    write_u32(b, m.tokens_redeemed);
    write_u64(b, m.expires_at);
    write_u32(b, m.ready ? 1 : 0);
    return b;
}

std::vector<uint8_t> encode(const HashOp& m) {
    std::vector<uint8_t> b;
    write_blob(b, m.token_hash);
    return b;
}

// --- decode ---

std::optional<Hello> decode_hello(const std::vector<uint8_t>& in) {
    size_t off = 0;
    Hello m;
    auto version = read_u32(in.data(), in.size(), off);
    auto nonce = fixed_blob(in, off, NONCE_BYTES);
    if (!version || !nonce || !at_end(in, off)) return std::nullopt;
    m.version = *version;
    m.client_nonce = std::move(*nonce);
    return m;
}

std::optional<HelloReply> decode_hello_reply(const std::vector<uint8_t>& in) {
    size_t off = 0;
    HelloReply m;
    auto key = read_blob(in.data(), in.size(), off, MAX_KEY_BLOB);
    auto sig = read_blob(in.data(), in.size(), off, MAX_KEY_BLOB);
    auto challenge = fixed_blob(in, off, NONCE_BYTES);
    if (!key || !sig || !challenge || !at_end(in, off)) return std::nullopt;
    m.relay_public_key = std::move(*key);
    m.signature = std::move(*sig);
    m.auth_challenge = std::move(*challenge);
    return m;
}

std::optional<Register> decode_register(const std::vector<uint8_t>& in) {
    size_t off = 0;
    Register m;
    auto invite = fixed_blob(in, off, INVITE_BYTES);
    auto mailbox = fixed_blob(in, off, MAILBOX_ID_BYTES);
    auto key = read_blob(in.data(), in.size(), off, MAX_KEY_BLOB);
    auto token_hash = fixed_blob(in, off, HASH_BYTES);
    auto sig = read_blob(in.data(), in.size(), off, MAX_KEY_BLOB);
    if (!invite || !mailbox || !key || !token_hash || !sig || !at_end(in, off)) return std::nullopt;
    m.invite = std::move(*invite);
    m.mailbox_id = std::move(*mailbox);
    m.access_public_key = std::move(*key);
    m.send_token_hash = std::move(*token_hash);
    m.signature = std::move(*sig);
    return m;
}

std::optional<Auth> decode_auth(const std::vector<uint8_t>& in) {
    size_t off = 0;
    Auth m;
    auto mailbox = fixed_blob(in, off, MAILBOX_ID_BYTES);
    auto sig = read_blob(in.data(), in.size(), off, MAX_KEY_BLOB);
    if (!mailbox || !sig || !at_end(in, off)) return std::nullopt;
    m.mailbox_id = std::move(*mailbox);
    m.signature = std::move(*sig);
    return m;
}

std::optional<Deposit> decode_deposit(const std::vector<uint8_t>& in) {
    size_t off = 0;
    Deposit m;
    auto mailbox = fixed_blob(in, off, MAILBOX_ID_BYTES);
    auto token = fixed_blob(in, off, SEND_TOKEN_BYTES);
    auto ttl = read_u32(in.data(), in.size(), off);
    auto envelope = read_blob(in.data(), in.size(), off, MAX_ENVELOPE_BYTES);
    if (!mailbox || !token || !ttl || !envelope || !at_end(in, off)) return std::nullopt;
    m.mailbox_id = std::move(*mailbox);
    m.send_token = std::move(*token);
    m.ttl_seconds = *ttl;
    m.envelope = std::move(*envelope);
    return m;
}

std::optional<StoredEnvelope> decode_stored_envelope(const std::vector<uint8_t>& in) {
    size_t off = 0;
    StoredEnvelope m;
    auto id = fixed_blob(in, off, ENVELOPE_ID_BYTES);
    auto at = read_u64(in.data(), in.size(), off);
    auto token_hash = fixed_blob(in, off, HASH_BYTES);
    auto envelope = read_blob(in.data(), in.size(), off, MAX_ENVELOPE_BYTES);
    if (!id || !at || !token_hash || !envelope || !at_end(in, off)) return std::nullopt;
    m.id = std::move(*id);
    m.deposited_at = *at;
    m.token_hash = std::move(*token_hash);
    m.envelope = std::move(*envelope);
    return m;
}

std::optional<IdList> decode_id_list(const std::vector<uint8_t>& in) {
    size_t off = 0;
    auto count = read_u32(in.data(), in.size(), off);
    if (!count || *count > MAX_ACK_IDS) return std::nullopt;
    IdList m;
    for (uint32_t i = 0; i < *count; i++) {
        auto id = fixed_blob(in, off, ENVELOPE_ID_BYTES);
        if (!id) return std::nullopt;
        m.ids.push_back(std::move(*id));
    }
    if (!at_end(in, off)) return std::nullopt;
    return m;
}

std::optional<InviteStatus> decode_invite_status(const std::vector<uint8_t>& in) {
    size_t off = 0;
    InviteStatus m;
    auto max_unused = read_u32(in.data(), in.size(), off);
    auto max_total = read_u32(in.data(), in.size(), off);
    auto unused = read_u32(in.data(), in.size(), off);
    if (!max_unused || !max_total || !unused || *unused > MAX_INVITE_STATUS_ENTRIES) return std::nullopt;
    m.max_unused = *max_unused;
    m.max_total = *max_total;
    for (uint32_t i = 0; i < *unused; i++) {
        auto hash = fixed_blob(in, off, HASH_BYTES);
        auto expires = read_u64(in.data(), in.size(), off);
        if (!hash || !expires) return std::nullopt;
        m.unused.push_back({std::move(*hash), *expires});
    }
    auto joined = read_u32(in.data(), in.size(), off);
    if (!joined || *joined > MAX_INVITE_STATUS_ENTRIES) return std::nullopt;
    for (uint32_t i = 0; i < *joined; i++) {
        auto id = fixed_blob(in, off, MAILBOX_ID_BYTES);
        auto at = read_u64(in.data(), in.size(), off);
        if (!id || !at) return std::nullopt;
        m.joined.push_back({std::move(*id), *at});
    }
    if (!at_end(in, off)) return std::nullopt;
    return m;
}

std::optional<ArchiveCreate> decode_archive_create(const std::vector<uint8_t>& in) {
    size_t off = 0;
    auto id = fixed_blob(in, off, ARCHIVE_ID_BYTES);
    auto count = read_u32(in.data(), in.size(), off);
    if (!id || !count || *count < 1 || *count > MAX_ARCHIVE_MEMBERS) return std::nullopt;
    ArchiveCreate m;
    m.archive_id = std::move(*id);
    for (uint32_t i = 0; i < *count; i++) {
        auto h = fixed_blob(in, off, HASH_BYTES);
        if (!h) return std::nullopt;
        m.join_token_hashes.push_back(std::move(*h));
    }
    if (!at_end(in, off)) return std::nullopt;
    return m;
}
std::optional<ArchiveJoin> decode_archive_join(const std::vector<uint8_t>& in) {
    size_t off = 0;
    auto id = fixed_blob(in, off, ARCHIVE_ID_BYTES);
    auto token = fixed_blob(in, off, JOIN_TOKEN_BYTES);
    auto key = read_blob(in.data(), in.size(), off, MAX_KEY_BLOB);
    auto sig = read_blob(in.data(), in.size(), off, MAX_KEY_BLOB);
    if (!id || !token || !key || !sig || !at_end(in, off)) return std::nullopt;
    return ArchiveJoin{std::move(*id), std::move(*token), std::move(*key), std::move(*sig)};
}
std::optional<ArchiveAuth> decode_archive_auth(const std::vector<uint8_t>& in) {
    size_t off = 0;
    auto id = fixed_blob(in, off, ARCHIVE_ID_BYTES);
    auto key_hash = fixed_blob(in, off, HASH_BYTES);
    auto sig = read_blob(in.data(), in.size(), off, MAX_KEY_BLOB);
    if (!id || !key_hash || !sig || !at_end(in, off)) return std::nullopt;
    return ArchiveAuth{std::move(*id), std::move(*key_hash), std::move(*sig)};
}
std::optional<ArchiveAppend> decode_archive_append(const std::vector<uint8_t>& in) {
    size_t off = 0;
    auto number = read_u64(in.data(), in.size(), off);
    auto hash = fixed_blob(in, off, HASH_BYTES);
    auto ct = read_blob(in.data(), in.size(), off, MAX_ARCHIVE_ENTRY_BYTES);
    if (!number || !hash || !ct || ct->empty() || !at_end(in, off)) return std::nullopt;
    return ArchiveAppend{*number, std::move(*hash), std::move(*ct)};
}
std::optional<ArchiveHead> decode_archive_head(const std::vector<uint8_t>& in) {
    size_t off = 0;
    auto number = read_u64(in.data(), in.size(), off);
    auto hash = fixed_blob(in, off, HASH_BYTES);
    if (!number || !hash || !at_end(in, off)) return std::nullopt;
    return ArchiveHead{*number, std::move(*hash)};
}
std::optional<ArchiveFetch> decode_archive_fetch(const std::vector<uint8_t>& in) {
    size_t off = 0;
    auto from = read_u64(in.data(), in.size(), off);
    auto limit = read_u32(in.data(), in.size(), off);
    if (!from || !limit || *from < 1 || *limit < 1 || *limit > MAX_FETCH_ENTRIES || !at_end(in, off)) return std::nullopt;
    return ArchiveFetch{*from, *limit};
}
std::optional<ArchiveEntry> decode_archive_entry(const std::vector<uint8_t>& in) {
    size_t off = 0;
    auto number = read_u64(in.data(), in.size(), off);
    auto hash = fixed_blob(in, off, HASH_BYTES);
    auto ct = read_blob(in.data(), in.size(), off, MAX_ARCHIVE_ENTRY_BYTES);
    auto tombstone = read_u32(in.data(), in.size(), off);
    // An entry has content, or it is a tombstone and has none: never both, never neither.
    if (!number || !hash || !ct || !tombstone || *tombstone > 1 || ct->empty() != (*tombstone == 1) || !at_end(in, off)) return std::nullopt;
    return ArchiveEntry{*number, std::move(*hash), std::move(*ct), *tombstone == 1};
}

std::optional<ArchiveDelete> decode_archive_delete(const std::vector<uint8_t>& in) {
    size_t off = 0;
    auto scope = read_u32(in.data(), in.size(), off);
    auto op = fixed_blob(in, off, 16);
    auto expires = read_u64(in.data(), in.size(), off);
    auto hashes = read_u32(in.data(), in.size(), off);
    if (!scope || !op || !expires || !hashes || (*scope != DELETE_SCOPE_CHAT && *scope != DELETE_SCOPE_ENTRIES)) return std::nullopt;
    if (*scope == DELETE_SCOPE_CHAT ? *hashes != 0 : (*hashes < 1 || *hashes > MAX_DELETE_ENTRIES)) return std::nullopt;
    ArchiveDelete m;
    m.scope = *scope;
    m.op_id = std::move(*op);
    m.expires_at = *expires;
    for (uint32_t i = 0; i < *hashes; i++) {
        auto h = fixed_blob(in, off, HASH_BYTES);
        if (!h) return std::nullopt;
        for (const auto& other : m.entry_hashes) if (other == *h) return std::nullopt;  // each entry once
        m.entry_hashes.push_back(std::move(*h));
    }
    auto sigs = read_u32(in.data(), in.size(), off);
    if (!sigs || *sigs < 1 || *sigs > MAX_ARCHIVE_MEMBERS) return std::nullopt;
    for (uint32_t i = 0; i < *sigs; i++) {
        auto kh = fixed_blob(in, off, HASH_BYTES);
        auto sg = read_blob(in.data(), in.size(), off, MAX_KEY_BLOB);
        if (!kh || !sg || sg->empty()) return std::nullopt;
        for (const auto& other : m.signatures) if (other.key_hash == *kh) return std::nullopt;  // one signature per key
        m.signatures.push_back({std::move(*kh), std::move(*sg)});
    }
    if (!at_end(in, off)) return std::nullopt;
    return m;
}

std::optional<KeyringChunk> decode_keyring_chunk(const std::vector<uint8_t>& in) {
    size_t off = 0;
    auto total = read_u32(in.data(), in.size(), off);
    auto index = read_u32(in.data(), in.size(), off);
    auto count = read_u32(in.data(), in.size(), off);
    auto data = read_blob(in.data(), in.size(), off, KEYRING_CHUNK_BYTES);
    if (!total || !index || !count || !data || !at_end(in, off)) return std::nullopt;
    KeyringChunk c{*total, *index, *count, std::move(*data)};
    if (c.total_size == 0) return c.index == 0 && c.count == 0 && c.data.empty() ? std::optional<KeyringChunk>(c) : std::nullopt;  // "none"
    if (c.total_size > MAX_KEYRING_BYTES) return std::nullopt;
    const uint32_t expected_count = static_cast<uint32_t>((static_cast<uint64_t>(c.total_size) + KEYRING_CHUNK_BYTES - 1) / KEYRING_CHUNK_BYTES);
    if (c.count != expected_count || c.index >= c.count) return std::nullopt;
    const uint64_t expected_size = c.index + 1 < c.count ? KEYRING_CHUNK_BYTES : c.total_size - static_cast<uint64_t>(KEYRING_CHUNK_BYTES) * (c.count - 1);
    if (c.data.size() != expected_size) return std::nullopt;
    return c;
}

std::optional<FileBegin> decode_file_begin(const std::vector<uint8_t>& in) {
    size_t off = 0;
    auto id = fixed_blob(in, off, FILE_ID_BYTES);
    auto total = read_u64(in.data(), in.size(), off);
    auto chunk_size = read_u32(in.data(), in.size(), off);
    auto count = read_u32(in.data(), in.size(), off);
    auto expires = read_u64(in.data(), in.size(), off);
    auto tokens = read_u32(in.data(), in.size(), off);
    if (!id || !total || !chunk_size || !count || !expires || !tokens) return std::nullopt;
    if (*total < 1 || *total > MAX_FILE_BYTES || *chunk_size < 1 || *chunk_size > MAX_FILE_CHUNK_BYTES) return std::nullopt;
    const uint64_t expected_count = (*total + *chunk_size - 1) / *chunk_size;
    if (*count != expected_count) return std::nullopt;
    if (*chunk_size < MIN_FILE_CHUNK_BYTES && *count != 1) return std::nullopt;  // many tiny chunks are just a way to waste the relay's time
    if (*tokens < 1 || *tokens > MAX_FILE_TOKENS) return std::nullopt;
    FileBegin m;
    m.file_id = std::move(*id);
    m.total_size = *total;
    m.chunk_size = *chunk_size;
    m.chunk_count = *count;
    m.expires_at = *expires;
    for (uint32_t i = 0; i < *tokens; i++) {
        auto h = fixed_blob(in, off, HASH_BYTES);
        if (!h) return std::nullopt;
        for (const auto& other : m.token_hashes) if (other == *h) return std::nullopt;  // each recipient's token is their own
        m.token_hashes.push_back(std::move(*h));
    }
    if (!at_end(in, off)) return std::nullopt;
    return m;
}
std::optional<FileChunk> decode_file_chunk(const std::vector<uint8_t>& in) {
    size_t off = 0;
    auto index = read_u32(in.data(), in.size(), off);
    auto data = read_blob(in.data(), in.size(), off, MAX_FILE_CHUNK_BYTES);
    if (!index || !data || data->empty() || !at_end(in, off)) return std::nullopt;
    return FileChunk{*index, std::move(*data)};
}
std::optional<FileDownload> decode_file_download(const std::vector<uint8_t>& in) {
    size_t off = 0;
    auto id = fixed_blob(in, off, FILE_ID_BYTES);
    auto token = fixed_blob(in, off, FILE_TOKEN_BYTES);
    auto from = read_u32(in.data(), in.size(), off);
    if (!id || !token || !from || !at_end(in, off)) return std::nullopt;
    return FileDownload{std::move(*id), std::move(*token), *from};
}
std::optional<FileInfo> decode_file_info(const std::vector<uint8_t>& in) {
    size_t off = 0;
    auto total = read_u64(in.data(), in.size(), off);
    auto chunk_size = read_u32(in.data(), in.size(), off);
    auto count = read_u32(in.data(), in.size(), off);
    auto expires = read_u64(in.data(), in.size(), off);
    if (!total || !chunk_size || !count || !expires || !at_end(in, off)) return std::nullopt;
    if (*total < 1 || *total > MAX_FILE_BYTES || *chunk_size < 1 || *chunk_size > MAX_FILE_CHUNK_BYTES || *count != (*total + *chunk_size - 1) / *chunk_size) return std::nullopt;
    return FileInfo{*total, *chunk_size, *count, *expires};
}
std::optional<FileRedeem> decode_file_redeem(const std::vector<uint8_t>& in) {
    size_t off = 0;
    auto id = fixed_blob(in, off, FILE_ID_BYTES);
    auto token = fixed_blob(in, off, FILE_TOKEN_BYTES);
    if (!id || !token || !at_end(in, off)) return std::nullopt;
    return FileRedeem{std::move(*id), std::move(*token)};
}
std::optional<FileRef> decode_file_ref(const std::vector<uint8_t>& in) {
    size_t off = 0;
    auto id = fixed_blob(in, off, FILE_ID_BYTES);
    if (!id || !at_end(in, off)) return std::nullopt;
    return FileRef{std::move(*id)};
}
std::optional<FileStatus> decode_file_status(const std::vector<uint8_t>& in) {
    size_t off = 0;
    auto total = read_u32(in.data(), in.size(), off);
    auto redeemed = read_u32(in.data(), in.size(), off);
    auto expires = read_u64(in.data(), in.size(), off);
    auto ready = read_u32(in.data(), in.size(), off);
    if (!total || !redeemed || !expires || !ready || *ready > 1 || *redeemed > *total || *total > MAX_FILE_TOKENS || !at_end(in, off)) return std::nullopt;
    return FileStatus{*total, *redeemed, *expires, *ready == 1};
}

std::optional<HashOp> decode_hash_op(const std::vector<uint8_t>& in) {
    size_t off = 0;
    auto hash = fixed_blob(in, off, HASH_BYTES);
    if (!hash || !at_end(in, off)) return std::nullopt;
    return HashOp{std::move(*hash)};
}

// --- signing inputs ---

std::vector<uint8_t> hello_signing_input(const std::vector<uint8_t>& client_nonce,
                                         const std::vector<uint8_t>& relay_id,
                                         uint32_t version,
                                         const std::vector<uint8_t>& auth_challenge) {
    std::vector<uint8_t> b;
    write_string(b, HELLO_LABEL);
    write_blob(b, relay_id);
    write_u32(b, version);
    write_blob(b, client_nonce);
    write_blob(b, auth_challenge);
    return b;
}

std::vector<uint8_t> register_signing_input(const std::vector<uint8_t>& relay_id,
                                            const std::vector<uint8_t>& mailbox_id,
                                            const std::vector<uint8_t>& access_public_key,
                                            const std::vector<uint8_t>& send_token_hash) {
    std::vector<uint8_t> b;
    write_string(b, REGISTER_LABEL);
    write_blob(b, relay_id);
    write_blob(b, mailbox_id);
    write_blob(b, access_public_key);
    write_blob(b, send_token_hash);
    return b;
}

std::vector<uint8_t> archive_join_signing_input(const std::vector<uint8_t>& relay_id, const std::vector<uint8_t>& archive_id,
                                                const std::vector<uint8_t>& public_key, const std::vector<uint8_t>& join_token_hash) {
    std::vector<uint8_t> b;
    write_string(b, ARCHIVE_JOIN_LABEL);
    write_blob(b, relay_id);
    write_blob(b, archive_id);
    write_blob(b, public_key);
    write_blob(b, join_token_hash);
    return b;
}
std::vector<uint8_t> archive_auth_signing_input(const std::vector<uint8_t>& auth_challenge, const std::vector<uint8_t>& relay_id,
                                                const std::vector<uint8_t>& archive_id, const std::vector<uint8_t>& key_hash) {
    std::vector<uint8_t> b;
    write_string(b, ARCHIVE_AUTH_LABEL);
    write_blob(b, relay_id);
    write_blob(b, archive_id);
    write_blob(b, key_hash);
    write_blob(b, auth_challenge);
    return b;
}
std::vector<uint8_t> archive_delete_signing_input(const std::vector<uint8_t>& relay_id, const std::vector<uint8_t>& archive_id, uint32_t scope,
                                                  const std::vector<uint8_t>& op_id, uint64_t expires_at,
                                                  const std::vector<std::vector<uint8_t>>& entry_hashes) {
    std::vector<uint8_t> b;
    write_string(b, ARCHIVE_DELETE_LABEL);
    write_blob(b, relay_id);
    write_blob(b, archive_id);
    write_u32(b, scope);
    write_blob(b, op_id);
    write_u64(b, expires_at);
    write_u32(b, static_cast<uint32_t>(entry_hashes.size()));
    for (const auto& h : entry_hashes) write_blob(b, h);
    return b;
}
std::vector<uint8_t> archive_genesis_input(const std::vector<uint8_t>& archive_id) {
    std::vector<uint8_t> b;
    write_string(b, ARCHIVE_GENESIS_LABEL);
    write_blob(b, archive_id);
    return b;
}
std::vector<uint8_t> archive_entry_hash_input(const std::vector<uint8_t>& archive_id, uint64_t number,
                                              const std::vector<uint8_t>& previous_hash, const std::vector<uint8_t>& ciphertext) {
    std::vector<uint8_t> b;
    write_string(b, ARCHIVE_ENTRY_LABEL);
    write_blob(b, archive_id);
    write_u64(b, number);
    write_blob(b, previous_hash);
    write_blob(b, ciphertext);
    return b;
}
std::vector<uint8_t> auth_signing_input(const std::vector<uint8_t>& auth_challenge,
                                        const std::vector<uint8_t>& relay_id,
                                        const std::vector<uint8_t>& mailbox_id) {
    std::vector<uint8_t> b;
    write_string(b, AUTH_LABEL);
    write_blob(b, relay_id);
    write_blob(b, mailbox_id);
    write_blob(b, auth_challenge);
    return b;
}

}  // namespace relay
