#include "sharing.h"

#include "crypto_engine.h"
#include "key_store.h"
#include "protocol.h"

#include <algorithm>
#include <cctype>
#include <cstring>

namespace {

const char CARD_PREFIX[] = "pqft-contact-1:";
const char CARD2_PREFIX[] = "pqft-contact-2:";
const char LINK_PREFIX[] = "pqft://";
constexpr uint32_t CARD_MAGIC = 0x50514343;  // "PQCC"
constexpr uint32_t CARD_VERSION = 1;
constexpr size_t MAX_CARD_NAME_BYTES = 64;
constexpr size_t MAX_CARD_SERVER_BYTES = 255;
constexpr size_t CARD_CHECKSUM_BYTES = 4;

// --- base64url (no padding) ---

const char B64_ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int b64_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

std::string b64_encode(const std::vector<uint8_t>& in) {
    std::string out;
    out.reserve((in.size() + 2) / 3 * 4);
    size_t i = 0;
    for (; i + 3 <= in.size(); i += 3) {
        uint32_t v = (static_cast<uint32_t>(in[i]) << 16) | (static_cast<uint32_t>(in[i + 1]) << 8) | in[i + 2];
        out.push_back(B64_ALPHABET[(v >> 18) & 63]);
        out.push_back(B64_ALPHABET[(v >> 12) & 63]);
        out.push_back(B64_ALPHABET[(v >> 6) & 63]);
        out.push_back(B64_ALPHABET[v & 63]);
    }
    size_t rem = in.size() - i;
    if (rem == 1) {
        uint32_t v = static_cast<uint32_t>(in[i]) << 16;
        out.push_back(B64_ALPHABET[(v >> 18) & 63]);
        out.push_back(B64_ALPHABET[(v >> 12) & 63]);
    } else if (rem == 2) {
        uint32_t v = (static_cast<uint32_t>(in[i]) << 16) | (static_cast<uint32_t>(in[i + 1]) << 8);
        out.push_back(B64_ALPHABET[(v >> 18) & 63]);
        out.push_back(B64_ALPHABET[(v >> 12) & 63]);
        out.push_back(B64_ALPHABET[(v >> 6) & 63]);
    }
    return out;
}

std::optional<std::vector<uint8_t>> b64_decode(const std::string& in) {
    if (in.size() % 4 == 1) return std::nullopt;
    std::vector<uint8_t> out;
    out.reserve(in.size() * 3 / 4);
    uint32_t acc = 0;
    int bits = 0;
    for (char c : in) {
        int v = b64_value(c);
        if (v < 0) return std::nullopt;
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((acc >> bits) & 0xFF));
        }
    }
    if (bits > 0 && (acc & ((1u << bits) - 1)) != 0) return std::nullopt;  // non-canonical tail
    return out;
}

// --- small string helpers ---

std::string trim(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) b++;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) e--;
    return s.substr(b, e - b);
}

std::string ascii_lower(std::string s) {
    for (auto& c : s)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return s;
}

bool is_valid_host(const std::string& host) {
    if (host.empty() || host.size() > 253) return false;
    if (host.find(':') != std::string::npos) {  // IPv6 literal
        return std::all_of(host.begin(), host.end(), [](char c) {
            return std::isxdigit(static_cast<unsigned char>(c)) || c == ':' || c == '.';
        });
    }
    if (host.front() == '-' || host.front() == '.') return false;
    return std::all_of(host.begin(), host.end(), [](char c) {
        return std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-' || c == '_';
    });
}

}  // namespace

// --- Server addresses ---

std::optional<ServerAddress> parse_server_address(const std::string& text) {
    std::string s = trim(text);
    std::string host, port_text;
    bool has_port = false;

    if (!s.empty() && s[0] == '[') {
        size_t end = s.find(']');
        if (end == std::string::npos) return std::nullopt;
        host = s.substr(1, end - 1);
        std::string rest = s.substr(end + 1);
        if (!rest.empty()) {
            if (rest[0] != ':') return std::nullopt;
            has_port = true;
            port_text = rest.substr(1);
        }
    } else if (std::count(s.begin(), s.end(), ':') == 1) {
        size_t colon = s.find(':');
        host = s.substr(0, colon);
        port_text = s.substr(colon + 1);
        has_port = true;
    } else {
        host = s;  // plain host, or a bare IPv6 address without a port
    }

    if (!is_valid_host(host)) return std::nullopt;

    ServerAddress addr;
    addr.host = host;
    if (has_port) {
        if (port_text.empty() || port_text.size() > 5) return std::nullopt;
        if (!std::all_of(port_text.begin(), port_text.end(), [](char c) { return c >= '0' && c <= '9'; }))
            return std::nullopt;
        unsigned long value = std::stoul(port_text);
        if (value == 0 || value > 65535) return std::nullopt;
        addr.port = static_cast<uint16_t>(value);
    }
    return addr;
}

std::string format_server_address(const ServerAddress& addr) {
    bool v6 = addr.host.find(':') != std::string::npos;
    std::string out = v6 ? "[" + addr.host + "]" : addr.host;
    if (addr.port != DEFAULT_RELAY_PORT) out += ":" + std::to_string(addr.port);
    return out;
}

bool same_server(const ServerAddress& a, const ServerAddress& b) {
    return a.port == b.port && ascii_lower(a.host) == ascii_lower(b.host);
}

// --- Contact names ---

std::string sanitize_contact_name(const std::string& raw) {
    std::string out;
    for (char c : raw) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                  c == ' ' || c == '-' || c == '_' || c == '.';
        if (ok) out.push_back(c);
        else if (out.empty() || out.back() != '_') out.push_back('_');  // collapse runs
    }
    auto strip = [&] {
        while (!out.empty() && (out.front() == '.' || out.front() == ' ')) out.erase(0, 1);
        while (!out.empty() && (out.back() == '.' || out.back() == ' ')) out.pop_back();
    };
    strip();
    if (out.size() > 64) out.resize(64);
    strip();
    return KeyStore::is_valid_contact_name(out) ? out : "contact";
}

// --- Contact cards ---

std::string encode_contact_card(const ContactCard& card) {
    std::vector<uint8_t> buf;
    write_u32(buf, CARD_MAGIC);
    write_u32(buf, CARD_VERSION);
    write_string(buf, card.name);
    write_blob(buf, card.pub_kem);
    write_blob(buf, card.pub_dsa);
    write_string(buf, card.server);
    auto digest = CryptoEngine::sha256(buf);
    buf.insert(buf.end(), digest.begin(), digest.begin() + CARD_CHECKSUM_BYTES);
    return CARD_PREFIX + b64_encode(buf);
}

bool looks_like_contact_card(const std::string& text) {
    return text.find(CARD_PREFIX) != std::string::npos || text.find(CARD2_PREFIX) != std::string::npos;
}

// --- Contact cards, version 2 ---

std::string encode_contact_card_v2(const std::vector<uint8_t>& bundle_raw) {
    std::vector<uint8_t> buf = bundle_raw;
    auto digest = CryptoEngine::sha256(bundle_raw);
    buf.insert(buf.end(), digest.begin(), digest.begin() + CARD_CHECKSUM_BYTES);
    return CARD2_PREFIX + b64_encode(buf);
}

std::optional<ImportedCard> decode_any_contact_card(const std::string& text, std::string* error) {
    auto fail = [&](const std::string& msg) -> std::optional<ImportedCard> {
        if (error) *error = msg;
        return std::nullopt;
    };

    std::string compact;
    for (char c : text)
        if (!std::isspace(static_cast<unsigned char>(c))) compact.push_back(c);

    size_t start = compact.find(CARD2_PREFIX);
    if (start == std::string::npos) {
        // Not a v2 card: fall back to the old format, whose contact has no verified key.
        auto v1 = decode_contact_card(text, error);
        if (!v1) return std::nullopt;
        ImportedCard card;
        card.name = std::move(v1->name);
        card.pub_kem = std::move(v1->pub_kem);
        card.pub_dsa = std::move(v1->pub_dsa);
        card.server = std::move(v1->server);
        return card;
    }

    std::string body;
    for (size_t i = start + std::strlen(CARD2_PREFIX); i < compact.size() && b64_value(compact[i]) >= 0; i++)
        body.push_back(compact[i]);

    const char* damaged = "The contact card is damaged or incomplete. Paste only the card, exactly as it was sent.";
    auto raw = b64_decode(body);
    if (!raw || raw->size() <= CARD_CHECKSUM_BYTES) return fail(damaged);

    const size_t bundle_len = raw->size() - CARD_CHECKSUM_BYTES;
    std::vector<uint8_t> bundle_raw(raw->begin(), raw->begin() + static_cast<std::ptrdiff_t>(bundle_len));
    auto digest = CryptoEngine::sha256(bundle_raw);
    if (!std::equal(digest.begin(), digest.begin() + CARD_CHECKSUM_BYTES,
                    raw->begin() + static_cast<std::ptrdiff_t>(bundle_len)))
        return fail(damaged);

    std::string bundle_error;
    auto bundle = parse_identity_bundle(bundle_raw, &bundle_error);
    if (!bundle) return fail(bundle_error);
    if (!bundle->relay_hint.empty() && !parse_server_address(bundle->relay_hint))
        return fail("The contact card contains an invalid relay server address.");

    ImportedCard card;
    card.name = bundle->display_name;
    card.pub_kem = bundle->encryption_key;
    card.pub_dsa = bundle->signing_key;
    card.server = bundle->relay_hint;
    card.bundle = std::move(bundle);
    return card;
}

std::optional<ContactCard> decode_contact_card(const std::string& text, std::string* error) {
    auto fail = [&](const char* msg) -> std::optional<ContactCard> {
        if (error) *error = msg;
        return std::nullopt;
    };
    const char* damaged = "The contact card is damaged or incomplete. Paste only the card, exactly as it was sent.";

    std::string compact;
    for (char c : text)
        if (!std::isspace(static_cast<unsigned char>(c))) compact.push_back(c);

    size_t start = compact.find(CARD_PREFIX);
    if (start == std::string::npos) return fail("That doesn't look like a contact card.");

    std::string body;
    for (size_t i = start + std::strlen(CARD_PREFIX); i < compact.size() && b64_value(compact[i]) >= 0; i++)
        body.push_back(compact[i]);

    auto raw = b64_decode(body);
    if (!raw || raw->size() <= CARD_CHECKSUM_BYTES) return fail(damaged);

    const size_t payload_len = raw->size() - CARD_CHECKSUM_BYTES;
    std::vector<uint8_t> payload(raw->begin(), raw->begin() + static_cast<std::ptrdiff_t>(payload_len));
    auto digest = CryptoEngine::sha256(payload);
    if (!std::equal(digest.begin(), digest.begin() + CARD_CHECKSUM_BYTES,
                    raw->begin() + static_cast<std::ptrdiff_t>(payload_len)))
        return fail(damaged);

    size_t off = 0;
    auto magic = read_u32(payload.data(), payload_len, off);
    if (!magic || *magic != CARD_MAGIC) return fail("That doesn't look like a contact card.");
    auto version = read_u32(payload.data(), payload_len, off);
    if (!version || *version != CARD_VERSION)
        return fail("This contact card was made by an incompatible version of the app.");

    ContactCard card;
    auto name = read_string(payload.data(), payload_len, off, MAX_CARD_NAME_BYTES);
    auto kem = read_blob(payload.data(), payload_len, off, MAX_KEM_CIPHERTEXT_SIZE);
    auto dsa = read_blob(payload.data(), payload_len, off, MAX_SIGNATURE_SIZE);
    auto server = read_string(payload.data(), payload_len, off, MAX_CARD_SERVER_BYTES);
    if (!name || !kem || !dsa || !server || off != payload_len) return fail(damaged);

    if (kem->size() != CryptoEngine::kem_public_key_size() || dsa->size() != CryptoEngine::sig_public_key_size())
        return fail("The keys in this card are not ML-KEM-768 / ML-DSA-65 public keys.");
    if (!server->empty() && !parse_server_address(*server))
        return fail("The contact card contains an invalid relay server address.");

    card.name = std::move(*name);
    card.pub_kem = std::move(*kem);
    card.pub_dsa = std::move(*dsa);
    card.server = std::move(*server);
    return card;
}

// --- Share links ---

std::string build_share_link(const ServerAddress& server, const std::string& transfer_id) {
    return LINK_PREFIX + format_server_address(server) + "/" + transfer_id;
}

std::optional<ShareLink> parse_share_link(const std::string& text) {
    std::string s = trim(text);
    // Chat apps like to wrap links in <>, quotes or trailing punctuation.
    while (!s.empty() && (s.front() == '<' || s.front() == '"' || s.front() == '\'')) s.erase(0, 1);
    while (!s.empty() && (s.back() == '>' || s.back() == '"' || s.back() == '\'' || s.back() == '.' ||
                          s.back() == ',' || s.back() == '/'))
        s.pop_back();

    const size_t prefix_len = std::strlen(LINK_PREFIX);
    if (s.size() <= prefix_len || ascii_lower(s.substr(0, prefix_len)) != LINK_PREFIX) return std::nullopt;

    std::string rest = s.substr(prefix_len);
    size_t slash = rest.find('/');
    if (slash == std::string::npos) return std::nullopt;

    auto server = parse_server_address(rest.substr(0, slash));
    if (!server) return std::nullopt;

    std::string id = ascii_lower(rest.substr(slash + 1));
    if (!is_lower_hex(id, TRANSFER_ID_HEX_LEN)) return std::nullopt;

    return ShareLink{*server, id};
}
