#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// Everything about turning identities and transfers into text that can be
// pasted into a chat or email: server addresses, contact cards and share links.
// No GUI dependencies, so it can be unit-tested.

constexpr uint16_t DEFAULT_RELAY_PORT = 9000;

// --- Relay server addresses ---

struct ServerAddress {
    std::string host;  // hostname, IPv4 or IPv6 literal (no brackets)
    uint16_t port = DEFAULT_RELAY_PORT;
};

// Accepts "host", "host:port", "[ipv6]", "[ipv6]:port" or a bare IPv6 address.
// Rejects anything with characters that don't belong in a host name.
std::optional<ServerAddress> parse_server_address(const std::string& text);

// "host", "host:port" or "[ipv6]:port". The port is omitted when it is the default.
std::string format_server_address(const ServerAddress& addr);

bool same_server(const ServerAddress& a, const ServerAddress& b);

// --- Contact cards ---
//
// A card is one line of text holding a name, both public keys and optionally a
// relay server: "pqft-contact-1:<base64url>". A short checksum catches copy/paste
// damage. It is NOT authentication: anyone can make a card. Trust comes from
// comparing the fingerprint with the person out of band.

struct ContactCard {
    std::string name;                // the sender's chosen display name (untrusted text)
    std::vector<uint8_t> pub_kem;
    std::vector<uint8_t> pub_dsa;
    std::string server;              // optional suggested relay, e.g. "10.8.0.1" or ""
};

std::string encode_contact_card(const ContactCard& card);

// Tolerates whitespace and line wrapping. On failure returns std::nullopt and
// (if `error` is non-null) a message suitable for showing to the user.
std::optional<ContactCard> decode_contact_card(const std::string& text, std::string* error = nullptr);

bool looks_like_contact_card(const std::string& text);

// Turns an untrusted display name into something KeyStore accepts as a contact name.
std::string sanitize_contact_name(const std::string& raw);

// --- Share links ---
//
// "pqft://host[:port]/<32 hex transfer id>". The link is a download credential,
// exactly like the bare transfer ID.

struct ShareLink {
    ServerAddress server;
    std::string transfer_id;  // lowercase hex
};

std::string build_share_link(const ServerAddress& server, const std::string& transfer_id);
std::optional<ShareLink> parse_share_link(const std::string& text);
