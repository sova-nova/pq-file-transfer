#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "identity_bundle.h"

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

bool looks_like_contact_card(const std::string& text);  // either version

// --- Contact cards, version 2 ---
//
// "pqft-contact-2:<base64url>" holds a signed identity bundle (see identity_bundle.h) plus the
// same copy/paste checksum. Unlike a v1 card, its encryption key is bound to the signing key,
// so altering it in transit breaks the signature.

std::string encode_contact_card_v2(const std::vector<uint8_t>& bundle_raw);

// --- Contact cards, version 3 ---
//
// "pqft-contact-3:<base64url>": the signed bundle (which now carries the mailbox address) plus the
// send token issued for whoever this card is for. The token sits outside the signature on purpose:
// it is a bearer credential for one contact, not a statement about the identity, so the bundle
// itself can be public without letting anyone message you.
std::string encode_contact_card_v3(const std::vector<uint8_t>& bundle_raw, const std::vector<uint8_t>& send_token);

// What importing either kind of card yields. `bundle` is set for v2 cards only; a contact
// added from a card without one has an encryption key nobody has verified.
struct ImportedCard {
    std::string name;                // suggested name (untrusted text)
    std::vector<uint8_t> pub_kem;
    std::vector<uint8_t> pub_dsa;
    std::string server;              // optional suggested relay; "" if none
    std::optional<IdentityBundle> bundle;
    std::vector<uint8_t> send_token;  // v3 cards: lets you deposit to this contact's mailbox; empty otherwise
};

// Decodes a v3, v2 or v1 card (the newest version present wins). On failure returns std::nullopt and,
// if `error` is non-null, a message suitable for showing to the user.
std::optional<ImportedCard> decode_any_contact_card(const std::string& text, std::string* error = nullptr);

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

// --- Relay invites ---
//
// "pqft-relay://host[:port]/<64 hex relay ID>/<32 hex invite code>", printed by
// `pq-server --create-invite --public-address ...`. One string carries where the relay is, which
// relay key to trust (so the very first connection is already verified) and the one-time code.

struct RelayInvite {
    ServerAddress server;
    std::vector<uint8_t> relay_id;  // 32 bytes: SHA-256 of the relay's signing key
    std::vector<uint8_t> invite;    // 16 bytes
};

std::string build_relay_invite(const RelayInvite& invite);
// Tolerates surrounding whitespace, quotes and dashes or spaces inside the code.
std::optional<RelayInvite> parse_relay_invite(const std::string& text);
