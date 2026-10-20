#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// The keyring (M4): what a reinstalled app needs, besides the keys folder, to find and open its chats'
// archives and to restore the small facts that can't be rebuilt from them. It is encrypted under a key
// derived from the identity's keys and kept in a slot of the user's own mailbox on the relay, which can't
// read it. Messages are not in it: they come back from the archives.
namespace keyring {

using Bytes = std::vector<uint8_t>;

constexpr uint32_t VERSION = 1;

struct ArchiveItem {
    Bytes conversation_id;
    std::string relay_address;
    Bytes relay_id;
    int role = 2;   // 1 creator, 2 member
    int state = 0;  // 0 granted (the join token is still needed), 1 joined, 2 failed
    Bytes archive_key;
    Bytes chat_public_key, chat_private_key;
    Bytes join_token;  // only while granted
};
struct MemberToken {
    Bytes conversation_id;
    std::string member_fp;
    Bytes token;
};
struct Introduced {
    std::string fp;
    Bytes bundle;
    int64_t issued_at = 0;
    std::string introduced_by;
    int64_t first_seen = 0;
};
struct IssuedToken {
    Bytes hash;
    std::string label;
    int64_t created_at = 0;
    std::string bound_fp;
    bool revoked = false;
};
struct Receipts {
    Bytes conversation_id;
    bool delivery = true;
    bool read = true;
};

struct Contents {
    std::vector<ArchiveItem> archives;
    std::vector<std::string> verified;  // fingerprints the user compared
    std::vector<MemberToken> member_tokens;
    std::vector<Introduced> introduced;
    std::vector<IssuedToken> issued_tokens;
    std::vector<Receipts> receipts;

    bool empty() const {
        return archives.empty() && verified.empty() && member_tokens.empty() && introduced.empty() && issued_tokens.empty() && receipts.empty();
    }
};

// The same contents always give the same bytes, so a changed keyring can be told from an unchanged one.
// Throws std::runtime_error if something is too large to represent.
Bytes serialize(const Contents& contents);
// Strict: std::nullopt for anything malformed, over-long, out of range or from a newer version.
std::optional<Contents> parse(const Bytes& data);

// nonce(12) || AES-256-GCM(key, plaintext), with the mailbox ID as associated data so a keyring can't be
// passed off as another mailbox's. `key` is 32 bytes.
Bytes seal(const Bytes& key, const Bytes& mailbox_id, const Bytes& plaintext);
std::optional<Bytes> open(const Bytes& key, const Bytes& mailbox_id, const Bytes& sealed);

}  // namespace keyring
