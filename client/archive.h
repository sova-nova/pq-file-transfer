#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "relay_protocol.h"

// Chat archives, the client's half (M4). The relay keeps an encrypted, hash-chained log per chat and
// cannot read it; this is how an entry is encrypted and how a copy of the chain is checked.
namespace archive {

using Bytes = std::vector<uint8_t>;

constexpr size_t KEY_BYTES = 32;     // the archive key every member holds
constexpr size_t NONCE_BYTES = 12;
constexpr size_t TAG_BYTES = 16;
// The largest record an entry can hold: its sealed form must fit the relay's entry limit.
constexpr size_t MAX_RECORD_BYTES = relay::MAX_ARCHIVE_ENTRY_BYTES - NONCE_BYTES - TAG_BYTES;

// The head of an empty archive, and each entry's hash, exactly as the relay works them out.
Bytes genesis_hash(const Bytes& archive_id);
Bytes entry_hash(const Bytes& archive_id, uint64_t number, const Bytes& previous_hash, const Bytes& blob);

// What is stored as an entry: a fresh random nonce, then AES-256-GCM of one signed record under the
// archive key, with the archive ID and entry number as associated data. The nonce is random and kept
// with the entry, not derived from the entry number: when two members race for the same number the
// relay sees both ciphertexts (the loser's is refused but was still sent), and under one key and one
// nonce that would leak both messages.
// Throws std::runtime_error if the key or record has the wrong size.
Bytes seal_entry(const Bytes& archive_key, const Bytes& archive_id, uint64_t number, const Bytes& record);
// std::nullopt if the entry was made under another key, for another archive or number, or was altered.
std::optional<Bytes> open_entry(const Bytes& archive_key, const Bytes& archive_id, uint64_t number, const Bytes& blob);

struct Head {
    uint64_t number = 0;
    Bytes hash;
};
// Checks that `entries` carry on from `from` in an unbroken chain: consecutive numbers, and each hash
// the one that follows from the entry before it. Returns the new head, or std::nullopt if anything is
// out of order, missing, reordered or altered. An empty list is valid (the head is unchanged).
std::optional<Head> verify_chain(const Bytes& archive_id, const Head& from, const std::vector<relay::ArchiveEntry>& entries);

}  // namespace archive
