#pragma once

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#include "relay_protocol.h"

struct evp_md_ctx_st;

// Attachments, the client's half (M5). A file is encrypted by the sender under its own random key, in
// chunks, and parked on a relay; this is how it is cut up, sealed, put back together and checked, and how
// a name someone else chose is made safe to save under. Files are streamed from and to disk, never held whole.
namespace attachment {

using Bytes = std::vector<uint8_t>;
namespace fs = std::filesystem;

constexpr size_t KEY_BYTES = 32;
constexpr size_t TAG_BYTES = 16;
// Plaintext bytes per chunk (the last may be shorter). With the tag, a sealed chunk is 49,168 bytes: well within
// the relay's limit of one message per chunk, and big enough that a gigabyte is about 22,000 chunks.
constexpr size_t CHUNK_PLAINTEXT_BYTES = 48 * 1024;
// The largest file: its sealed form must fit the relay protocol's ceiling of 16 GiB.
constexpr uint64_t MAX_PLAINTEXT_BYTES = 15ull * 1024 * 1024 * 1024;

struct Plan {
    uint32_t chunk_count = 0;       // always at least 1: an empty file is one chunk holding only its tag
    uint32_t chunk_size = 0;        // sealed bytes in every chunk but the last (what relay::FileBegin calls chunk_size)
    uint64_t ciphertext_size = 0;   // all sealed chunks together
};
// Throws std::runtime_error if the file is too large.
Plan plan_for(uint64_t plaintext_size);

// Each file has its own random key, so a chunk's number can safely serve as its nonce: no two chunks of any file
// ever share a key and a nonce. The file's ID, the chunk's number and the chunk count are bound in as associated
// data, so a chunk can't be moved, repeated, or passed off as part of another file. Throws std::runtime_error
// if the key or chunk has the wrong size.
Bytes seal_chunk(const Bytes& key, const Bytes& file_id, uint32_t index, uint32_t count, const Bytes& plaintext);
// std::nullopt if the chunk was made under another key, for another file, place or count, or was altered.
std::optional<Bytes> open_chunk(const Bytes& key, const Bytes& file_id, uint32_t index, uint32_t count, const Bytes& sealed);

// SHA-256 computed a piece at a time.
class Sha256 {
public:
    Sha256();
    ~Sha256();
    Sha256(const Sha256&) = delete;
    Sha256& operator=(const Sha256&) = delete;
    void update(const uint8_t* data, size_t size);
    Bytes finish();  // once

private:
    evp_md_ctx_st* ctx_;
};

struct Fingerprint {
    uint64_t size = 0;
    Bytes sha256;
};
// Reads the file once to find its size and SHA-256 (which the message will carry). std::nullopt, with a reason, if
// it can't be read or is too large.
std::optional<Fingerprint> fingerprint_file(const fs::path& path, std::string& error);

// Reads a file and seals it chunk by chunk, for uploading. Chunks can be asked for in any order.
class Encryptor {
public:
    Encryptor(const fs::path& path, const Bytes& key, const Bytes& file_id, uint64_t plaintext_size);
    Plan plan() const { return plan_; }
    // Reads chunk `index` and seals it. False, with a reason, if the file can't be read or has changed size.
    bool chunk(uint32_t index, Bytes& sealed, std::string& error);

private:
    std::ifstream in_;
    Bytes key_, file_id_;
    uint64_t size_;
    Plan plan_;
};

// Puts a downloaded file back together: chunks arrive in order, each is opened and written to a temporary file next
// to where the file will be saved; at the end the whole is checked against the fingerprint the sender signed.
// Nothing is saved under the file's real name unless everything checks out.
class Decryptor {
public:
    // `directory` must exist. `name` is as the sender called it; it is made safe and made unique when saving.
    Decryptor(const fs::path& directory, const std::string& name, const Bytes& key, const Bytes& file_id, uint64_t plaintext_size, const Bytes& sha256);
    ~Decryptor();
    // With `resume`, picks up what an earlier, interrupted attempt left (re-checking it) and carries on from the next
    // whole chunk; see next_chunk().
    bool begin(bool resume, std::string& error);
    uint32_t next_chunk() const { return next_; }
    uint32_t chunk_count() const { return plan_.chunk_count; }
    // The next sealed chunk, in order. False if it is out of order, can't be opened, or is the wrong size.
    bool accept(uint32_t index, const Bytes& sealed, std::string& error);
    // After the last chunk: checks the size and SHA-256, then saves the file under a safe, unused name and returns its path.
    bool finish(fs::path& saved, std::string& error);
    // Throws away what has been written so far.
    void abort();

private:
    fs::path directory_, part_;
    std::string name_;
    Bytes key_, file_id_, expected_hash_;
    uint64_t size_;
    Plan plan_;
    uint32_t next_ = 0;
    uint64_t written_ = 0;
    std::ofstream out_;
    std::unique_ptr<Sha256> hash_;
};

// A name chosen by someone else, made safe to use as a file name here: valid UTF-8 only; no control characters, path
// separators or characters Windows forbids, no text-direction tricks; no leading or trailing spaces and dots; not a
// reserved Windows device name; at most 200 bytes (keeping the extension). Never empty.
std::string sanitize_filename(const std::string& name);
// `name` in `directory`, or "name (2).ext", "name (3).ext"... if that is taken (by anything, including a dangling
// link): nothing existing is ever overwritten. Empty if no free name was found.
fs::path unique_path(const fs::path& directory, const std::string& name);

}  // namespace attachment
