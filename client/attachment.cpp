#include "attachment.h"

#include <algorithm>
#include <cctype>
#include <memory>
#include <stdexcept>

#include <openssl/evp.h>

#include "crypto_engine.h"
#include "protocol.h"

namespace attachment {

namespace {

const char CHUNK_AAD_LABEL[] = "pq-suite v3 attachment chunk";

Bytes chunk_aad(const Bytes& file_id, uint32_t index, uint32_t count) {
    Bytes b;
    write_string(b, CHUNK_AAD_LABEL);
    write_blob(b, file_id);
    write_u32(b, index);
    write_u32(b, count);
    return b;
}

Bytes chunk_nonce(uint32_t index) {
    Bytes n(12, 0);
    for (int i = 0; i < 4; i++) n[11 - i] = static_cast<uint8_t>(index >> (8 * i));
    return n;
}

uint64_t plain_size_of_chunk(const Plan& plan, uint64_t size, uint32_t index) {
    return index + 1 < plan.chunk_count ? CHUNK_PLAINTEXT_BYTES : size - static_cast<uint64_t>(CHUNK_PLAINTEXT_BYTES) * (plan.chunk_count - 1);
}

// Strict UTF-8 decoding: no overlong forms, surrogates or values beyond U+10FFFF.
bool decode_utf8(const std::string& s, std::vector<uint32_t>& out) {
    static const uint32_t MIN_FOR_LENGTH[] = {0, 0, 0x80, 0x800, 0x10000};
    size_t i = 0;
    while (i < s.size()) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        uint32_t cp;
        size_t len;
        if (c < 0x80) { cp = c; len = 1; }
        else if ((c & 0xE0) == 0xC0) { cp = c & 0x1Fu; len = 2; }
        else if ((c & 0xF0) == 0xE0) { cp = c & 0x0Fu; len = 3; }
        else if ((c & 0xF8) == 0xF0) { cp = c & 0x07u; len = 4; }
        else return false;
        if (i + len > s.size()) return false;
        for (size_t k = 1; k < len; k++) {
            const unsigned char cc = static_cast<unsigned char>(s[i + k]);
            if ((cc & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (cc & 0x3Fu);
        }
        if (len > 1 && cp < MIN_FOR_LENGTH[len]) return false;
        if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
        out.push_back(cp);
        i += len;
    }
    return true;
}

void append_utf8(std::string& out, uint32_t cp) {
    if (cp < 0x80) out += static_cast<char>(cp);
    else if (cp < 0x800) { out += static_cast<char>(0xC0 | (cp >> 6)); out += static_cast<char>(0x80 | (cp & 0x3F)); }
    else if (cp < 0x10000) { out += static_cast<char>(0xE0 | (cp >> 12)); out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F)); out += static_cast<char>(0x80 | (cp & 0x3F)); }
    else { out += static_cast<char>(0xF0 | (cp >> 18)); out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F)); out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F)); out += static_cast<char>(0x80 | (cp & 0x3F)); }
}

bool unsafe_in_name(uint32_t cp) {
    if (cp < 0x20 || (cp >= 0x7F && cp <= 0x9F)) return true;                      // control characters
    if ((cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069)) return true;  // text-direction overrides and isolates
    if (cp == 0x200E || cp == 0x200F || cp == 0x061C || cp == 0xFEFF) return true;       // direction marks, byte order mark
    switch (cp) {
        case '/': case '\\': case ':': case '*': case '?': case '"': case '<': case '>': case '|': return true;
        default: return false;
    }
}

bool reserved_windows_name(const std::string& name) {
    std::string base = name.substr(0, name.find('.'));
    while (!base.empty() && base.back() == ' ') base.pop_back();
    std::string upper;
    for (char c : base) upper += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    if (upper == "CON" || upper == "PRN" || upper == "AUX" || upper == "NUL") return true;
    return upper.size() == 4 && (upper.compare(0, 3, "COM") == 0 || upper.compare(0, 3, "LPT") == 0) && upper[3] >= '1' && upper[3] <= '9';
}

}  // namespace

Plan plan_for(uint64_t plaintext_size) {
    if (plaintext_size > MAX_PLAINTEXT_BYTES) throw std::runtime_error("That file is too large to send");
    Plan p;
    p.chunk_count = plaintext_size == 0 ? 1 : static_cast<uint32_t>((plaintext_size + CHUNK_PLAINTEXT_BYTES - 1) / CHUNK_PLAINTEXT_BYTES);
    p.chunk_size = static_cast<uint32_t>(CHUNK_PLAINTEXT_BYTES + TAG_BYTES);
    p.ciphertext_size = plaintext_size + static_cast<uint64_t>(p.chunk_count) * TAG_BYTES;
    return p;
}

Bytes seal_chunk(const Bytes& key, const Bytes& file_id, uint32_t index, uint32_t count, const Bytes& plaintext) {
    if (key.size() != KEY_BYTES) throw std::runtime_error("The file key has the wrong size");
    if (file_id.size() != relay::FILE_ID_BYTES || plaintext.size() > CHUNK_PLAINTEXT_BYTES || count == 0 || index >= count)
        throw std::runtime_error("That chunk is not valid");
    return CryptoEngine::encrypt(key, chunk_nonce(index), plaintext, chunk_aad(file_id, index, count));
}

std::optional<Bytes> open_chunk(const Bytes& key, const Bytes& file_id, uint32_t index, uint32_t count, const Bytes& sealed) {
    if (key.size() != KEY_BYTES || file_id.size() != relay::FILE_ID_BYTES || count == 0 || index >= count || sealed.size() < TAG_BYTES ||
        sealed.size() > CHUNK_PLAINTEXT_BYTES + TAG_BYTES)
        return std::nullopt;
    try {
        return CryptoEngine::decrypt(key, chunk_nonce(index), sealed, chunk_aad(file_id, index, count));
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

Sha256::Sha256() : ctx_(EVP_MD_CTX_new()) {
    if (!ctx_ || EVP_DigestInit_ex(ctx_, EVP_sha256(), nullptr) != 1) throw std::runtime_error("Could not start a hash");
}
Sha256::~Sha256() { EVP_MD_CTX_free(ctx_); }
void Sha256::update(const uint8_t* data, size_t size) {
    if (size && EVP_DigestUpdate(ctx_, data, size) != 1) throw std::runtime_error("Hashing failed");
}
Bytes Sha256::finish() {
    Bytes out(32);
    unsigned int n = 0;
    if (EVP_DigestFinal_ex(ctx_, out.data(), &n) != 1 || n != 32) throw std::runtime_error("Hashing failed");
    return out;
}

std::optional<Fingerprint> fingerprint_file(const fs::path& path, std::string& error) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        error = "That file could not be opened";
        return std::nullopt;
    }
    Sha256 hash;
    Fingerprint f;
    Bytes buffer(1024 * 1024);
    while (in) {
        in.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize got = in.gcount();
        if (got <= 0) break;
        f.size += static_cast<uint64_t>(got);
        if (f.size > MAX_PLAINTEXT_BYTES) {
            error = "That file is too large to send";
            return std::nullopt;
        }
        hash.update(buffer.data(), static_cast<size_t>(got));
    }
    if (in.bad()) {
        error = "That file could not be read";
        return std::nullopt;
    }
    f.sha256 = hash.finish();
    return f;
}

Encryptor::Encryptor(const fs::path& path, const Bytes& key, const Bytes& file_id, uint64_t plaintext_size)
    : in_(path, std::ios::binary), key_(key), file_id_(file_id), size_(plaintext_size), plan_(plan_for(plaintext_size)) {}

bool Encryptor::chunk(uint32_t index, Bytes& sealed, std::string& error) {
    if (!in_.is_open()) {
        error = "That file could not be opened";
        return false;
    }
    in_.clear();  // an earlier short read must not make every later request fail
    if (index >= plan_.chunk_count) {
        error = "That chunk is past the end of the file";
        return false;
    }
    const uint64_t want = plain_size_of_chunk(plan_, size_, index);
    Bytes plain(static_cast<size_t>(want));
    in_.clear();
    in_.seekg(static_cast<std::streamoff>(static_cast<uint64_t>(index) * CHUNK_PLAINTEXT_BYTES));
    if (want) in_.read(reinterpret_cast<char*>(plain.data()), static_cast<std::streamsize>(want));
    if (!in_ || static_cast<uint64_t>(in_.gcount()) != want) {
        error = "The file changed while it was being sent";
        return false;
    }
    try {
        sealed = seal_chunk(key_, file_id_, index, plan_.chunk_count, plain);
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
    return true;
}

Decryptor::Decryptor(const fs::path& directory, const std::string& name, const Bytes& key, const Bytes& file_id, uint64_t plaintext_size, const Bytes& sha256)
    : directory_(directory), name_(name), key_(key), file_id_(file_id), expected_hash_(sha256), size_(plaintext_size), plan_(plan_for(plaintext_size)) {
    part_ = directory_ / (".pqft-" + bytes_to_hex(file_id_).substr(0, 16) + ".part");
}

Decryptor::~Decryptor() { out_.close(); }  // what was written stays, so a later attempt can carry on

bool Decryptor::begin(bool resume, std::string& error) {
    std::error_code ec;
    if (!fs::is_directory(directory_, ec)) {
        error = "The folder to save in doesn't exist";
        return false;
    }
    out_.close();
    hash_ = std::make_unique<Sha256>();
    next_ = 0;
    written_ = 0;
    if (resume && fs::exists(part_, ec)) {
        // Keep only whole chunks, and check them again from the start: the hash has to cover everything.
        uint64_t have = fs::file_size(part_, ec);
        if (ec) have = 0;
        uint64_t keep = have >= size_ ? size_ : have - have % CHUNK_PLAINTEXT_BYTES;
        if (keep > 0) {
            fs::resize_file(part_, keep, ec);
            std::ifstream in(part_, std::ios::binary);
            Bytes buffer(1024 * 1024);
            uint64_t left = keep;
            while (in && left) {
                in.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(std::min<uint64_t>(buffer.size(), left)));
                const auto got = static_cast<uint64_t>(in.gcount());
                if (!got) break;
                hash_->update(buffer.data(), static_cast<size_t>(got));
                left -= got;
            }
            if (left) {  // it could not be read back: start again
                keep = 0;
                hash_ = std::make_unique<Sha256>();
            }
        }
        if (keep == 0) fs::resize_file(part_, 0, ec);
        written_ = keep;
        next_ = keep >= size_ && size_ > 0 ? plan_.chunk_count : static_cast<uint32_t>(keep / CHUNK_PLAINTEXT_BYTES);
        out_.open(part_, std::ios::binary | std::ios::app);
    } else {
        out_.open(part_, std::ios::binary | std::ios::trunc);
    }
    if (!out_) {
        error = "The file could not be saved here";
        return false;
    }
    return true;
}

bool Decryptor::accept(uint32_t index, const Bytes& sealed, std::string& error) {
    if (!out_ || !hash_) {
        error = "The download was not started";
        return false;
    }
    if (index != next_ || index >= plan_.chunk_count) {
        error = "A chunk arrived out of order";
        return false;
    }
    auto plain = open_chunk(key_, file_id_, index, plan_.chunk_count, sealed);
    if (!plain) {
        error = "A chunk of the file could not be opened: it is damaged, or not from this file";
        return false;
    }
    if (plain->size() != plain_size_of_chunk(plan_, size_, index)) {
        error = "A chunk of the file is the wrong size";
        return false;
    }
    out_.write(reinterpret_cast<const char*>(plain->data()), static_cast<std::streamsize>(plain->size()));
    if (!out_) {
        error = "The file could not be saved here (is the disk full?)";
        return false;
    }
    hash_->update(plain->data(), plain->size());
    written_ += plain->size();
    next_++;
    return true;
}

bool Decryptor::finish(fs::path& saved, std::string& error) {
    if (!out_ || !hash_ || next_ != plan_.chunk_count || written_ != size_) {
        error = "The file is not complete";
        return false;
    }
    out_.flush();
    out_.close();
    if (hash_->finish() != expected_hash_) {
        abort();
        error = "The file does not match the fingerprint the sender signed: it was altered, so it was not saved";
        return false;
    }
    const fs::path target = unique_path(directory_, sanitize_filename(name_));
    if (target.empty()) {
        error = "No free file name was found in that folder";
        return false;
    }
    std::error_code ec;
    fs::rename(part_, target, ec);
    if (ec) {
        error = "The file could not be saved: " + ec.message();
        return false;
    }
    saved = target;
    return true;
}

void Decryptor::abort() {
    out_.close();
    std::error_code ec;
    fs::remove(part_, ec);
    next_ = 0;
    written_ = 0;
}

std::string sanitize_filename(const std::string& name) {
    std::vector<uint32_t> cps;
    if (!decode_utf8(name, cps)) return "attachment";
    std::string out;
    for (uint32_t cp : cps) append_utf8(out, unsafe_in_name(cp) ? '_' : cp);
    // No leading or trailing spaces and dots: a leading dot hides the file, and Windows drops trailing ones.
    size_t from = 0, to = out.size();
    while (from < to && (out[from] == ' ' || out[from] == '.')) from++;
    while (to > from && (out[to - 1] == ' ' || out[to - 1] == '.')) to--;
    out = out.substr(from, to - from);
    if (out.empty()) return "attachment";
    if (out.size() > 200) {
        // Keep a short extension, and cut the rest on a character boundary.
        std::string ext;
        const size_t dot = out.rfind('.');
        if (dot != std::string::npos && dot > 0 && out.size() - dot <= 20) ext = out.substr(dot);
        size_t keep = 200 - ext.size();
        while (keep > 0 && (static_cast<unsigned char>(out[keep]) & 0xC0) == 0x80) keep--;
        out = out.substr(0, keep) + ext;
    }
    if (reserved_windows_name(out)) out = "_" + out;
    return out;
}

fs::path unique_path(const fs::path& directory, const std::string& name) {
    auto taken = [](const fs::path& p) {
        std::error_code ec;
        return fs::symlink_status(p, ec).type() != fs::file_type::not_found;  // a dangling link counts
    };
    fs::path candidate = directory / name;
    if (!taken(candidate)) return candidate;
    std::string stem = name, ext;
    const size_t dot = name.rfind('.');
    if (dot != std::string::npos && dot > 0) {
        stem = name.substr(0, dot);
        ext = name.substr(dot);
    }
    for (int n = 2; n < 10000; n++) {
        candidate = directory / (stem + " (" + std::to_string(n) + ")" + ext);
        if (!taken(candidate)) return candidate;
    }
    return fs::path();
}

}  // namespace attachment
