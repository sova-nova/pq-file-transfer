#include "transfer_engine.h"

#include "crypto_engine.h"
#include "protocol.h"
#include "scope_exit.h"

#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>

namespace fs = std::filesystem;

namespace {

constexpr int SOCKET_TIMEOUT_SECONDS = 60;

// Domain-separation labels. Each use of a key or signature gets its own label so
// a value produced for one purpose can never be accepted for another.
const char SIGNATURE_CONTEXT[] = "pq-file-transfer v2 header signature";
const char METADATA_AAD[] = "pq-file-transfer v2 metadata";
const char CHUNK_AAD[] = "pq-file-transfer v2 chunk";

struct TransferError : std::runtime_error {
    using std::runtime_error::runtime_error;
};
struct TransferCancelled {};

// The sender signs the public header plus the sealed fields. Everything is
// length-prefixed so field boundaries are unambiguous.
std::vector<uint8_t> build_signing_payload(const std::vector<uint8_t>& public_fields,
                                           const std::string& filename,
                                           const std::string& sender_fingerprint) {
    std::vector<uint8_t> p;
    write_string(p, SIGNATURE_CONTEXT);
    write_blob(p, public_fields);
    write_string(p, filename);
    write_string(p, sender_fingerprint);
    return p;
}

std::vector<uint8_t> metadata_aad() {
    return std::vector<uint8_t>(METADATA_AAD, METADATA_AAD + sizeof(METADATA_AAD) - 1);
}

// Binds each chunk to its position and marks the last one, so chunks can't be
// reordered, duplicated or dropped without failing authentication.
std::vector<uint8_t> chunk_aad(uint32_t index, bool is_last) {
    std::vector<uint8_t> aad(CHUNK_AAD, CHUNK_AAD + sizeof(CHUNK_AAD) - 1);
    write_u32(aad, index);
    aad.push_back(is_last ? 1 : 0);
    return aad;
}

// Unique per chunk under a per-transfer key: base nonce XOR big-endian index.
std::vector<uint8_t> chunk_nonce(const std::vector<uint8_t>& base, uint32_t index) {
    std::vector<uint8_t> nonce = base;
    nonce[8]  ^= static_cast<uint8_t>(index >> 24);
    nonce[9]  ^= static_cast<uint8_t>(index >> 16);
    nonce[10] ^= static_cast<uint8_t>(index >> 8);
    nonce[11] ^= static_cast<uint8_t>(index);
    return nonce;
}

// Server-provided text goes into the UI; keep it short and printable.
std::string clean_server_text(const std::vector<uint8_t>& payload) {
    std::string out;
    for (uint8_t b : payload) {
        if (out.size() >= 200) break;
        out.push_back(b >= 0x20 && b != 0x7F ? static_cast<char>(b) : ' ');
    }
    return out.empty() ? "unknown error" : out;
}

[[noreturn]] void throw_server_error(const std::optional<WireMessage>& msg, const std::string& context) {
    if (msg && msg->type == MessageType::ERROR_MSG)
        throw TransferError("Server: " + clean_server_text(msg->payload));
    throw TransferError(context);
}

// Replaces invalid UTF-8 with '_' (Windows can't build a path from it).
std::string sanitize_utf8(const std::string& in) {
    std::string out;
    size_t i = 0;
    while (i < in.size()) {
        auto byte = [&](size_t k) { return static_cast<unsigned char>(in[i + k]); };
        unsigned char c = byte(0);
        size_t n = c < 0x80 ? 1 : (c >> 5) == 0x6 ? 2 : (c >> 4) == 0xE ? 3 : (c >> 3) == 0x1E ? 4 : 0;
        bool valid = n != 0 && i + n <= in.size();
        for (size_t k = 1; valid && k < n; k++) valid = (byte(k) & 0xC0) == 0x80;
        if (valid && n == 2) valid = c >= 0xC2;                                          // overlong
        if (valid && n == 3) valid = !(c == 0xE0 && byte(1) < 0xA0) &&                   // overlong
                                     !(c == 0xED && byte(1) >= 0xA0);                    // surrogates
        if (valid && n == 4) valid = !(c == 0xF0 && byte(1) < 0x90) && c <= 0xF4 &&
                                     !(c == 0xF4 && byte(1) >= 0x90);                    // > U+10FFFF
        if (valid) {
            out.append(in, i, n);
            i += n;
        } else {
            out.push_back('_');
            i++;
        }
    }
    return out;
}

// The filename comes from the sender. Even a trusted contact's name must not
// be able to escape the downloads folder or produce a hidden/special file.
std::string sanitize_filename(const std::string& raw) {
    std::string name = sanitize_utf8(raw);
    auto slash = name.find_last_of("/\\");
    if (slash != std::string::npos) name = name.substr(slash + 1);

    std::string cleaned;
    for (char ch : name) {
        unsigned char u = static_cast<unsigned char>(ch);
        bool bad = u < 0x20 || u == 0x7F || std::strchr("<>:\"|?*", ch) != nullptr;
        cleaned.push_back(bad ? '_' : ch);
    }
    while (!cleaned.empty() && (cleaned.front() == '.' || cleaned.front() == ' ')) cleaned.erase(0, 1);
    while (!cleaned.empty() && (cleaned.back() == '.' || cleaned.back() == ' ')) cleaned.pop_back();

    if (cleaned.size() > 200) {
        size_t cut = 200;
        while (cut > 0 && (static_cast<unsigned char>(cleaned[cut]) & 0xC0) == 0x80) cut--;
        cleaned.resize(cut);
    }
    if (cleaned.empty()) return "received_file";

    std::string base = cleaned.substr(0, cleaned.find('.'));
    for (auto& c : base)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    static const char* reserved[] = {"con", "prn", "aux", "nul",
                                     "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
                                     "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9"};
    for (const char* r : reserved)
        if (base == r) return "_" + cleaned;
    return cleaned;
}

fs::path part_path_for(const fs::path& p) {
    fs::path part = p;
    part += ".part";
    return part;
}

// Never overwrite an existing file: "report.pdf" → "report (1).pdf" → ...
fs::path unique_output_path(const fs::path& dir, const std::string& name) {
    fs::path base = fs::u8path(name);
    std::string stem = base.stem().u8string();
    std::string ext = base.extension().u8string();
    for (int n = 0; n < 10000; n++) {
        std::string candidate = n == 0 ? name : stem + " (" + std::to_string(n) + ")" + ext;
        fs::path p = dir / fs::u8path(candidate);
        std::error_code ec;
        if (!fs::exists(p, ec) && !fs::exists(part_path_for(p), ec)) return p;
    }
    throw TransferError("Could not find a free file name in " + dir.u8string());
}

}  // namespace

// --- Public entry points ---

void TransferEngine::upload_file(const std::string& filepath, const std::string& server_host,
                                 uint16_t server_port, const KeyStore::Contact& recipient) {
    cancel_flag_ = false;
    try {
        upload_impl(filepath, server_host, server_port, recipient);
    } catch (const TransferCancelled&) {
        if (on_error) on_error("Transfer cancelled");
    } catch (const std::exception& e) {
        if (on_error) on_error(e.what());
    }
}

void TransferEngine::download_file(const std::string& transfer_id, const std::string& server_host,
                                   uint16_t server_port, const std::string& output_dir) {
    cancel_flag_ = false;
    try {
        download_impl(transfer_id, server_host, server_port, output_dir);
    } catch (const TransferCancelled&) {
        if (on_error) on_error("Transfer cancelled");
    } catch (const std::exception& e) {
        if (on_error) on_error(e.what());
    }
}

const KeyStore& TransferEngine::active_keystore(std::unique_ptr<KeyStore>& fallback) const {
    if (keystore_) return *keystore_;
    fallback = std::make_unique<KeyStore>();
    return *fallback;
}

void TransferEngine::cancel() {
    cancel_flag_ = true;
    std::lock_guard<std::mutex> lock(socket_mutex_);
    // Unblocks any send/recv in progress; the worker then closes the socket.
    if (active_socket_ != INVALID_SOCKET_VAL) ::shutdown(active_socket_, SHUTDOWN_BOTH);
}

// --- Helpers ---

void TransferEngine::status(const std::string& msg) {
    if (on_status) on_status(msg);
}

void TransferEngine::progress(double fraction) {
    if (on_progress) on_progress(fraction);
}

void TransferEngine::check_cancelled() const {
    if (cancel_flag_) throw TransferCancelled{};
}

socket_t TransferEngine::connect_to_server(const std::string& host, uint16_t port) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* results = nullptr;
    std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &results) != 0 || !results)
        throw TransferError("Could not resolve server address \"" + host + "\"");
    auto free_results = make_scope_exit([results] { freeaddrinfo(results); });

    int failure = 0;
    for (addrinfo* ai = results; ai; ai = ai->ai_next) {
        check_cancelled();
        socket_t sock = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock == INVALID_SOCKET_VAL) continue;
        set_socket_timeouts(sock, SOCKET_TIMEOUT_SECONDS);
        disable_sigpipe(sock);
        {
            std::lock_guard<std::mutex> lock(socket_mutex_);
            active_socket_ = sock;
        }
        if (::connect(sock, ai->ai_addr, static_cast<socklen_t>(ai->ai_addrlen)) == 0) return sock;
        failure = last_socket_error();  // read before release_socket can change it
        release_socket(sock);
    }
    check_cancelled();
    throw TransferError(describe_connect_failure("server", host + ":" + port_str, failure));
}

void TransferEngine::release_socket(socket_t sock) {
    std::lock_guard<std::mutex> lock(socket_mutex_);
    if (active_socket_ == sock) active_socket_ = INVALID_SOCKET_VAL;
    close_socket(sock);
}

// --- Upload ---

void TransferEngine::upload_impl(const std::string& filepath, const std::string& host, uint16_t port,
                                 const KeyStore::Contact& recipient) {
    status("Loading keys...");
    std::unique_ptr<KeyStore> fallback_store;
    const KeyStore& keystore = active_keystore(fallback_store);
    if (keystore.private_keys_locked()) throw TransferError("Your keys are locked. Unlock them first");
    auto priv_dsa = keystore.load_private_dsa();
    auto pub_dsa = keystore.load_public_dsa();
    auto wipe_key = make_scope_exit([&] { CryptoEngine::secure_wipe(priv_dsa); });
    if (priv_dsa.empty() || pub_dsa.empty()) throw TransferError("Your signing keys could not be loaded");

    // Open and size the file before doing anything on the network.
    fs::path path = fs::u8path(filepath);
    std::error_code ec;
    if (!fs::is_regular_file(path, ec)) throw TransferError("Not a regular file: " + filepath);
    uint64_t file_size = fs::file_size(path, ec);
    if (ec) throw TransferError("Cannot read file size: " + filepath);
    if (file_size > MAX_FILE_SIZE) throw TransferError("File is larger than the 16 GiB limit");

    std::string filename = path.filename().u8string();
    if (filename.size() > MAX_FILENAME_BYTES) throw TransferError("File name is too long");

    std::ifstream file(path, std::ios::binary);
    if (!file) throw TransferError("Cannot open file: " + filepath);

    status("Encrypting for " + recipient.name + "...");

    FileHeader header;
    header.file_size = file_size;
    header.chunk_size = DEFAULT_CHUNK_SIZE;
    header.total_chunks = expected_total_chunks(file_size, header.chunk_size);
    header.nonce = CryptoEngine::random_bytes(NONCE_SIZE);

    auto encap = CryptoEngine::encapsulate(recipient.pub_kem);
    header.kem_ciphertext = encap.ciphertext;

    // Keys depend on every public header field, so tampering with any of them
    // makes decryption fail.
    auto public_fields = serialize_header_public_fields(header);
    auto keys = CryptoEngine::derive_session_keys(encap.shared_secret, CryptoEngine::sha256(public_fields));
    CryptoEngine::secure_wipe(encap.shared_secret);

    FileMetadata meta;
    meta.filename = filename;
    meta.sender_fingerprint = CryptoEngine::fingerprint(pub_dsa);
    meta.signature = CryptoEngine::sign(
        build_signing_payload(public_fields, meta.filename, meta.sender_fingerprint), priv_dsa);
    CryptoEngine::secure_wipe(priv_dsa);

    header.sealed_metadata = CryptoEngine::encrypt(keys.metadata_key, header.nonce,
                                                   serialize_file_metadata(meta), metadata_aad());

    status("Connecting to server...");
    socket_t sock = connect_to_server(host, port);
    auto close_guard = make_scope_exit([&] { release_socket(sock); });

    if (!send_message(sock, MessageType::UPLOAD_REQUEST, serialize_file_header(header))) {
        check_cancelled();
        throw TransferError("Failed to send file header");
    }

    auto ack = recv_message(sock, MAX_CONTROL_MESSAGE);
    check_cancelled();
    if (!ack || ack->type != MessageType::ACK) throw_server_error(ack, "Server rejected the upload");

    std::string transfer_id(ack->payload.begin(), ack->payload.end());
    if (!is_lower_hex(transfer_id, TRANSFER_ID_HEX_LEN)) throw TransferError("Server sent an invalid transfer ID");
    if (on_transfer_id) on_transfer_id(transfer_id);

    status("Encrypting and uploading " + filename + "...");
    std::vector<uint8_t> buffer;
    uint64_t bytes_sent = 0;

    for (uint32_t i = 0; i < header.total_chunks; i++) {
        check_cancelled();

        size_t expected = static_cast<size_t>(expected_chunk_plaintext_size(header, i));
        buffer.resize(expected);
        if (expected > 0) {
            file.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(expected));
            if (static_cast<size_t>(file.gcount()) != expected)
                throw TransferError("The file changed while it was being sent");
        }

        FileChunk chunk;
        chunk.chunk_index = i;
        chunk.data = CryptoEngine::encrypt(keys.data_key, chunk_nonce(header.nonce, i), buffer,
                                           chunk_aad(i, i + 1 == header.total_chunks));

        if (!send_message(sock, MessageType::UPLOAD_CHUNK, serialize_file_chunk(chunk))) {
            check_cancelled();
            // The server may have explained why it stopped reading.
            throw_server_error(recv_message(sock, MAX_CONTROL_MESSAGE), "Connection lost while uploading");
        }

        bytes_sent += expected;
        progress(file_size == 0 ? 1.0 : static_cast<double>(bytes_sent) / static_cast<double>(file_size));
    }

    if (file.peek() != std::char_traits<char>::eof())
        throw TransferError("The file changed while it was being sent");

    if (!send_message(sock, MessageType::UPLOAD_DONE, {})) {
        check_cancelled();
        throw TransferError("Failed to finalize upload");
    }

    auto final_ack = recv_message(sock, MAX_CONTROL_MESSAGE);
    check_cancelled();
    if (!final_ack || final_ack->type != MessageType::ACK) throw_server_error(final_ack, "Server did not confirm the upload");

    progress(1.0);
    status("Uploaded " + filename + " for " + recipient.name +
           ". Send them the transfer ID. It works once and expires in 24 hours.");
    if (on_complete) on_complete(filepath);
}

// --- Download ---

void TransferEngine::download_impl(const std::string& raw_id, const std::string& host, uint16_t port,
                                   const std::string& output_dir) {
    // Accept IDs pasted with stray whitespace or in upper case.
    std::string transfer_id;
    for (char c : raw_id) {
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') continue;
        transfer_id.push_back(c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c);
    }
    if (!is_lower_hex(transfer_id, TRANSFER_ID_HEX_LEN))
        throw TransferError("That doesn't look like a transfer ID (expected 32 hex characters)");

    std::unique_ptr<KeyStore> fallback_store;
    const KeyStore& keystore = active_keystore(fallback_store);
    if (keystore.private_keys_locked()) throw TransferError("Your keys are locked. Unlock them first");
    auto priv_kem = keystore.load_private_kem();
    auto own_pub_dsa = keystore.load_public_dsa();
    auto wipe_key = make_scope_exit([&] { CryptoEngine::secure_wipe(priv_kem); });
    if (priv_kem.empty() || own_pub_dsa.empty()) throw TransferError("Your keys could not be loaded");

    status("Connecting to server...");
    socket_t sock = connect_to_server(host, port);
    auto close_guard = make_scope_exit([&] { release_socket(sock); });

    if (!send_text_message(sock, MessageType::DOWNLOAD_REQUEST, transfer_id)) {
        check_cancelled();
        throw TransferError("Failed to send download request");
    }

    status("Receiving file header...");
    auto header_msg = recv_message(sock, MAX_HEADER_MESSAGE);
    check_cancelled();
    if (!header_msg || header_msg->type != MessageType::DOWNLOAD_HEADER)
        throw_server_error(header_msg, "Server did not send a file header");

    auto header = deserialize_file_header(header_msg->payload.data(), header_msg->payload.size());
    if (!header) throw TransferError("Malformed file header (the sender may be using a different version)");
    std::string problem = validate_file_header(*header);
    if (!problem.empty()) throw TransferError("Invalid file header: " + problem);
    if (header->kem_ciphertext.size() != CryptoEngine::kem_ciphertext_size())
        throw TransferError("Invalid file header: bad key encapsulation size");

    status("Decrypting...");
    auto public_fields = serialize_header_public_fields(*header);
    auto shared_secret = CryptoEngine::decapsulate(header->kem_ciphertext, priv_kem);
    auto keys = CryptoEngine::derive_session_keys(shared_secret, CryptoEngine::sha256(public_fields));
    CryptoEngine::secure_wipe(shared_secret);
    CryptoEngine::secure_wipe(priv_kem);

    // ML-KEM never "fails" for the wrong key; it yields an unrelated secret, so
    // this authenticated decryption is where a transfer meant for someone else
    // (or a tampered header) is detected.
    auto meta_bytes = CryptoEngine::decrypt(keys.metadata_key, header->nonce, header->sealed_metadata, metadata_aad());
    if (!meta_bytes)
        throw TransferError("This transfer was not encrypted for your keys, or it was tampered with");
    auto meta = deserialize_file_metadata(meta_bytes->data(), meta_bytes->size());
    if (!meta) throw TransferError("Malformed transfer metadata");

    status("Verifying sender...");
    std::string sender_name;
    std::vector<uint8_t> sender_pub_dsa;
    if (meta->sender_fingerprint == CryptoEngine::fingerprint(own_pub_dsa)) {
        sender_name = "yourself";
        sender_pub_dsa = own_pub_dsa;
    } else if (auto contact = keystore.find_contact_by_fingerprint(meta->sender_fingerprint)) {
        sender_name = contact->name;
        sender_pub_dsa = contact->pub_dsa;
    } else {
        throw TransferError("The sender is not in your contacts (fingerprint " +
                            meta->sender_fingerprint.substr(0, 16) +
                            "...). Add them, after verifying their fingerprint, then try again.");
    }

    auto signing_payload = build_signing_payload(public_fields, meta->filename, meta->sender_fingerprint);
    if (!CryptoEngine::verify(signing_payload, meta->signature, sender_pub_dsa))
        throw TransferError("Signature verification FAILED. The transfer may be forged or tampered with");

    std::string safe_name = sanitize_filename(meta->filename);
    status("Signature verified, from " + sender_name + ". Receiving " + safe_name + "...");

    fs::path out_dir = fs::u8path(output_dir);
    std::error_code ec;
    fs::create_directories(out_dir, ec);
    if (ec) throw TransferError("Cannot create download folder: " + ec.message());

    // Write to "<name>.part" and only rename once every chunk has been
    // authenticated, so a failed transfer never leaves a plausible-looking file.
    fs::path final_path = unique_output_path(out_dir, safe_name);
    fs::path part_path = part_path_for(final_path);
    std::ofstream out(part_path, std::ios::binary | std::ios::trunc);
    if (!out) throw TransferError("Cannot create output file in " + out_dir.u8string());
    auto remove_partial = make_scope_exit([&] {
        out.close();
        std::error_code rm_ec;
        fs::remove(part_path, rm_ec);
    });

    uint64_t bytes_written = 0;
    for (uint32_t i = 0; i < header->total_chunks; i++) {
        check_cancelled();
        auto msg = recv_message(sock, MAX_CHUNK_MESSAGE);
        check_cancelled();
        if (!msg || msg->type != MessageType::DOWNLOAD_CHUNK)
            throw_server_error(msg, "Connection lost during download");

        auto chunk = deserialize_file_chunk(msg->payload.data(), msg->payload.size());
        if (!chunk) throw TransferError("Malformed chunk from server");
        if (chunk->chunk_index != i) throw TransferError("Chunks arrived out of order");

        auto plain = CryptoEngine::decrypt(keys.data_key, chunk_nonce(header->nonce, i), chunk->data,
                                           chunk_aad(i, i + 1 == header->total_chunks));
        if (!plain) throw TransferError("Chunk " + std::to_string(i) + " failed authentication. Data was tampered with");
        if (plain->size() != expected_chunk_plaintext_size(*header, i))
            throw TransferError("Chunk " + std::to_string(i) + " has an unexpected size");

        if (!plain->empty()) {
            out.write(reinterpret_cast<const char*>(plain->data()), static_cast<std::streamsize>(plain->size()));
            if (!out) throw TransferError("Failed writing to disk (is it full?)");
        }
        bytes_written += plain->size();
        progress(header->file_size == 0 ? 1.0
                                        : static_cast<double>(bytes_written) / static_cast<double>(header->file_size));
    }

    auto done = recv_message(sock, MAX_CONTROL_MESSAGE);
    check_cancelled();
    if (!done || done->type != MessageType::DOWNLOAD_DONE) throw_server_error(done, "Server did not finish the transfer");

    out.close();
    if (out.fail() || bytes_written != header->file_size) throw TransferError("Failed writing to disk");

    // If something took the name meanwhile, pick another rather than overwrite.
    if (fs::exists(final_path, ec)) final_path = unique_output_path(out_dir, safe_name);
    fs::rename(part_path, final_path, ec);
    if (ec) throw TransferError("Cannot save file: " + ec.message());
    remove_partial.dismiss();

    // Tell the relay it can delete its copy. If this fails the copy just expires.
    send_message(sock, MessageType::ACK, {});

    progress(1.0);
    status("Received " + final_path.filename().u8string() + " from " + sender_name);
    if (on_complete) on_complete(final_path.u8string());
}
