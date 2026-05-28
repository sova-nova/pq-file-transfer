#include "transfer_engine.h"
#include "protocol.h"
#include "crypto_engine.h"
#include "key_store.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <fstream>
#include <filesystem>
#include <cstring>
#include <thread>
#include <random>

namespace fs = std::filesystem;

TransferEngine::TransferEngine() = default;

void TransferEngine::cancel() {
    cancel_flag_ = true;
}

int TransferEngine::connect_to_server(const std::string& addr, uint16_t port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return -1;

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, addr.c_str(), &server_addr.sin_addr) <= 0) {
        close(sockfd);
        return -1;
    }

    if (::connect(sockfd, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) < 0) {
        close(sockfd);
        return -1;
    }

    return sockfd;
}

std::vector<uint8_t> TransferEngine::compute_chunk_nonce(
    const std::vector<uint8_t>& base_nonce, uint32_t chunk_index)
{
    std::vector<uint8_t> nonce = base_nonce;
    nonce[8]  ^= static_cast<uint8_t>(chunk_index);
    nonce[9]  ^= static_cast<uint8_t>(chunk_index >> 8);
    nonce[10] ^= static_cast<uint8_t>(chunk_index >> 16);
    nonce[11] ^= static_cast<uint8_t>(chunk_index >> 24);
    return nonce;
}

std::vector<uint8_t> TransferEngine::build_signing_payload(const FileHeader& header) {
    std::vector<uint8_t> payload;

    payload.insert(payload.end(), header.filename.begin(), header.filename.end());

    for (int i = 7; i >= 0; i--) {
        payload.push_back(static_cast<uint8_t>(header.file_size >> (i * 8)));
    }

    for (int i = 3; i >= 0; i--) {
        payload.push_back(static_cast<uint8_t>(header.chunk_size >> (i * 8)));
    }

    for (int i = 3; i >= 0; i--) {
        payload.push_back(static_cast<uint8_t>(header.total_chunks >> (i * 8)));
    }

    payload.insert(payload.end(), header.sender_id.begin(), header.sender_id.end());
    payload.insert(payload.end(), header.kem_ciphertext.begin(), header.kem_ciphertext.end());
    payload.insert(payload.end(), header.nonce.begin(), header.nonce.end());

    return payload;
}

void TransferEngine::upload_file(const std::string& filepath,
                                 const std::string& server_addr,
                                 uint16_t server_port) {
    cancel_flag_ = false;

    if (on_status) on_status("Loading keys...");

    CryptoEngine crypto;
    KeyStore keystore;

    auto pub_kem = keystore.load_public_kem();
    auto priv_dsa = keystore.load_private_dsa();
    auto pub_dsa = keystore.load_public_dsa();

    if (pub_kem.empty() || priv_dsa.empty()) {
        if (on_error) on_error("No keys found — restart the app to generate them");
        return;
    }

    if (on_status) on_status("Performing key exchange...");

    auto encap_result = crypto.encapsulate(pub_kem);

    if (on_status) on_status("Deriving encryption key...");

    auto aes_key = crypto.generate_aes_key(encap_result.shared_secret);

    std::vector<uint8_t> base_nonce(12);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dist(0, 255);
    for (auto& b : base_nonce) {
        b = static_cast<uint8_t>(dist(gen));
    }

    if (!fs::exists(filepath)) {
        if (on_error) on_error("File not found: " + filepath);
        return;
    }

    uint64_t file_size = fs::file_size(filepath);
    std::string filename = fs::path(filepath).filename().string();
    constexpr uint32_t chunk_size = 65536;
    uint32_t total_chunks = static_cast<uint32_t>((file_size + chunk_size - 1) / chunk_size);
    if (file_size == 0) total_chunks = 1;

    std::string sender_id;
    for (size_t i = 0; i < 8 && i < pub_dsa.size(); i++) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", pub_dsa[i]);
        sender_id += hex;
    }

    FileHeader header;
    header.filename = filename;
    header.file_size = file_size;
    header.chunk_size = chunk_size;
    header.total_chunks = total_chunks;
    header.sender_id = sender_id;
    header.kem_ciphertext = encap_result.ciphertext;
    header.nonce = base_nonce;
    header.encrypted = true;

    if (on_status) on_status("Signing file header...");

    auto signing_payload = build_signing_payload(header);
    header.signature = crypto.sign(signing_payload, priv_dsa);

    if (on_status) on_status("Connecting to server...");

    int sockfd = connect_to_server(server_addr, server_port);
    if (sockfd < 0) {
        if (on_error) on_error("Failed to connect to server");
        return;
    }

    if (on_status) on_status("Sending file header...");

    auto header_payload = serialize_file_header(header);
    if (!send_message(sockfd, MessageType::UPLOAD_REQUEST, header_payload)) {
        if (on_error) on_error("Failed to send file header");
        close(sockfd);
        return;
    }

    auto ack = recv_message(sockfd);
    if (!ack || ack->type != MessageType::ACK) {
        if (on_error) on_error("Server rejected upload");
        close(sockfd);
        return;
    }

    std::string transfer_id(ack->payload.begin(), ack->payload.end());
    if (on_transfer_id) on_transfer_id(transfer_id);

    if (on_status) on_status("Encrypting and uploading " + filename + "...");

    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        if (on_error) on_error("Failed to open file");
        close(sockfd);
        return;
    }

    std::vector<uint8_t> buffer(chunk_size);
    uint64_t bytes_sent = 0;

    for (uint32_t i = 0; i < total_chunks; i++) {
        if (cancel_flag_) {
            if (on_error) on_error("Transfer cancelled");
            file.close();
            close(sockfd);
            return;
        }

        file.read(reinterpret_cast<char*>(buffer.data()), chunk_size);
        std::streamsize bytes_read = file.gcount();

        auto chunk_nonce = compute_chunk_nonce(base_nonce, i);

        auto encrypted = crypto.encrypt_chunk(
            aes_key,
            std::vector<uint8_t>(buffer.begin(), buffer.begin() + bytes_read),
            chunk_nonce
        );

        FileChunk chunk;
        chunk.chunk_index = i;
        chunk.data = std::move(encrypted);

        auto chunk_payload = serialize_file_chunk(chunk);
        if (!send_message(sockfd, MessageType::UPLOAD_CHUNK, chunk_payload)) {
            if (on_error) on_error("Failed to send chunk " + std::to_string(i));
            file.close();
            close(sockfd);
            return;
        }

        bytes_sent += bytes_read;
        double progress = static_cast<double>(bytes_sent) / static_cast<double>(file_size);
        if (on_progress) on_progress(progress);
    }

    file.close();

    if (!send_message(sockfd, MessageType::UPLOAD_DONE, {})) {
        if (on_error) on_error("Failed to finalize upload");
        close(sockfd);
        return;
    }

    auto final_ack = recv_message(sockfd);
    if (final_ack && final_ack->type == MessageType::ACK) {
        std::string msg(final_ack->payload.begin(), final_ack->payload.end());
        if (on_status) on_status("Upload complete: " + msg);
    }

    if (on_progress) on_progress(1.0);
    if (on_complete) on_complete(filepath);

    close(sockfd);
}

void TransferEngine::download_file(const std::string& transfer_id,
                                   const std::string& server_addr,
                                   uint16_t server_port,
                                   const std::string& output_dir) {
    cancel_flag_ = false;

    if (on_status) on_status("Connecting to server...");

    int sockfd = connect_to_server(server_addr, server_port);
    if (sockfd < 0) {
        if (on_error) on_error("Failed to connect to server");
        return;
    }

    std::vector<uint8_t> id_payload(transfer_id.begin(), transfer_id.end());
    if (!send_message(sockfd, MessageType::DOWNLOAD_REQUEST, id_payload)) {
        if (on_error) on_error("Failed to send download request");
        close(sockfd);
        return;
    }

    if (on_status) on_status("Receiving file header...");

    auto header_msg = recv_message(sockfd);
    if (!header_msg || header_msg->type != MessageType::UPLOAD_REQUEST) {
        if (on_error) on_error("Server did not send file header");
        close(sockfd);
        return;
    }

    auto header = deserialize_file_header(header_msg->payload.data(), header_msg->payload.size());
    if (!header) {
        if (on_error) on_error("Malformed file header from server");
        close(sockfd);
        return;
    }

    std::optional<std::vector<uint8_t>> aes_key;

    if (header->encrypted) {
        if (on_status) on_status("Decrypting — performing key exchange...");

        CryptoEngine crypto;
        KeyStore keystore;

        auto priv_kem = keystore.load_private_kem();
        auto pub_dsa = keystore.load_public_dsa();

        if (priv_kem.empty()) {
            if (on_error) on_error("No private KEM key found");
            close(sockfd);
            return;
        }

        auto shared_secret = crypto.decapsulate(header->kem_ciphertext, priv_kem);

        aes_key = crypto.generate_aes_key(shared_secret);

        if (on_status) on_status("Verifying signature...");

        auto signing_payload = build_signing_payload(*header);
        bool valid = crypto.verify(signing_payload, header->signature, pub_dsa);

        if (!valid) {
            if (on_error) on_error("Signature verification FAILED — file may be tampered or from unknown sender");
            close(sockfd);
            return;
        }

        if (on_status) on_status("Signature verified ✓  Downloading...");
    } else {
        if (on_status) on_status("Downloading (unencrypted)...");
    }

    fs::create_directories(output_dir);
    std::string output_path = (fs::path(output_dir) / header->filename).string();

    std::ofstream file(output_path, std::ios::binary);
    if (!file.is_open()) {
        if (on_error) on_error("Failed to create output file: " + output_path);
        close(sockfd);
        return;
    }

    uint64_t bytes_received = 0;
    while (true) {
        auto msg = recv_message(sockfd);
        if (!msg) {
            if (on_error) on_error("Connection lost during download");
            file.close();
            close(sockfd);
            return;
        }

        if (msg->type == MessageType::DOWNLOAD_DONE) {
            break;
        }

        if (msg->type != MessageType::DOWNLOAD_CHUNK) {
            continue;
        }

        auto chunk = deserialize_file_chunk(msg->payload.data(), msg->payload.size());
        if (!chunk) continue;

        std::vector<uint8_t> write_data;

        if (aes_key.has_value()) {
            CryptoEngine crypto;
            auto chunk_nonce = compute_chunk_nonce(header->nonce, chunk->chunk_index);
            write_data = crypto.decrypt_chunk(*aes_key, chunk->data, chunk_nonce);
        } else {
            write_data = std::move(chunk->data);
        }

        file.write(reinterpret_cast<const char*>(write_data.data()), write_data.size());
        bytes_received += write_data.size();

        double progress = static_cast<double>(bytes_received) / static_cast<double>(header->file_size);
        if (on_progress) on_progress(progress);

        if (cancel_flag_) {
            if (on_error) on_error("Transfer cancelled");
            file.close();
            fs::remove(output_path);
            close(sockfd);
            return;
        }
    }

    file.close();

    if (on_progress) on_progress(1.0);
    if (on_status) on_status("Download complete: " + output_path);
    if (on_complete) on_complete(output_path);

    close(sockfd);
}