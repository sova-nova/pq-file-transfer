#include "transfer_engine.h"
#include "protocol.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <fstream>
#include <filesystem>
#include <cstring>
#include <thread>

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

void TransferEngine::upload_file(const std::string& filepath,
                                 const std::string& server_addr,
                                 uint16_t server_port) {
    cancel_flag_ = false;

    if (on_status) on_status("Connecting to server...");

    int sockfd = connect_to_server(server_addr, server_port);
    if (sockfd < 0) {
        if (on_error) on_error("Failed to connect to server");
        return;
    }

    // Get file info
    if (!fs::exists(filepath)) {
        if (on_error) on_error("File not found: " + filepath);
        close(sockfd);
        return;
    }

    uint64_t file_size = fs::file_size(filepath);
    std::string filename = fs::path(filepath).filename().string();
    constexpr uint32_t chunk_size = 65536;
    uint32_t total_chunks = static_cast<uint32_t>((file_size + chunk_size - 1) / chunk_size);
    if (file_size == 0) total_chunks = 1;

    // Build header
    FileHeader header;
    header.filename = filename;
    header.file_size = file_size;
    header.chunk_size = chunk_size;
    header.total_chunks = total_chunks;
    header.sender_id = "anonymous";  // Will be replaced with real ID in Phase 6

    if (on_status) on_status("Sending file header...");

    // Send UPLOAD_REQUEST
    auto header_payload = serialize_file_header(header);
    if (!send_message(sockfd, MessageType::UPLOAD_REQUEST, header_payload)) {
        if (on_error) on_error("Failed to send file header");
        close(sockfd);
        return;
    }

    // Wait for ACK (contains transfer_id)
    auto ack = recv_message(sockfd);
    if (!ack || ack->type != MessageType::ACK) {
        if (on_error) on_error("Server rejected upload");
        close(sockfd);
        return;
    }

    std::string transfer_id(ack->payload.begin(), ack->payload.end());
    if (on_transfer_id) on_transfer_id(transfer_id);

    if (on_status) on_status("Uploading " + filename + "...");

    // Send chunks
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

        FileChunk chunk;
        chunk.chunk_index = i;
        chunk.data.assign(buffer.begin(), buffer.begin() + bytes_read);

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

    // Send UPLOAD_DONE
    if (!send_message(sockfd, MessageType::UPLOAD_DONE, {})) {
        if (on_error) on_error("Failed to finalize upload");
        close(sockfd);
        return;
    }

    // Wait for final ACK
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

    // Send DOWNLOAD_REQUEST with transfer_id
    std::vector<uint8_t> id_payload(transfer_id.begin(), transfer_id.end());
    if (!send_message(sockfd, MessageType::DOWNLOAD_REQUEST, id_payload)) {
        if (on_error) on_error("Failed to send download request");
        close(sockfd);
        return;
    }

    if (on_status) on_status("Waiting for file header...");

    // Receive file header
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

    // Create output directory
    fs::create_directories(output_dir);
    std::string output_path = (fs::path(output_dir) / header->filename).string();

    if (on_status) on_status("Downloading " + header->filename + "...");

    // Open output file
    std::ofstream file(output_path, std::ios::binary);
    if (!file.is_open()) {
        if (on_error) on_error("Failed to create output file: " + output_path);
        close(sockfd);
        return;
    }

    // Receive chunks
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
        if (!chunk) {
            continue;  // skip malformed
        }

        file.write(reinterpret_cast<const char*>(chunk->data.data()), chunk->data.size());
        bytes_received += chunk->data.size();

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