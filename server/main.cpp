#include <iostream>
#include <csignal>
#include <thread>
#include <mutex>
#include <map>
#include <fstream>
#include <filesystem>
#include <random>
#include <cstring>

#include "protocol.h"
#include "platform.h"

namespace fs = std::filesystem;

// --- Server State ---

struct TransferState {
    std::string transfer_id;
    FileHeader header;
    std::string dir_path;
    uint32_t chunks_received = 0;
    bool complete = false;
};

static std::map<std::string, TransferState> g_transfers;
static std::mutex g_mutex;
static const std::string STORAGE_DIR = "/tmp/pq-transfer";

// --- Helpers ---

std::string generate_transfer_id() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFFFF);

    uint32_t val = dist(gen);
    char buf[9];
    std::snprintf(buf, sizeof(buf), "%08x", val);
    return std::string(buf);
}

void send_ack(int sockfd, const std::string& message = "") {
    std::vector<uint8_t> payload(message.begin(), message.end());
    send_message(sockfd, MessageType::ACK, payload);
}

bool send_error_and_close(int sockfd, const std::string& error_msg) {
    std::cerr << "Error: " << error_msg << std::endl;
    send_ack(sockfd, "ERROR: " + error_msg);
    close_socket(sockfd);
    return false;
}

std::string chunk_filename(uint32_t index) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "chunk_%06u.bin", index);
    return std::string(buf);
}

// --- Client Handler ---

void handle_client(socket_t sockfd) {
    uint8_t len_buf[4];
    if (!recv_exact(sockfd, len_buf, 4)) { close_socket(sockfd); return; }

    uint32_t net_len;
    std::memcpy(&net_len, len_buf, 4);
    uint32_t payload_len = ntohl(net_len);

    if (payload_len > 256 * 1024 * 1024) { close_socket(sockfd); return; }

    uint8_t type_byte;
    if (!recv_exact(sockfd, &type_byte, 1)) { close_socket(sockfd); return; }

    MessageType type = static_cast<MessageType>(type_byte);

    std::vector<uint8_t> payload(payload_len);
    if (payload_len > 0) {
        if (!recv_exact(sockfd, payload.data(), payload_len)) { close_socket(sockfd); return; }
    }

    if (type == MessageType::UPLOAD_REQUEST) {
        auto header = deserialize_file_header(payload.data(), payload.size());
        if (!header) {
            send_error_and_close(sockfd, "Malformed FileHeader");
            return;
        }

        std::string transfer_id = generate_transfer_id();
        std::string dir_path = (fs::path(STORAGE_DIR) / transfer_id).string();
        fs::create_directories(dir_path);

        auto header_bytes = serialize_file_header(*header);
        std::ofstream(dir_path + "/header.bin", std::ios::binary)
            .write(reinterpret_cast<const char*>(header_bytes.data()), header_bytes.size());

        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_transfers[transfer_id] = TransferState{transfer_id, *header, dir_path, 0, false};
        }

        std::cout << "Upload started: " << header->filename
                  << " (" << header->file_size << " bytes)"
                  << " -> ID: " << transfer_id << std::endl;

        send_ack(sockfd, transfer_id);

        uint32_t chunks_received = 0;
        while (true) {
            auto chunk_msg = recv_message(sockfd);
            if (!chunk_msg) {
                std::cerr << "Sender disconnected: " << transfer_id << std::endl;
                fs::remove_all(dir_path);
                std::lock_guard<std::mutex> lock(g_mutex);
                g_transfers.erase(transfer_id);
                return;
            }

            if (chunk_msg->type == MessageType::UPLOAD_DONE) {
                break;
            }

            if (chunk_msg->type != MessageType::UPLOAD_CHUNK) {
                continue;
            }

            auto chunk = deserialize_file_chunk(chunk_msg->payload.data(), chunk_msg->payload.size());
            if (!chunk) continue;

            std::string chunk_path = dir_path + "/" + chunk_filename(chunk->chunk_index);
            std::ofstream cf(chunk_path, std::ios::binary);
            if (cf.is_open()) {
                cf.write(reinterpret_cast<const char*>(chunk->data.data()), chunk->data.size());
                cf.close();
            }

            chunks_received++;
        }

        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_transfers[transfer_id].chunks_received = chunks_received;
            g_transfers[transfer_id].complete = true;
        }

        std::cout << "Upload complete: " << transfer_id
                  << " (" << chunks_received << " chunks)" << std::endl;

        send_ack(sockfd, "UPLOAD_COMPLETE");
        close_socket(sockfd);

    } else if (type == MessageType::LIST_FILES || type == MessageType::DOWNLOAD_REQUEST) {
        if (type == MessageType::LIST_FILES) {
            std::vector<TransferInfo> files;
            {
                std::lock_guard<std::mutex> lock(g_mutex);
                for (const auto& [id, state] : g_transfers) {
                    if (state.complete) {
                        files.push_back(TransferInfo{
                            id, state.header.filename,
                            state.header.file_size, state.header.sender_id
                        });
                    }
                }
            }

            auto file_list_payload = serialize_file_list(files);
            send_message(sockfd, MessageType::FILE_LIST, file_list_payload);
            std::cout << "Sent file list: " << files.size() << " files" << std::endl;
            close_socket(sockfd);

        } else {
            std::string transfer_id(payload.begin(), payload.end());

            TransferState state;
            {
                std::lock_guard<std::mutex> lock(g_mutex);
                auto it = g_transfers.find(transfer_id);
                if (it == g_transfers.end() || !it->second.complete) {
                    send_error_and_close(sockfd, "Transfer not found or not complete");
                    return;
                }
                state = it->second;
            }

            std::cout << "Download started: " << transfer_id << std::endl;

            std::ifstream hf(state.dir_path + "/header.bin", std::ios::binary | std::ios::ate);
            if (!hf.is_open()) {
                send_error_and_close(sockfd, "Header file missing");
                return;
            }
            auto hsize = hf.tellg();
            hf.seekg(0);
            std::vector<uint8_t> header_bytes(hsize);
            hf.read(reinterpret_cast<char*>(header_bytes.data()), hsize);
            hf.close();

            send_message(sockfd, MessageType::UPLOAD_REQUEST, header_bytes);

            for (uint32_t i = 0; i < state.header.total_chunks; i++) {
                std::string chunk_path = state.dir_path + "/" + chunk_filename(i);

                std::ifstream cf(chunk_path, std::ios::binary | std::ios::ate);
                if (!cf.is_open()) {
                    std::cerr << "Chunk file missing: " << chunk_path << std::endl;
                    break;
                }

                auto csize = cf.tellg();
                cf.seekg(0);
                std::vector<uint8_t> chunk_data(csize);
                cf.read(reinterpret_cast<char*>(chunk_data.data()), csize);
                cf.close();

                FileChunk chunk;
                chunk.chunk_index = i;
                chunk.data = std::move(chunk_data);

                auto chunk_payload = serialize_file_chunk(chunk);
                if (!send_message(sockfd, MessageType::DOWNLOAD_CHUNK, chunk_payload)) {
                    std::cerr << "Receiver disconnected: " << transfer_id << std::endl;
                    close_socket(sockfd);
                    return;
                }
            }

            send_message(sockfd, MessageType::DOWNLOAD_DONE, {});

            std::cout << "Download complete: " << transfer_id << std::endl;

            {
                std::lock_guard<std::mutex> lock(g_mutex);
                g_transfers.erase(transfer_id);
            }
            fs::remove_all(state.dir_path);
            std::cout << "Cleaned up: " << transfer_id << std::endl;

            close_socket(sockfd);
        }

    } else {
        send_error_and_close(sockfd, "Unexpected first message type");
    }
}

// --- Main ---

static constexpr int PORT = 9000;
static constexpr int BACKLOG = 5;

int main() {
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif

    if (platform_init() != 0) {
        std::cerr << "Failed to initialize network" << std::endl;
        return 1;
    }

    fs::create_directories(STORAGE_DIR);
    std::cout << "Storage directory: " << STORAGE_DIR << std::endl;

    socket_t server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == INVALID_SOCKET_VAL) {
        std::cerr << "Failed to create socket" << std::endl;
        platform_cleanup();
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(server_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR_VAL) {
        std::cerr << "Failed to bind to port " << PORT << std::endl;
        close_socket(server_fd);
        platform_cleanup();
        return 1;
    }

    if (listen(server_fd, BACKLOG) == SOCKET_ERROR_VAL) {
        std::cerr << "Failed to listen" << std::endl;
        close_socket(server_fd);
        platform_cleanup();
        return 1;
    }

    std::cout << "PQ Relay Server listening on port " << PORT << std::endl;
    std::cout << "Press Ctrl+C to stop." << std::endl;

    while (true) {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        socket_t client_fd = accept(server_fd, reinterpret_cast<sockaddr*>(&client_addr), &client_len);

        if (client_fd == INVALID_SOCKET_VAL) {
            std::cerr << "Failed to accept connection" << std::endl;
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        std::cout << "Connection from " << client_ip << ":"
                  << ntohs(client_addr.sin_port) << std::endl;

        std::thread(handle_client, client_fd).detach();
    }

    close_socket(server_fd);
    platform_cleanup();
    return 0;
}