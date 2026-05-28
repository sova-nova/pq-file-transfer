#include <iostream>
#include <csignal>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <mutex>
#include <map>
#include <fstream>
#include <filesystem>
#include <random>
#include <chrono>
#include <cstring>

#include "protocol.h"

namespace fs = std::filesystem;

// --- Server State ---

struct TransferState {
    std::string transfer_id;
    FileHeader header;
    std::string filepath;
    uint64_t bytes_received = 0;
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
    close(sockfd);
    return false;
}

// --- Client Handler ---

void handle_sender(int sockfd) {
    // 1. Wait for UPLOAD_REQUEST
    auto msg = recv_message(sockfd);
    if (!msg || msg->type != MessageType::UPLOAD_REQUEST) {
        send_error_and_close(sockfd, "Expected UPLOAD_REQUEST");
        return;
    }

    auto header = deserialize_file_header(msg->payload.data(), msg->payload.size());
    if (!header) {
        send_error_and_close(sockfd, "Malformed FileHeader");
        return;
    }

    // 2. Create transfer
    std::string transfer_id = generate_transfer_id();
    std::string filepath = (fs::path(STORAGE_DIR) / transfer_id).string();

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_transfers[transfer_id] = TransferState{
            transfer_id,
            *header,
            filepath,
            0,
            false
        };
    }

    std::cout << "Upload started: " << header->filename
              << " (" << header->file_size << " bytes)"
              << " -> ID: " << transfer_id << std::endl;

    // 3. Send ACK with transfer_id so sender knows it was accepted
    send_ack(sockfd, transfer_id);

    // 4. Receive chunks
    std::ofstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        send_error_and_close(sockfd, "Failed to create file on server");
        return;
    }

    uint64_t total_received = 0;
    while (true) {
        auto chunk_msg = recv_message(sockfd);
        if (!chunk_msg) {
            // Connection lost
            std::cerr << "Sender disconnected during upload: " << transfer_id << std::endl;
            file.close();
            fs::remove(filepath);
            std::lock_guard<std::mutex> lock(g_mutex);
            g_transfers.erase(transfer_id);
            return;
        }

        if (chunk_msg->type == MessageType::UPLOAD_DONE) {
            break;
        }

        if (chunk_msg->type != MessageType::UPLOAD_CHUNK) {
            continue; // ignore unexpected messages
        }

        auto chunk = deserialize_file_chunk(chunk_msg->payload.data(), chunk_msg->payload.size());
        if (!chunk) {
            continue; // skip malformed chunk
        }

        file.write(reinterpret_cast<const char*>(chunk->data.data()), chunk->data.size());
        total_received += chunk->data.size();
    }

    file.close();

    // 5. Mark transfer as complete
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_transfers[transfer_id].bytes_received = total_received;
        g_transfers[transfer_id].complete = true;
    }

    std::cout << "Upload complete: " << transfer_id
              << " (" << total_received << " bytes received)" << std::endl;

    send_ack(sockfd, "UPLOAD_COMPLETE");
    close(sockfd);
}

void handle_receiver(int sockfd) {
    // 1. Wait for a message: either LIST_FILES or DOWNLOAD_REQUEST
    auto msg = recv_message(sockfd);
    if (!msg) {
        close(sockfd);
        return;
    }

    if (msg->type == MessageType::LIST_FILES) {
        // Send back all complete transfers
        std::vector<TransferInfo> files;

        {
            std::lock_guard<std::mutex> lock(g_mutex);
            for (const auto& [id, state] : g_transfers) {
                if (state.complete) {
                    files.push_back(TransferInfo{
                        state.transfer_id,
                        state.header.filename,
                        state.header.file_size,
                        state.header.sender_id
                    });
                }
            }
        }

        auto payload = serialize_file_list(files);
        send_message(sockfd, MessageType::FILE_LIST, payload);
        std::cout << "Sent file list: " << files.size() << " files" << std::endl;
        close(sockfd);
        return;
    }

    if (msg->type == MessageType::DOWNLOAD_REQUEST) {
        // Payload is the transfer_id as a string
        std::string transfer_id(msg->payload.begin(), msg->payload.end());

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

        std::cout << "Download started: " << transfer_id
                  << " -> " << state.header.filename << std::endl;

        // 2. Send the file header so receiver knows what to expect
        auto header_payload = serialize_file_header(state.header);
        send_message(sockfd, MessageType::UPLOAD_REQUEST, header_payload);

        // 3. Stream file in chunks
        std::ifstream file(state.filepath, std::ios::binary);
        if (!file.is_open()) {
            send_error_and_close(sockfd, "Failed to open file on server");
            return;
        }

        uint32_t chunk_size = state.header.chunk_size;
        std::vector<uint8_t> buffer(chunk_size);
        uint32_t chunk_index = 0;

        while (true) {
            file.read(reinterpret_cast<char*>(buffer.data()), chunk_size);
            std::streamsize bytes_read = file.gcount();

            if (bytes_read <= 0) break;

            FileChunk chunk;
            chunk.chunk_index = chunk_index;
            chunk.data.assign(buffer.begin(), buffer.begin() + bytes_read);

            auto chunk_payload = serialize_file_chunk(chunk);
            if (!send_message(sockfd, MessageType::DOWNLOAD_CHUNK, chunk_payload)) {
                std::cerr << "Receiver disconnected during download: " << transfer_id << std::endl;
                file.close();
                close(sockfd);
                return;
            }

            chunk_index++;
        }

        file.close();

        // 4. Send DOWNLOAD_DONE
        send_message(sockfd, MessageType::DOWNLOAD_DONE, {});

        std::cout << "Download complete: " << transfer_id << std::endl;

        // 5. Delete the file and remove from state
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_transfers.erase(transfer_id);
        }
        fs::remove(state.filepath);
        std::cout << "Cleaned up transfer: " << transfer_id << std::endl;

        close(sockfd);
        return;
    }

    send_error_and_close(sockfd, "Expected LIST_FILES or DOWNLOAD_REQUEST");
}

void handle_client(int sockfd) {
    // The first message determines if this is a sender or receiver.
    // But we can't peek easily with our protocol, so let's use a simple approach:
    // We'll expect the client to send a specific first message.
    // Actually, let's just use a convention:
    //   - Senders start with UPLOAD_REQUEST
    //   - Receivers start with LIST_FILES or DOWNLOAD_REQUEST
    // We already handle this by reading the first message in each handler.
    // 
    // The problem: we need to know WHICH handler to call before reading.
    // Solution: Read the first message here, then dispatch.

    // Read the 4-byte length + 1-byte type
    uint8_t len_buf[4];
    if (!recv_exact(sockfd, len_buf, 4)) {
        close(sockfd);
        return;
    }

    uint32_t net_len;
    std::memcpy(&net_len, len_buf, 4);
    uint32_t payload_len = ntohl(net_len);

    if (payload_len > 256 * 1024 * 1024) {
        close(sockfd);
        return;
    }

    uint8_t type_byte;
    if (!recv_exact(sockfd, &type_byte, 1)) {
        close(sockfd);
        return;
    }

    MessageType type = static_cast<MessageType>(type_byte);

    std::vector<uint8_t> payload(payload_len);
    if (payload_len > 0) {
        if (!recv_exact(sockfd, payload.data(), payload_len)) {
            close(sockfd);
            return;
        }
    }

    // Now dispatch based on type
    if (type == MessageType::UPLOAD_REQUEST) {
        // We already consumed the first message, so we need to pass it along
        // to the sender handler. Let's restructure slightly.
        // Easiest approach: inline the logic here.

        // --- SENDER PATH ---
        auto header = deserialize_file_header(payload.data(), payload.size());
        if (!header) {
            send_error_and_close(sockfd, "Malformed FileHeader");
            return;
        }

        std::string transfer_id = generate_transfer_id();
        std::string filepath = (fs::path(STORAGE_DIR) / transfer_id).string();

        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_transfers[transfer_id] = TransferState{transfer_id, *header, filepath, 0, false};
        }

        std::cout << "Upload started: " << header->filename
                  << " (" << header->file_size << " bytes)"
                  << " -> ID: " << transfer_id << std::endl;

        send_ack(sockfd, transfer_id);

        std::ofstream file(filepath, std::ios::binary);
        if (!file.is_open()) {
            send_error_and_close(sockfd, "Failed to create file on server");
            return;
        }

        uint64_t total_received = 0;
        while (true) {
            auto chunk_msg = recv_message(sockfd);
            if (!chunk_msg) {
                std::cerr << "Sender disconnected: " << transfer_id << std::endl;
                file.close();
                fs::remove(filepath);
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

            file.write(reinterpret_cast<const char*>(chunk->data.data()), chunk->data.size());
            total_received += chunk->data.size();
        }

        file.close();

        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_transfers[transfer_id].bytes_received = total_received;
            g_transfers[transfer_id].complete = true;
        }

        std::cout << "Upload complete: " << transfer_id
                  << " (" << total_received << " bytes)" << std::endl;

        send_ack(sockfd, "UPLOAD_COMPLETE");
        close(sockfd);

    } else if (type == MessageType::LIST_FILES || type == MessageType::DOWNLOAD_REQUEST) {
        // --- RECEIVER PATH ---
        if (type == MessageType::LIST_FILES) {
            std::vector<TransferInfo> files;
            {
                std::lock_guard<std::mutex> lock(g_mutex);
                for (const auto& [id, state] : g_transfers) {
                    if (state.complete) {
                        files.push_back(TransferInfo{id, state.header.filename, state.header.file_size, state.header.sender_id});
                    }
                }
            }

            auto file_list_payload = serialize_file_list(files);
            send_message(sockfd, MessageType::FILE_LIST, file_list_payload);
            std::cout << "Sent file list: " << files.size() << " files" << std::endl;
            close(sockfd);

        } else {
            // DOWNLOAD_REQUEST — payload is transfer_id string
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

            auto header_payload = serialize_file_header(state.header);
            send_message(sockfd, MessageType::UPLOAD_REQUEST, header_payload);

            std::ifstream file(state.filepath, std::ios::binary);
            if (!file.is_open()) {
                send_error_and_close(sockfd, "Failed to open file");
                return;
            }

            uint32_t chunk_size = state.header.chunk_size;
            std::vector<uint8_t> buffer(chunk_size);
            uint32_t chunk_index = 0;

            while (true) {
                file.read(reinterpret_cast<char*>(buffer.data()), chunk_size);
                std::streamsize bytes_read = file.gcount();
                if (bytes_read <= 0) break;

                FileChunk chunk;
                chunk.chunk_index = chunk_index;
                chunk.data.assign(buffer.begin(), buffer.begin() + bytes_read);

                auto chunk_payload = serialize_file_chunk(chunk);
                if (!send_message(sockfd, MessageType::DOWNLOAD_CHUNK, chunk_payload)) {
                    std::cerr << "Receiver disconnected: " << transfer_id << std::endl;
                    file.close();
                    close(sockfd);
                    return;
                }
                chunk_index++;
            }

            file.close();
            send_message(sockfd, MessageType::DOWNLOAD_DONE, {});

            std::cout << "Download complete: " << transfer_id << std::endl;

            {
                std::lock_guard<std::mutex> lock(g_mutex);
                g_transfers.erase(transfer_id);
            }
            fs::remove(state.filepath);
            std::cout << "Cleaned up: " << transfer_id << std::endl;

            close(sockfd);
        }

    } else {
        send_error_and_close(sockfd, "Unexpected first message type");
    }
}

// --- Main ---

static constexpr int PORT = 9000;
static constexpr int BACKLOG = 5;

int main() {
    signal(SIGPIPE, SIG_IGN);

    // Create storage directory
    fs::create_directories(STORAGE_DIR);
    std::cout << "Storage directory: " << STORAGE_DIR << std::endl;

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        std::cerr << "Failed to create socket" << std::endl;
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(server_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "Failed to bind to port " << PORT << std::endl;
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, BACKLOG) < 0) {
        std::cerr << "Failed to listen" << std::endl;
        close(server_fd);
        return 1;
    }

    std::cout << "PQ Relay Server listening on port " << PORT << std::endl;
    std::cout << "Press Ctrl+C to stop." << std::endl;

    while (true) {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, reinterpret_cast<sockaddr*>(&client_addr), &client_len);

        if (client_fd < 0) {
            std::cerr << "Failed to accept connection" << std::endl;
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        std::cout << "Connection from " << client_ip << ":"
                  << ntohs(client_addr.sin_port) << std::endl;

        // Spawn a thread for each client
        std::thread(handle_client, client_fd).detach();
    }

    close(server_fd);
    return 0;
}