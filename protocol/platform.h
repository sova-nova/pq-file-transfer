#pragma once

// Cross-platform socket abstraction

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")

    using socket_t = SOCKET;
    #define INVALID_SOCKET_VAL INVALID_SOCKET
    #define SOCKET_ERROR_VAL SOCKET_ERROR

    inline void close_socket(socket_t s) { closesocket(s); }

    // Windows doesn't have MSG_NOSIGNAL — just pass 0
    #define SEND_FLAGS 0

    inline int platform_init() {
        WSADATA wsaData;
        return WSAStartup(MAKEWORD(2, 2), &wsaData);
    }

    inline void platform_cleanup() {
        WSACleanup();
    }

#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>

    using socket_t = int;
    #define INVALID_SOCKET_VAL (-1)
    #define SOCKET_ERROR_VAL (-1)

    inline void close_socket(socket_t s) { close(s); }

    #define SEND_FLAGS MSG_NOSIGNAL

    inline int platform_init() { return 0; }
    inline void platform_cleanup() {}
#endif