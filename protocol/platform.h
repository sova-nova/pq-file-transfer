#pragma once

// Cross-platform socket abstraction.

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #ifndef NOMINMAX
        #define NOMINMAX
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #ifdef _MSC_VER
        #pragma comment(lib, "ws2_32.lib")
    #endif

    using socket_t = SOCKET;
    #define INVALID_SOCKET_VAL INVALID_SOCKET
    #define SOCKET_ERROR_VAL SOCKET_ERROR
    #define SEND_FLAGS 0
    #define SHUTDOWN_BOTH SD_BOTH

    inline void close_socket(socket_t s) { closesocket(s); }

    inline int platform_init() {
        WSADATA wsaData;
        return WSAStartup(MAKEWORD(2, 2), &wsaData);
    }

    inline void platform_cleanup() { WSACleanup(); }

    inline void set_socket_timeouts(socket_t s, int seconds) {
        DWORD ms = static_cast<DWORD>(seconds) * 1000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&ms), sizeof(ms));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&ms), sizeof(ms));
    }

    inline void disable_sigpipe(socket_t) {}

#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <sys/time.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <csignal>

    using socket_t = int;
    #define INVALID_SOCKET_VAL (-1)
    #define SOCKET_ERROR_VAL (-1)
    #define SHUTDOWN_BOTH SHUT_RDWR

    // macOS has no MSG_NOSIGNAL; it uses the SO_NOSIGPIPE socket option instead
    // (see disable_sigpipe), and platform_init ignores SIGPIPE process-wide.
    #ifdef MSG_NOSIGNAL
        #define SEND_FLAGS MSG_NOSIGNAL
    #else
        #define SEND_FLAGS 0
    #endif

    inline void close_socket(socket_t s) { close(s); }

    inline int platform_init() {
        std::signal(SIGPIPE, SIG_IGN);
        return 0;
    }

    inline void platform_cleanup() {}

    inline void set_socket_timeouts(socket_t s, int seconds) {
        timeval tv{};
        tv.tv_sec = seconds;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }

    inline void disable_sigpipe(socket_t s) {
    #ifdef SO_NOSIGPIPE
        int one = 1;
        setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
    #else
        (void)s;
    #endif
    }
#endif
