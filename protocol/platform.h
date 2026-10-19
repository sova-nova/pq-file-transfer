#pragma once

#include <cerrno>
#include <string>

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
    #include <sys/select.h>
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

// True if the socket has data to read (or has been closed) within `millis` milliseconds.
inline bool wait_readable(socket_t s, int millis) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    timeval tv;
    tv.tv_sec = millis / 1000;
    tv.tv_usec = (millis % 1000) * 1000;
    return select(static_cast<int>(s) + 1, &fds, nullptr, nullptr, &tv) > 0;
}

// The error code of the last failed socket call on this thread.
inline int last_socket_error() {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

// Why a connection attempt failed, in words, and what to check. `what` is "relay" or "server".
// `err` is last_socket_error() right after the failed connect(), or 0 if unknown.
inline std::string describe_connect_failure(const std::string& what, const std::string& address, int err) {
#ifdef _WIN32
    const bool refused = err == WSAECONNREFUSED;
    const bool silent = err == WSAETIMEDOUT || err == WSAEHOSTUNREACH || err == WSAENETUNREACH || err == WSAENETDOWN;
#else
    const bool refused = err == ECONNREFUSED;
    const bool silent = err == ETIMEDOUT || err == EHOSTUNREACH || err == ENETUNREACH || err == ENETDOWN;
#endif
    std::string head = "Could not connect to the " + what + " at " + address;
    if (refused)
        return head + ": nothing is listening there (connection refused). Is the " + what +
               " running? Check the address and port, and that the " + what + " is set to listen on an address you can reach.";
    if (silent)
        return head + ": no answer. Check the address, that you are on the right network or VPN, and that a firewall isn't blocking the port.";
    return head + ". Check that the " + what + " is running, that the address and port are right, that you are on the right network or VPN, and that a firewall isn't blocking the port.";
}
