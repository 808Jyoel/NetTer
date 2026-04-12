#include "network_scanner/ports/tcp_port_scanner.h"

#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>

#include <chrono>
#include <vector>

namespace network_scanner {

namespace {

struct SocketHandle {
    SOCKET socket{INVALID_SOCKET};

    explicit SocketHandle(const SOCKET value) : socket(value) {}

    ~SocketHandle() {
        if (socket != INVALID_SOCKET) {
            closesocket(socket);
        }
    }
};

PortState mapSocketErrorToState(const int errorCode) {
    if (errorCode == 0) {
        return PortState::Open;
    }

    if (errorCode == WSAECONNREFUSED || errorCode == WSAECONNRESET || errorCode == WSAENETUNREACH || errorCode == WSAEHOSTUNREACH) {
        return PortState::Closed;
    }

    if (errorCode == WSAETIMEDOUT) {
        return PortState::Filtered;
    }

    return PortState::Error;
}

}

PortResult TcpPortScanner::probe(const std::string& ip, const std::uint16_t port, const unsigned long timeoutMs) const {
    PortResult result{
        .port = port,
        .state = PortState::Error,
        .latencyMs = std::nullopt,
        .errorCode = 0
    };

    SocketHandle client(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    if (client.socket == INVALID_SOCKET) {
        result.errorCode = WSAGetLastError();
        return result;
    }

    u_long mode = 1;
    if (ioctlsocket(client.socket, FIONBIO, &mode) != 0) {
        result.errorCode = WSAGetLastError();
        return result;
    }

    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_port = htons(port);

    if (InetPtonA(AF_INET, ip.c_str(), &target.sin_addr) != 1) {
        result.errorCode = WSAGetLastError();
        return result;
    }

    const auto startedAt = std::chrono::steady_clock::now();
    const int connectResult = connect(client.socket, reinterpret_cast<sockaddr*>(&target), sizeof(target));
    if (connectResult == 0) {
        const auto endedAt = std::chrono::steady_clock::now();
        result.state = PortState::Open;
        result.latencyMs = static_cast<unsigned long>(std::chrono::duration_cast<std::chrono::milliseconds>(endedAt - startedAt).count());
        return result;
    }

    const int connectError = WSAGetLastError();
    if (connectError != WSAEWOULDBLOCK && connectError != WSAEINPROGRESS && connectError != WSAEINVAL) {
        result.errorCode = connectError;
        result.state = mapSocketErrorToState(connectError);
        return result;
    }

    fd_set writeSet;
    FD_ZERO(&writeSet);
    FD_SET(client.socket, &writeSet);

    fd_set errorSet;
    FD_ZERO(&errorSet);
    FD_SET(client.socket, &errorSet);

    timeval timeout{};
    timeout.tv_sec = static_cast<long>(timeoutMs / 1000);
    timeout.tv_usec = static_cast<long>((timeoutMs % 1000) * 1000);

    const int selectResult = select(0, nullptr, &writeSet, &errorSet, &timeout);
    if (selectResult == 0) {
        result.state = PortState::Filtered;
        result.errorCode = WSAETIMEDOUT;
        return result;
    }

    if (selectResult < 0) {
        result.errorCode = WSAGetLastError();
        result.state = mapSocketErrorToState(result.errorCode);
        return result;
    }

    int socketError = 0;
    int socketErrorLength = sizeof(socketError);
    if (getsockopt(client.socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&socketError), &socketErrorLength) != 0) {
        result.errorCode = WSAGetLastError();
        result.state = mapSocketErrorToState(result.errorCode);
        return result;
    }

    result.errorCode = socketError;
    result.state = mapSocketErrorToState(socketError);
    if (result.state == PortState::Open) {
        const auto endedAt = std::chrono::steady_clock::now();
        result.latencyMs = static_cast<unsigned long>(std::chrono::duration_cast<std::chrono::milliseconds>(endedAt - startedAt).count());
    }

    return result;
}

std::vector<PortResult> TcpPortScanner::scan(
    const std::string& ip,
    const std::vector<std::uint16_t>& ports,
    const unsigned long timeoutMs
) const {
    std::vector<PortResult> results;
    results.reserve(ports.size());

    for (const std::uint16_t port : ports) {
        results.push_back(probe(ip, port, timeoutMs));
    }

    return results;
}

}
