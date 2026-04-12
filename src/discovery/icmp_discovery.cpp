#include "network_scanner/discovery/icmp_discovery.h"

#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>

#include <array>
#include <cstddef>
#include <cstring>
#include <stdexcept>

namespace network_scanner {

IcmpDiscovery::IcmpDiscovery() : handle_(IcmpCreateFile()) {
    if (handle_ == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("No se pudo abrir el manejador ICMP.");
    }
}

IcmpDiscovery::~IcmpDiscovery() {
    if (handle_ != INVALID_HANDLE_VALUE) {
        IcmpCloseHandle(handle_);
    }
}

std::optional<unsigned long> IcmpDiscovery::probe(const std::string& ip, unsigned long timeoutMs) const {
    constexpr std::array<char, 32> payload{"network-scanner"};
    constexpr DWORD replySize = sizeof(ICMP_ECHO_REPLY) + 64;
    std::array<std::byte, replySize> replyBuffer{};

    const IPAddr destination = inet_addr(ip.c_str());
    if (destination == INADDR_NONE) {
        return std::nullopt;
    }

    const DWORD replyCount = IcmpSendEcho(
        handle_,
        destination,
        const_cast<char*>(payload.data()),
        static_cast<WORD>(std::strlen(payload.data())),
        nullptr,
        replyBuffer.data(),
        replySize,
        timeoutMs
    );

    if (replyCount == 0) {
        return std::nullopt;
    }

    const auto* reply = reinterpret_cast<const ICMP_ECHO_REPLY*>(replyBuffer.data());
    if (reply->Status != IP_SUCCESS) {
        return std::nullopt;
    }

    return reply->RoundTripTime;
}

}
