#pragma once

#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstdint>
#include <string>
#include <stdexcept>

namespace network_scanner {

inline std::uint32_t parseIpv4(const std::string& ip) {
    IN_ADDR address{};
    if (InetPtonA(AF_INET, ip.c_str(), &address) != 1) {
        throw std::runtime_error("IPv4 inválida: " + ip);
    }

    return ntohl(address.S_un.S_addr);
}

inline std::string toIpv4String(std::uint32_t hostOrderIp) {
    IN_ADDR address{};
    address.S_un.S_addr = htonl(hostOrderIp);

    char buffer[INET_ADDRSTRLEN]{};
    if (InetNtopA(AF_INET, &address, buffer, static_cast<DWORD>(sizeof(buffer))) == nullptr) {
        throw std::runtime_error("No se pudo convertir la IP a texto.");
    }

    return std::string(buffer);
}

}
