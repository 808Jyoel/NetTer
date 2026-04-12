#include "network_scanner/discovery/target_resolver.h"

#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include "core/ip_utils.h"

#include <cstddef>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace network_scanner {

namespace {

std::string trim(const std::string& value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return {};
    }

    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

bool isPrivateIpv4(std::uint32_t hostOrderIp) {
    const std::uint8_t first = static_cast<std::uint8_t>((hostOrderIp >> 24) & 0xFF);
    const std::uint8_t second = static_cast<std::uint8_t>((hostOrderIp >> 16) & 0xFF);

    if (first == 10) {
        return true;
    }

    if (first == 172 && second >= 16 && second <= 31) {
        return true;
    }

    return first == 192 && second == 168;
}

std::string toCidrString(std::uint32_t hostOrderIp, std::uint8_t prefixLength) {
    return toIpv4String(hostOrderIp) + "/" + std::to_string(static_cast<int>(prefixLength));
}

}

NetworkRange TargetResolver::parseCidr(const std::string& cidr) const {
    const auto slashPos = cidr.find('/');
    if (slashPos == std::string::npos) {
        throw std::runtime_error("CIDR inválido: " + cidr);
    }

    const std::string ipPart = trim(cidr.substr(0, slashPos));
    const std::string prefixPart = trim(cidr.substr(slashPos + 1));

    const int prefix = std::stoi(prefixPart);
    if (prefix < 0 || prefix > 32) {
        throw std::runtime_error("Prefijo fuera de rango: " + cidr);
    }

    const std::uint32_t ip = parseIpv4(ipPart);
    const std::uint32_t mask = prefix == 0 ? 0u : std::numeric_limits<std::uint32_t>::max() << (32 - prefix);
    const std::uint32_t network = ip & mask;
    const std::uint32_t broadcast = network | ~mask;

    return NetworkRange{
        .network = network,
        .broadcast = broadcast,
        .prefixLength = static_cast<std::uint8_t>(prefix)
    };
}

std::string TargetResolver::normalizeCidr(const std::string& cidr) const {
    const NetworkRange range = parseCidr(trim(cidr));
    return toCidrString(range.network, range.prefixLength);
}

std::vector<std::string> TargetResolver::enumerateTargets(const NetworkRange& range) const {
    std::vector<std::string> targets;

    std::uint32_t start = range.network;
    std::uint32_t finish = range.broadcast;

    if (range.prefixLength <= 30 && finish > start + 1) {
        start += 1;
        finish -= 1;
    }

    targets.reserve(finish >= start ? static_cast<std::size_t>(finish - start + 1) : 0);

    for (std::uint32_t value = start; value <= finish; ++value) {
        targets.push_back(toIpv4String(value));
        if (value == std::numeric_limits<std::uint32_t>::max()) {
            break;
        }
    }

    return targets;
}

std::string TargetResolver::resolveDefaultCidr() const {
    ULONG bufferSize = 0;
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    constexpr ULONG family = AF_INET;

    GetAdaptersAddresses(family, flags, nullptr, nullptr, &bufferSize);
    std::vector<std::byte> buffer(bufferSize);

    auto* addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
    const ULONG result = GetAdaptersAddresses(family, flags, nullptr, addresses, &bufferSize);
    if (result != NO_ERROR) {
        throw std::runtime_error("No se pudieron enumerar las interfaces de red.");
    }

    for (auto* adapter = addresses; adapter != nullptr; adapter = adapter->Next) {
        if (adapter->OperStatus != IfOperStatusUp) {
            continue;
        }

        for (auto* entry = adapter->FirstUnicastAddress; entry != nullptr; entry = entry->Next) {
            if (entry->Address.lpSockaddr == nullptr || entry->Address.lpSockaddr->sa_family != AF_INET) {
                continue;
            }

            auto* address = reinterpret_cast<sockaddr_in*>(entry->Address.lpSockaddr);
            const std::uint32_t ip = ntohl(address->sin_addr.S_un.S_addr);

            if (!isPrivateIpv4(ip)) {
                continue;
            }

            std::uint8_t prefix = entry->OnLinkPrefixLength;
            if (prefix < 24) {
                prefix = 24;
            } else if (prefix > 30) {
                prefix = 30;
            }

            const std::uint32_t mask = prefix == 0 ? 0u : std::numeric_limits<std::uint32_t>::max() << (32 - prefix);
            const std::uint32_t network = ip & mask;
            return toCidrString(network, prefix);
        }
    }

    throw std::runtime_error("No se encontró una interfaz IPv4 privada activa para escanear.");
}

}
