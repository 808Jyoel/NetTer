#pragma once

#include "network_scanner/core/models.h"

#include <cstdint>
#include <string>
#include <vector>

namespace network_scanner {

class TcpPortScanner {
public:
    PortResult probe(const std::string& ip, std::uint16_t port, unsigned long timeoutMs) const;
    std::vector<PortResult> scan(const std::string& ip, const std::vector<std::uint16_t>& ports, unsigned long timeoutMs) const;
};

}
