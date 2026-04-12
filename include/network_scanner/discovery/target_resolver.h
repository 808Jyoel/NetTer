#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace network_scanner {

struct NetworkRange {
    std::uint32_t network;
    std::uint32_t broadcast;
    std::uint8_t prefixLength;
};

class TargetResolver {
public:
    std::string resolveDefaultCidr() const;
    NetworkRange parseCidr(const std::string& cidr) const;
    std::string normalizeCidr(const std::string& cidr) const;
    std::vector<std::string> enumerateTargets(const NetworkRange& range) const;
};

}
