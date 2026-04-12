#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace network_scanner {

enum class PortState {
    Open,
    Closed,
    Filtered,
    Error
};

struct PortResult {
    std::uint16_t port;
    PortState state;
    std::optional<unsigned long> latencyMs;
    int errorCode;
};

struct HostResult {
    std::string ip;
    bool discovered;
    bool icmpReachable;
    std::optional<unsigned long> icmpLatencyMs;
    std::vector<PortResult> portResults;
};

struct ScanReport {
    std::string targetCidr;
    std::vector<std::uint16_t> targetPorts;
    std::vector<HostResult> hosts;
    unsigned long long elapsedMs;
};

struct ScannerConfig {
    std::optional<std::string> cidr;
    std::vector<std::uint16_t> ports;
    unsigned long pingTimeoutMs;
    unsigned long connectTimeoutMs;
    std::size_t workerCount;
    bool includeUnresponsiveHosts;
};

}
