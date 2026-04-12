#include "network_scanner/core/scanner.h"

#define NOMINMAX
#include <winsock2.h>

#include "core/ip_utils.h"
#include "network_scanner/discovery/icmp_discovery.h"
#include "network_scanner/discovery/target_resolver.h"
#include "network_scanner/ports/tcp_port_scanner.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <future>
#include <iterator>
#include <thread>
#include <vector>

namespace network_scanner {

namespace {

struct WsaGuard {
    WsaGuard() {
        WSADATA data{};
        const int result = WSAStartup(MAKEWORD(2, 2), &data);
        if (result != 0) {
            throw std::runtime_error("No se pudo inicializar Winsock.");
        }
    }

    ~WsaGuard() {
        WSACleanup();
    }
};

std::vector<std::uint16_t> normalizePorts(const std::vector<std::uint16_t>& ports) {
    std::vector<std::uint16_t> result = ports;
    if (result.empty()) {
        result = {21, 22, 23, 53, 80, 135, 139, 443, 445, 3389};
    }

    std::sort(result.begin(), result.end());
    result.erase(std::unique(result.begin(), result.end()), result.end());
    return result;
}

bool hasOpenPort(const std::vector<PortResult>& portResults) {
    return std::any_of(portResults.begin(), portResults.end(), [](const PortResult& result) {
        return result.state == PortState::Open;
    });
}

HostResult scanHost(
    const std::string& ip,
    const std::vector<std::uint16_t>& ports,
    const unsigned long pingTimeoutMs,
    const unsigned long connectTimeoutMs
) {
    IcmpDiscovery icmp;
    TcpPortScanner portScanner;

    const std::optional<unsigned long> icmpLatency = icmp.probe(ip, pingTimeoutMs);
    std::vector<PortResult> portResults = portScanner.scan(ip, ports, connectTimeoutMs);
    const bool discovered = icmpLatency.has_value() || hasOpenPort(portResults);

    return HostResult{
        .ip = ip,
        .discovered = discovered,
        .icmpReachable = icmpLatency.has_value(),
        .icmpLatencyMs = icmpLatency,
        .portResults = std::move(portResults)
    };
}

}

std::string NetworkScanner::resolveTargetCidr(const ScannerConfig& config) const {
    TargetResolver resolver;
    if (config.cidr.has_value() && !config.cidr->empty()) {
        return resolver.normalizeCidr(*config.cidr);
    }

    return resolver.resolveDefaultCidr();
}

ScanReport NetworkScanner::scan(const ScannerConfig& config) const {
    const auto startedAt = std::chrono::steady_clock::now();
    TargetResolver resolver;
    const std::string targetCidr = resolveTargetCidr(config);
    const NetworkRange range = resolver.parseCidr(targetCidr);
    const std::vector<std::string> targets = resolver.enumerateTargets(range);
    const std::vector<std::uint16_t> targetPorts = normalizePorts(config.ports);

    const std::size_t desiredWorkers = config.workerCount == 0
        ? static_cast<std::size_t>(std::max(1u, std::thread::hardware_concurrency()))
        : config.workerCount;
    const std::size_t workerCount = std::max<std::size_t>(1, std::min<std::size_t>(
        desiredWorkers,
        targets.empty() ? 1 : targets.size()
    ));

    WsaGuard wsaGuard;
    std::atomic<std::size_t> nextIndex{0};
    std::vector<std::future<std::vector<HostResult>>> workers;
    workers.reserve(workerCount);

    for (std::size_t worker = 0; worker < workerCount; ++worker) {
        workers.push_back(std::async(std::launch::async, [&]() {
            std::vector<HostResult> localResults;
            while (true) {
                const std::size_t index = nextIndex.fetch_add(1);
                if (index >= targets.size()) {
                    break;
                }

                HostResult hostResult = scanHost(
                    targets[index],
                    targetPorts,
                    config.pingTimeoutMs,
                    config.connectTimeoutMs
                );

                if (hostResult.discovered || config.includeUnresponsiveHosts) {
                    localResults.push_back(std::move(hostResult));
                }
            }
            return localResults;
        }));
    }

    std::vector<HostResult> hosts;
    for (auto& worker : workers) {
        std::vector<HostResult> partial = worker.get();
        hosts.insert(hosts.end(), std::make_move_iterator(partial.begin()), std::make_move_iterator(partial.end()));
    }

    std::sort(hosts.begin(), hosts.end(), [](const HostResult& left, const HostResult& right) {
        return parseIpv4(left.ip) < parseIpv4(right.ip);
    });

    const auto endedAt = std::chrono::steady_clock::now();
    const unsigned long long elapsed = static_cast<unsigned long long>(
        std::chrono::duration_cast<std::chrono::milliseconds>(endedAt - startedAt).count()
    );

    return ScanReport{
        .targetCidr = targetCidr,
        .targetPorts = targetPorts,
        .hosts = std::move(hosts),
        .elapsedMs = elapsed
    };
}

}
