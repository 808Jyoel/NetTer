#pragma once

#include <optional>
#include <string>

namespace network_scanner {

class IcmpDiscovery {
public:
    IcmpDiscovery();
    ~IcmpDiscovery();

    IcmpDiscovery(const IcmpDiscovery&) = delete;
    IcmpDiscovery& operator=(const IcmpDiscovery&) = delete;

    std::optional<unsigned long> probe(const std::string& ip, unsigned long timeoutMs) const;

private:
    void* handle_;
};

}
