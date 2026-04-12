#pragma once

#include "network_scanner/core/models.h"

namespace network_scanner {

class NetworkScanner {
public:
    std::string resolveTargetCidr(const ScannerConfig& config) const;
    ScanReport scan(const ScannerConfig& config) const;
};

}
