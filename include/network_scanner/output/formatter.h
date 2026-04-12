#pragma once

#include "network_scanner/core/models.h"

#include <string>

namespace network_scanner {

class Formatter {
public:
    std::string toText(const ScanReport& report) const;
    std::string toJson(const ScanReport& report) const;
};

}
