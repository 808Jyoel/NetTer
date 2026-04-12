#include "network_scanner/output/formatter.h"

#include <iomanip>
#include <sstream>

namespace network_scanner {

namespace {

std::string escapeJson(const std::string& value) {
    std::ostringstream output;
    for (const char ch : value) {
        switch (ch) {
            case '"': output << "\\\""; break;
            case '\\': output << "\\\\"; break;
            case '\b': output << "\\b"; break;
            case '\f': output << "\\f"; break;
            case '\n': output << "\\n"; break;
            case '\r': output << "\\r"; break;
            case '\t': output << "\\t"; break;
            default:
                if (static_cast<unsigned char>(ch) < 0x20) {
                    output << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(static_cast<unsigned char>(ch));
                } else {
                    output << ch;
                }
                break;
        }
    }
    return output.str();
}

std::string stateToString(const PortState state) {
    switch (state) {
        case PortState::Open: return "open";
        case PortState::Closed: return "closed";
        case PortState::Filtered: return "filtered";
        case PortState::Error: return "error";
    }
    return "error";
}

std::string formatPortsText(const std::vector<PortResult>& ports) {
    if (ports.empty()) {
        return "-";
    }

    std::ostringstream output;
    for (std::size_t index = 0; index < ports.size(); ++index) {
        const PortResult& port = ports[index];
        if (index != 0) {
            output << " | ";
        }
        output << port.port << ":" << stateToString(port.state);
    }
    return output.str();
}

}

std::string Formatter::toText(const ScanReport& report) const {
    std::ostringstream output;
    output << "Escaneando red: " << report.targetCidr << "\n";
    output << "Hosts detectados: " << report.hosts.size() << "\n";
    output << "Tiempo total: " << report.elapsedMs << " ms\n\n";

    output << std::left
           << std::setw(18) << "IP"
           << std::setw(14) << "ICMP"
           << std::setw(12) << "Activo"
           << "Estados de puertos\n";
    output << std::string(110, '-') << '\n';

    for (const HostResult& host : report.hosts) {
        const std::string icmp = host.icmpLatencyMs.has_value()
            ? std::to_string(*host.icmpLatencyMs) + " ms"
            : "sin-respuesta";

        output << std::left
               << std::setw(18) << host.ip
               << std::setw(14) << icmp
               << std::setw(12) << (host.discovered ? "si" : "no")
               << formatPortsText(host.portResults)
               << '\n';
    }

    return output.str();
}

std::string Formatter::toJson(const ScanReport& report) const {
    std::ostringstream output;
    output << "{";
    output << "\"target_cidr\":\"" << escapeJson(report.targetCidr) << "\",";
    output << "\"elapsed_ms\":" << report.elapsedMs << ",";
    output << "\"target_ports\":[";

    for (std::size_t index = 0; index < report.targetPorts.size(); ++index) {
        if (index != 0) {
            output << ",";
        }
        output << report.targetPorts[index];
    }

    output << "],";
    output << "\"hosts\":[";

    for (std::size_t hostIndex = 0; hostIndex < report.hosts.size(); ++hostIndex) {
        if (hostIndex != 0) {
            output << ",";
        }

        const HostResult& host = report.hosts[hostIndex];
        output << "{";
        output << "\"ip\":\"" << escapeJson(host.ip) << "\",";
        output << "\"discovered\":" << (host.discovered ? "true" : "false") << ",";
        output << "\"icmp_reachable\":" << (host.icmpReachable ? "true" : "false") << ",";
        if (host.icmpLatencyMs.has_value()) {
            output << "\"icmp_latency_ms\":" << *host.icmpLatencyMs << ",";
        } else {
            output << "\"icmp_latency_ms\":null,";
        }
        output << "\"ports\":[";

        for (std::size_t portIndex = 0; portIndex < host.portResults.size(); ++portIndex) {
            if (portIndex != 0) {
                output << ",";
            }
            const PortResult& port = host.portResults[portIndex];
            output << "{";
            output << "\"port\":" << port.port << ",";
            output << "\"state\":\"" << stateToString(port.state) << "\",";
            if (port.latencyMs.has_value()) {
                output << "\"latency_ms\":" << *port.latencyMs << ",";
            } else {
                output << "\"latency_ms\":null,";
            }
            output << "\"error_code\":" << port.errorCode;
            output << "}";
        }

        output << "]";
        output << "}";
    }

    output << "]";
    output << "}";
    return output.str();
}

}
