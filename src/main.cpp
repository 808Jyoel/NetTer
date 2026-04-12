#include "network_scanner/core/scanner.h"
#include "network_scanner/output/formatter.h"

#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <algorithm>
#include <cstdlib>
#include <cstdint>
#include <exception>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

std::vector<std::string> split(std::string_view value, char delimiter) {
    std::vector<std::string> parts;
    std::size_t start = 0;

    while (start <= value.size()) {
        const std::size_t end = value.find(delimiter, start);
        if (end == std::string_view::npos) {
            parts.emplace_back(value.substr(start));
            break;
        }
        parts.emplace_back(value.substr(start, end - start));
        start = end + 1;
    }

    return parts;
}

std::string trim(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return {};
    }

    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

std::vector<std::uint16_t> parsePorts(const std::string& value) {
    std::vector<std::uint16_t> ports;

    for (std::string item : split(value, ',')) {
        item = trim(std::move(item));
        if (item.empty()) {
            continue;
        }

        const int parsed = std::stoi(item);
        if (parsed < 1 || parsed > 65535) {
            throw std::runtime_error("Puerto fuera de rango: " + item);
        }

        ports.push_back(static_cast<std::uint16_t>(parsed));
    }

    std::sort(ports.begin(), ports.end());
    ports.erase(std::unique(ports.begin(), ports.end()), ports.end());
    return ports;
}

void printUsage() {
    std::cout
        << "Uso:\n"
        << "  network_scanner [--cidr 192.168.1.0/24] [--ports 22,80,443] [--ping-timeout 300] [--connect-timeout 200] [--workers 32] [--output text|json] [--all-hosts]\n\n"
        << "Opciones:\n"
        << "  --cidr             Objetivo CIDR, IP o hostname.\n"
        << "  --ports            Lista de puertos TCP separados por coma.\n"
        << "  --ping-timeout     Timeout del ping ICMP en ms.\n"
        << "  --connect-timeout  Timeout de conexión TCP en ms.\n"
        << "  --workers          Número de hilos de escaneo.\n"
        << "  --output           Formato de salida: text o json.\n"
        << "  --all-hosts        Incluye hosts no detectados como activos.\n"
        << "  --help             Muestra esta ayuda.\n";
}

struct CliOptions {
    network_scanner::ScannerConfig scannerConfig;
    std::string outputFormat;
    bool pauseOnExit;
};

void configureConsoleUtf8() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
}

void printInteractiveLogo() {
    std::cout
        << "========================================\n"
        << "      _   _      _   _____             \n"
        << "     | \\ | | ___| |_|_   _|__ _ __     \n"
        << "     |  \\| |/ _ \\ __| | |/ _ \\ '__|    \n"
        << "     | |\\  |  __/ |_  | |  __/ |       \n"
        << "     |_| \\_|\\___|\\__| |_|\\___|_|       \n"
        << "         Network Scanner Console        \n"
        << "========================================\n\n";
}

void printSectionHeader(const std::string& title) {
    std::cout << "\n----------------------------------------\n";
    std::cout << title << '\n';
    std::cout << "----------------------------------------\n";
}

std::string portsToText(const std::vector<std::uint16_t>& ports) {
    if (ports.empty()) {
        return "default (21,22,23,53,80,135,139,443,445,3389)";
    }

    std::ostringstream output;
    for (std::size_t index = 0; index < ports.size(); ++index) {
        if (index != 0) {
            output << ",";
        }
        output << ports[index];
    }
    return output.str();
}

std::string resolveHostToIpv4(const std::string& host) {
    WSADATA data{};
    const int startupResult = WSAStartup(MAKEWORD(2, 2), &data);
    if (startupResult != 0) {
        throw std::runtime_error("No se pudo inicializar Winsock para resolver host.");
    }

    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* addresses = nullptr;
    const int result = getaddrinfo(host.c_str(), nullptr, &hints, &addresses);
    if (result != 0) {
        WSACleanup();
        throw std::runtime_error("No se pudo resolver el host: " + host);
    }

    std::string ip;
    for (addrinfo* current = addresses; current != nullptr; current = current->ai_next) {
        if (current->ai_family != AF_INET) {
            continue;
        }

        const auto* ipv4 = reinterpret_cast<sockaddr_in*>(current->ai_addr);
        char buffer[INET_ADDRSTRLEN]{};
        if (InetNtopA(AF_INET, &ipv4->sin_addr, buffer, static_cast<DWORD>(sizeof(buffer))) != nullptr) {
            ip = buffer;
            break;
        }
    }

    freeaddrinfo(addresses);
    WSACleanup();

    if (ip.empty()) {
        throw std::runtime_error("No se encontró una IPv4 válida para el host: " + host);
    }

    return ip;
}

std::string normalizeTargetToCidr(std::string targetInput) {
    targetInput = trim(std::move(targetInput));
    if (targetInput.empty()) {
        throw std::runtime_error("El objetivo no puede estar vacío.");
    }

    if (targetInput.find('/') != std::string::npos) {
        return targetInput;
    }

    IN_ADDR address{};
    if (InetPtonA(AF_INET, targetInput.c_str(), &address) == 1) {
        return targetInput + "/32";
    }

    return resolveHostToIpv4(targetInput) + "/32";
}

std::string askLine(const std::string& prompt) {
    std::cout << prompt;
    std::string value;
    std::getline(std::cin, value);
    return trim(std::move(value));
}

unsigned long askUnsignedLong(const std::string& label, const unsigned long defaultValue) {
    while (true) {
        const std::string input = askLine(label + " [" + std::to_string(defaultValue) + "]: ");
        if (input.empty()) {
            return defaultValue;
        }

        try {
            return static_cast<unsigned long>(std::stoul(input));
        } catch (...) {
            std::cout << "Valor inválido. Intenta de nuevo.\n";
        }
    }
}

std::size_t askSizeT(const std::string& label, const std::size_t defaultValue) {
    while (true) {
        const std::string input = askLine(label + " [" + std::to_string(defaultValue) + "]: ");
        if (input.empty()) {
            return defaultValue;
        }

        try {
            return static_cast<std::size_t>(std::stoull(input));
        } catch (...) {
            std::cout << "Valor inválido. Intenta de nuevo.\n";
        }
    }
}

bool askYesNo(const std::string& label, const bool defaultValue) {
    while (true) {
        const std::string defaultToken = defaultValue ? "S/n" : "s/N";
        const std::string input = askLine(label + " [" + defaultToken + "]: ");
        if (input.empty()) {
            return defaultValue;
        }

        if (input == "s" || input == "S" || input == "si" || input == "SI" || input == "Si" || input == "y" || input == "Y") {
            return true;
        }

        if (input == "n" || input == "N" || input == "no" || input == "NO" || input == "No") {
            return false;
        }

        std::cout << "Respuesta invalida. Usa s/n.\n";
    }
}

std::string askOutputFormat() {
    while (true) {
        const std::string input = askLine("Formato de salida (text/json) [text]: ");
        if (input.empty()) {
            return "text";
        }

        const std::string normalized = trim(input);
        if (normalized == "text" || normalized == "json") {
            return normalized;
        }

        std::cout << "Formato inválido. Usa text o json.\n";
    }
}

CliOptions parseInteractiveOptions() {
    printInteractiveLogo();
    std::cout << "Pulsa Enter para aceptar valores por defecto.\n";
    std::cout << "Sigue los pasos para configurar el escaneo.\n";

    network_scanner::ScannerConfig config{
        .cidr = std::nullopt,
        .ports = {},
        .pingTimeoutMs = 300,
        .connectTimeoutMs = 200,
        .workerCount = 32,
        .includeUnresponsiveHosts = false
    };

    printSectionHeader("Paso 1/5 - Objetivo de red");
    std::cout << "1) Detectar red automaticamente\n";
    std::cout << "2) Especificar objetivo manual (CIDR/IP/hostname)\n";

    bool useAutomaticNetwork = true;
    while (true) {
        const std::string selection = askLine("Seleccion [1]: ");
        if (selection.empty() || selection == "1") {
            useAutomaticNetwork = true;
            break;
        }
        if (selection == "2") {
            useAutomaticNetwork = false;
            break;
        }
        std::cout << "Seleccion invalida. Usa 1 o 2.\n";
    }

    if (!useAutomaticNetwork) {
        while (true) {
            const std::string target = askLine("Objetivo (CIDR, IP o hostname): ");
            if (!target.empty()) {
                try {
                    config.cidr = normalizeTargetToCidr(target);
                } catch (const std::exception& exception) {
                    std::cout << "Error en objetivo: " << exception.what() << '\n';
                    continue;
                }
                break;
            }
            std::cout << "Debes introducir un objetivo valido.\n";
        }
    }

    printSectionHeader("Paso 2/5 - Puertos");
    while (true) {
        const std::string portsInput = askLine("Puertos (coma separados, vacio = por defecto): ");
        if (portsInput.empty()) {
            break;
        }

        try {
            config.ports = parsePorts(portsInput);
            break;
        } catch (const std::exception& exception) {
            std::cout << "Error en puertos: " << exception.what() << '\n';
        }
    }

    printSectionHeader("Paso 3/5 - Rendimiento");
    config.pingTimeoutMs = askUnsignedLong("Timeout ping ICMP (ms)", 300);
    config.connectTimeoutMs = askUnsignedLong("Timeout conexion TCP (ms)", 200);
    config.workerCount = askSizeT("Numero de hilos", 32);

    printSectionHeader("Paso 4/5 - Alcance");
    config.includeUnresponsiveHosts = askYesNo("Incluir hosts no detectados como activos?", false);

    printSectionHeader("Paso 5/5 - Salida");
    const std::string outputFormat = askOutputFormat();

    printSectionHeader("Resumen de configuracion");
    std::cout << "Objetivo         : " << (config.cidr.has_value() ? *config.cidr : "automatico") << '\n';
    std::cout << "Puertos          : " << portsToText(config.ports) << '\n';
    std::cout << "Timeout ICMP     : " << config.pingTimeoutMs << " ms\n";
    std::cout << "Timeout TCP      : " << config.connectTimeoutMs << " ms\n";
    std::cout << "Workers          : " << config.workerCount << '\n';
    std::cout << "Incluir inactivos: " << (config.includeUnresponsiveHosts ? "si" : "no") << '\n';
    std::cout << "Salida           : " << outputFormat << '\n';
    std::cout << "----------------------------------------\n";

    if (!askYesNo("Iniciar escaneo ahora?", true)) {
        std::exit(0);
    }

    std::cout << "\nIniciando escaneo...\n\n";
    return CliOptions{
        .scannerConfig = std::move(config),
        .outputFormat = outputFormat,
        .pauseOnExit = true
    };
}

CliOptions parseArguments(int argc, char* argv[]) {
    if (argc == 1) {
        return parseInteractiveOptions();
    }

    network_scanner::ScannerConfig config{
        .cidr = std::nullopt,
        .ports = {},
        .pingTimeoutMs = 300,
        .connectTimeoutMs = 200,
        .workerCount = 32,
        .includeUnresponsiveHosts = false
    };
    std::string outputFormat = "text";

    for (int index = 1; index < argc; ++index) {
        const std::string_view argument = argv[index];

        auto requireValue = [&](std::string_view name) -> std::string {
            if (index + 1 >= argc) {
                throw std::runtime_error("Falta valor para " + std::string(name));
            }
            ++index;
            return argv[index];
        };

        if (argument == "--help") {
            printUsage();
            std::exit(0);
        }

        if (argument == "--cidr") {
            config.cidr = normalizeTargetToCidr(requireValue(argument));
            continue;
        }

        if (argument == "--ports") {
            config.ports = parsePorts(requireValue(argument));
            continue;
        }

        if (argument == "--ping-timeout") {
            config.pingTimeoutMs = static_cast<unsigned long>(std::stoul(requireValue(argument)));
            continue;
        }

        if (argument == "--connect-timeout") {
            config.connectTimeoutMs = static_cast<unsigned long>(std::stoul(requireValue(argument)));
            continue;
        }

        if (argument == "--workers") {
            config.workerCount = static_cast<std::size_t>(std::stoull(requireValue(argument)));
            continue;
        }

        if (argument == "--output") {
            outputFormat = trim(requireValue(argument));
            if (outputFormat != "text" && outputFormat != "json") {
                throw std::runtime_error("Formato de salida inválido: " + outputFormat);
            }
            continue;
        }

        if (argument == "--all-hosts") {
            config.includeUnresponsiveHosts = true;
            continue;
        }

        throw std::runtime_error("Argumento no reconocido: " + std::string(argument));
    }

    return CliOptions{
        .scannerConfig = std::move(config),
        .outputFormat = std::move(outputFormat),
        .pauseOnExit = false
    };
}

}

int main(int argc, char* argv[]) {
    try {
        configureConsoleUtf8();
        const CliOptions options = parseArguments(argc, argv);
        const network_scanner::NetworkScanner scanner;
        const network_scanner::Formatter formatter;
        const network_scanner::ScanReport report = scanner.scan(options.scannerConfig);

        if (options.outputFormat == "json") {
            std::cout << formatter.toJson(report) << '\n';
        } else {
            std::cout << formatter.toText(report);
        }
        if (options.pauseOnExit) {
            askLine("Pulsa Enter para cerrar...");
        }
        return 0;
    } catch (const std::exception& exception) {
        std::cerr << "Error: " << exception.what() << '\n';
        return 1;
    }
}
