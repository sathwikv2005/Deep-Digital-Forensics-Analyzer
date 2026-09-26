#include "networkCollector.h"

#include <iphlpapi.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")

namespace {

std::string wideToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return "";
    }

    int size = WideCharToMultiByte(CP_UTF8, 0, value.data(),
                                   static_cast<int>(value.size()), nullptr, 0,
                                   nullptr, nullptr);

    if (size <= 0) {
        return "";
    }

    std::string result(size, '\0');

    WideCharToMultiByte(CP_UTF8, 0, value.data(),
                        static_cast<int>(value.size()), result.data(), size,
                        nullptr, nullptr);

    return result;
}

std::string getProcessName(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

    if (!process) {
        return "Unknown";
    }

    wchar_t path[32768]{};

    DWORD size = static_cast<DWORD>(std::size(path));

    std::string result = "Unknown";

    if (QueryFullProcessImageNameW(process, 0, path, &size)) {
        std::wstring widePath(path, size);

        size_t separator = widePath.find_last_of(L"\\/");

        std::wstring filename = separator == std::wstring::npos
                                    ? widePath
                                    : widePath.substr(separator + 1);

        result = wideToUtf8(filename);
    }

    CloseHandle(process);

    return result;
}

std::string tcpStateToString(DWORD state) {
    switch (state) {
        case MIB_TCP_STATE_CLOSED:
            return "CLOSED";

        case MIB_TCP_STATE_LISTEN:
            return "LISTEN";

        case MIB_TCP_STATE_SYN_SENT:
            return "SYN_SENT";

        case MIB_TCP_STATE_SYN_RCVD:
            return "SYN_RECEIVED";

        case MIB_TCP_STATE_ESTAB:
            return "ESTABLISHED";

        case MIB_TCP_STATE_FIN_WAIT1:
            return "FIN_WAIT_1";

        case MIB_TCP_STATE_FIN_WAIT2:
            return "FIN_WAIT_2";

        case MIB_TCP_STATE_CLOSE_WAIT:
            return "CLOSE_WAIT";

        case MIB_TCP_STATE_CLOSING:
            return "CLOSING";

        case MIB_TCP_STATE_LAST_ACK:
            return "LAST_ACK";

        case MIB_TCP_STATE_TIME_WAIT:
            return "TIME_WAIT";

        case MIB_TCP_STATE_DELETE_TCB:
            return "DELETE_TCB";

        default:
            return "UNKNOWN";
    }
}

std::string currentTimestamp() {
    SYSTEMTIME time{};

    GetSystemTime(&time);

    char buffer[64]{};

    snprintf(buffer, sizeof(buffer), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
             time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute,
             time.wSecond, time.wMilliseconds);

    return buffer;
}

std::string ipv4ToString(DWORD address) {
    IN_ADDR addr{};

    addr.S_un.S_addr = address;

    char buffer[INET_ADDRSTRLEN]{};

    if (!inet_ntop(AF_INET, &addr, buffer, sizeof(buffer))) {
        return "";
    }

    return buffer;
}

std::string ipv6ToString(const BYTE address[16]) {
    IN6_ADDR addr{};

    memcpy(&addr, address, sizeof(addr));

    char buffer[INET6_ADDRSTRLEN]{};

    if (!inet_ntop(AF_INET6, &addr, buffer, sizeof(buffer))) {
        return "";
    }

    return buffer;
}

void collectIPv4(std::vector<Evidence>& evidence) {
    DWORD size = 0;

    DWORD result = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET,
                                       TCP_TABLE_OWNER_PID_ALL, 0);

    if (result != ERROR_INSUFFICIENT_BUFFER) {
        return;
    }

    std::vector<BYTE> buffer(size);

    auto* table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());

    result = GetExtendedTcpTable(table, &size, FALSE, AF_INET,
                                 TCP_TABLE_OWNER_PID_ALL, 0);

    if (result != NO_ERROR) {
        return;
    }

    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& connection = table->table[i];

        std::string localIp = ipv4ToString(connection.dwLocalAddr);

        std::string remoteIp = ipv4ToString(connection.dwRemoteAddr);

        uint16_t localPort =
            ntohs(static_cast<u_short>(connection.dwLocalPort));

        uint16_t remotePort =
            ntohs(static_cast<u_short>(connection.dwRemotePort));

        std::string process = getProcessName(connection.dwOwningPid);

        std::string state = tcpStateToString(connection.dwState);

        NetworkConnectionEvidence data;

        data.processId = connection.dwOwningPid;

        data.processName = process;

        data.localIp = localIp;

        data.localPort = localPort;

        data.remoteIp = remoteIp;

        data.remotePort = remotePort;

        data.state = state;

        Evidence item;

        item.id = "network-" + std::to_string(evidence.size() + 1);

        item.source = "Windows Network";

        item.timestamp = currentTimestamp();

        item.description =
            process + " (" + std::to_string(connection.dwOwningPid) + ") " +
            localIp + ":" + std::to_string(localPort) + " -> " + remoteIp +
            ":" + std::to_string(remotePort) + " [" + state + "]";

        item.raw =
            "family=IPv4"
            "; pid=" +
            std::to_string(connection.dwOwningPid) + "; process=" + process +
            "; local=" + localIp + ":" + std::to_string(localPort) +
            "; remote=" + remoteIp + ":" + std::to_string(remotePort) +
            "; state=" + state;

        item.data = std::move(data);

        evidence.push_back(std::move(item));
    }
}

void collectIPv6(std::vector<Evidence>& evidence) {
    DWORD size = 0;

    DWORD result = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET6,
                                       TCP_TABLE_OWNER_PID_ALL, 0);

    if (result != ERROR_INSUFFICIENT_BUFFER) {
        return;
    }

    std::vector<BYTE> buffer(size);

    auto* table = reinterpret_cast<PMIB_TCP6TABLE_OWNER_PID>(buffer.data());

    result = GetExtendedTcpTable(table, &size, FALSE, AF_INET6,
                                 TCP_TABLE_OWNER_PID_ALL, 0);

    if (result != NO_ERROR) {
        return;
    }

    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& connection = table->table[i];

        std::string localIp = ipv6ToString(connection.ucLocalAddr);

        std::string remoteIp = ipv6ToString(connection.ucRemoteAddr);

        uint16_t localPort =
            ntohs(static_cast<u_short>(connection.dwLocalPort));

        uint16_t remotePort =
            ntohs(static_cast<u_short>(connection.dwRemotePort));

        std::string process = getProcessName(connection.dwOwningPid);

        std::string state = tcpStateToString(connection.dwState);

        NetworkConnectionEvidence data;

        data.processId = connection.dwOwningPid;

        data.processName = process;

        data.localIp = localIp;

        data.localPort = localPort;

        data.remoteIp = remoteIp;

        data.remotePort = remotePort;

        data.state = state;

        Evidence item;

        item.id = "network-" + std::to_string(evidence.size() + 1);

        item.source = "Windows Network";

        item.timestamp = currentTimestamp();

        item.description =
            process + " (" + std::to_string(connection.dwOwningPid) + ") [" +
            localIp + "]:" + std::to_string(localPort) + " -> [" + remoteIp +
            "]:" + std::to_string(remotePort) + " [" + state + "]";

        item.raw =
            "family=IPv6"
            "; pid=" +
            std::to_string(connection.dwOwningPid) + "; process=" + process +
            "; local=[" + localIp + "]:" + std::to_string(localPort) +
            "; remote=[" + remoteIp + "]:" + std::to_string(remotePort) +
            "; state=" + state;

        item.data = std::move(data);

        evidence.push_back(std::move(item));
    }
}

}  // namespace

std::vector<Evidence> NetworkCollector::collect() {
    std::vector<Evidence> evidence;

    collectIPv4(evidence);
    collectIPv6(evidence);

    return evidence;
}