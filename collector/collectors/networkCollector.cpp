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

std::string getProcessName(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

    if (!process) {
        return "Unknown";
    }

    wchar_t path[MAX_PATH];

    DWORD size = MAX_PATH;

    std::string result = "Unknown";

    if (QueryFullProcessImageNameW(process, 0, path, &size)) {
        std::wstring widePath(path, size);

        size_t separator = widePath.find_last_of(L"\\/");

        std::wstring filename = separator == std::wstring::npos
                                    ? widePath
                                    : widePath.substr(separator + 1);

        result.assign(filename.begin(), filename.end());
    }

    CloseHandle(process);

    return result;
}

std::string ipToString(DWORD address) {
    IN_ADDR addr{};

    addr.S_un.S_addr = address;

    char buffer[INET_ADDRSTRLEN]{};

    if (!inet_ntop(AF_INET, &addr, buffer, sizeof(buffer))) {
        return "";
    }

    return buffer;
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

    char buffer[64];

    snprintf(buffer, sizeof(buffer), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
             time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute,
             time.wSecond, time.wMilliseconds);

    return buffer;
}

}  // namespace

std::vector<Evidence> NetworkCollector::collect() {
    std::vector<Evidence> evidence;

    DWORD size = 0;

    DWORD result = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET,
                                       TCP_TABLE_OWNER_PID_ALL, 0);

    if (result != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "Failed to query TCP table: " << result << '\n';

        return evidence;
    }

    std::vector<BYTE> buffer(size);

    auto* table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());

    result = GetExtendedTcpTable(table, &size, FALSE, AF_INET,
                                 TCP_TABLE_OWNER_PID_ALL, 0);

    if (result != NO_ERROR) {
        std::cerr << "Failed to retrieve TCP table: " << result << '\n';

        return evidence;
    }

    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& connection = table->table[i];

        std::string localIp = ipToString(connection.dwLocalAddr);

        std::string remoteIp = ipToString(connection.dwRemoteAddr);

        uint16_t localPort =
            ntohs(static_cast<u_short>(connection.dwLocalPort));

        uint16_t remotePort =
            ntohs(static_cast<u_short>(connection.dwRemotePort));

        std::string state = tcpStateToString(connection.dwState);

        std::string process = getProcessName(connection.dwOwningPid);

        NetworkConnectionEvidence networkData;

        networkData.processId = connection.dwOwningPid;

        networkData.processName = process;

        networkData.localIp = localIp;

        networkData.localPort = localPort;

        networkData.remoteIp = remoteIp;

        networkData.remotePort = remotePort;

        networkData.state = state;

        Evidence item;

        item.id = "network-" + std::to_string(evidence.size() + 1);

        item.source = "Windows Network";

        item.timestamp = currentTimestamp();

        item.description =
            process + " (" + std::to_string(connection.dwOwningPid) + ") " +
            localIp + ":" + std::to_string(localPort) + " -> " + remoteIp +
            ":" + std::to_string(remotePort) + " [" + state + "]";

        item.raw = "pid=" + std::to_string(connection.dwOwningPid) +
                   "; process=" + process + "; local=" + localIp + ":" +
                   std::to_string(localPort) + "; remote=" + remoteIp + ":" +
                   std::to_string(remotePort) + "; state=" + state;

        item.data = std::move(networkData);

        evidence.push_back(std::move(item));
    }

    return evidence;
}