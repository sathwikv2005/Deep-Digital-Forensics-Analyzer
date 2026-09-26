#include "browserCollector.h"

#include <windows.h>
#include <ws2tcpip.h>

#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "sqlite3.h"

#pragma comment(lib, "Ws2_32.lib")

namespace fs = std::filesystem;

namespace {

std::string chromeTimeToIso(long long chromeTime) {
    if (chromeTime == 0) return "";

    constexpr long long WINDOWS_EPOCH_OFFSET = 11644473600000000LL;

    long long unixMicroseconds = chromeTime - WINDOWS_EPOCH_OFFSET;

    if (unixMicroseconds < 0) return "";

    time_t seconds = unixMicroseconds / 1000000;

    tm utcTime{};

    if (gmtime_s(&utcTime, &seconds) != 0) {
        return "";
    }

    char buffer[64];

    strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &utcTime);

    return buffer;
}

std::string getTempHistoryPath() {
    wchar_t tempPath[MAX_PATH];

    DWORD length = GetTempPathW(MAX_PATH, tempPath);

    if (length == 0 || length >= MAX_PATH) {
        return "";
    }

    fs::path path(tempPath);
    path /= "deep_forensics_chrome_history";

    return path.string();
}

bool copyHistoryDatabase(const fs::path& source, fs::path& destination) {
    destination = fs::path(getTempHistoryPath());

    if (destination.empty()) {
        return false;
    }

    destination += "_" + std::to_string(GetCurrentProcessId()) + ".db";

    std::error_code error;

    fs::remove(destination, error);

    return CopyFileW(source.wstring().c_str(), destination.wstring().c_str(),
                     FALSE);
}

std::string extractDomain(const std::string& url) {
    if (url.empty()) {
        return "";
    }

    std::string start;

    if (url.rfind("https://", 0) == 0) {
        start = url.substr(8);
    } else if (url.rfind("http://", 0) == 0) {
        start = url.substr(7);
    } else {
        return "";
    }

    size_t end = start.find('/');

    if (end != std::string::npos) {
        start = start.substr(0, end);
    }

    end = start.find('?');

    if (end != std::string::npos) {
        start = start.substr(0, end);
    }

    end = start.find('#');

    if (end != std::string::npos) {
        start = start.substr(0, end);
    }

    if (!start.empty() && start.front() == '[') {
        size_t closing = start.find(']');

        if (closing != std::string::npos) {
            return start.substr(1, closing - 1);
        }
    }

    size_t colon = start.find(':');

    if (colon != std::string::npos) {
        start = start.substr(0, colon);
    }

    return start;
}

std::vector<std::string> resolveDomain(const std::string& domain) {
    std::vector<std::string> addresses;

    if (domain.empty()) {
        return addresses;
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* result = nullptr;

    int status = getaddrinfo(domain.c_str(), nullptr, &hints, &result);

    if (status != 0 || !result) {
        return addresses;
    }

    for (addrinfo* current = result; current != nullptr;
         current = current->ai_next) {
        char buffer[INET6_ADDRSTRLEN]{};

        void* address = nullptr;

        if (current->ai_family == AF_INET) {
            auto* ipv4 = reinterpret_cast<sockaddr_in*>(current->ai_addr);

            address = &ipv4->sin_addr;
        } else if (current->ai_family == AF_INET6) {
            auto* ipv6 = reinterpret_cast<sockaddr_in6*>(current->ai_addr);

            address = &ipv6->sin6_addr;
        } else {
            continue;
        }

        if (inet_ntop(current->ai_family, address, buffer, sizeof(buffer))) {
            std::string ip(buffer);

            bool alreadyExists = false;

            for (const auto& existing : addresses) {
                if (existing == ip) {
                    alreadyExists = true;
                    break;
                }
            }

            if (!alreadyExists) {
                addresses.push_back(std::move(ip));
            }
        }
    }

    freeaddrinfo(result);

    return addresses;
}

void collectProfile(const fs::path& profilePath,
                    std::vector<Evidence>& evidence) {
    fs::path historyPath = profilePath / "History";

    if (!fs::exists(historyPath)) {
        return;
    }

    fs::path tempDatabase;

    if (!copyHistoryDatabase(historyPath, tempDatabase)) {
        std::cerr << "Failed to copy Chrome history: " << historyPath << '\n';
        return;
    }

    sqlite3* database = nullptr;

    if (sqlite3_open_v2(tempDatabase.string().c_str(), &database,
                        SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to open Chrome history database\n";

        if (database) {
            sqlite3_close(database);
        }

        fs::remove(tempDatabase);

        return;
    }

    const char* query =
        "SELECT "
        "visits.visit_time, "
        "urls.url, "
        "urls.title "
        "FROM visits "
        "JOIN urls ON visits.url = urls.id "
        "ORDER BY visits.visit_time ASC;";

    sqlite3_stmt* statement = nullptr;

    if (sqlite3_prepare_v2(database, query, -1, &statement, nullptr) !=
        SQLITE_OK) {
        std::cerr << "Failed to prepare Chrome history query\n";

        sqlite3_close(database);
        fs::remove(tempDatabase);

        return;
    }

    std::string profileName = profilePath.filename().string();

    while (sqlite3_step(statement) == SQLITE_ROW) {
        long long visitTime = sqlite3_column_int64(statement, 0);

        const unsigned char* url = sqlite3_column_text(statement, 1);

        const unsigned char* title = sqlite3_column_text(statement, 2);

        std::string urlString = url ? reinterpret_cast<const char*>(url) : "";

        std::string titleString =
            title ? reinterpret_cast<const char*>(title) : "";

        BrowserHistoryEvidence browserData;

        browserData.url = urlString;
        browserData.domain = extractDomain(urlString);
        browserData.title = titleString;

        browserData.resolvedIps = resolveDomain(browserData.domain);

        Evidence item;

        item.id = "browser-" + std::to_string(evidence.size() + 1);

        item.source = "Chrome Browser";

        item.timestamp = chromeTimeToIso(visitTime);

        item.description = "Visited " + urlString;

        if (!titleString.empty()) {
            item.description += " (" + titleString + ")";
        }

        item.raw = "profile=" + profileName + "; url=" + urlString +
                   "; domain=" + browserData.domain + "; title=" + titleString;

        if (!browserData.resolvedIps.empty()) {
            item.raw += "; resolved_ips=";

            for (size_t i = 0; i < browserData.resolvedIps.size(); ++i) {
                if (i > 0) {
                    item.raw += ",";
                }

                item.raw += browserData.resolvedIps[i];
            }
        }

        item.data = std::move(browserData);

        evidence.push_back(std::move(item));
    }

    sqlite3_finalize(statement);
    sqlite3_close(database);

    std::error_code error;

    fs::remove(tempDatabase, error);
}

}  // namespace

std::vector<Evidence> BrowserCollector::collect() {
    std::vector<Evidence> evidence;

    WSADATA wsaData{};

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return evidence;
    }

    wchar_t* localAppData = nullptr;

    size_t size = 0;

    if (_wdupenv_s(&localAppData, &size, L"LOCALAPPDATA") != 0 ||
        !localAppData) {
        WSACleanup();

        return evidence;
    }

    fs::path chromePath(localAppData);

    free(localAppData);

    chromePath /= "Google";
    chromePath /= "Chrome";
    chromePath /= "User Data";

    if (!fs::exists(chromePath)) {
        WSACleanup();

        return evidence;
    }

    collectProfile(chromePath / "Default", evidence);

    for (const auto& entry : fs::directory_iterator(chromePath)) {
        if (!entry.is_directory()) {
            continue;
        }

        std::string name = entry.path().filename().string();

        if (name.rfind("Profile ", 0) == 0) {
            collectProfile(entry.path(), evidence);
        }
    }

    WSACleanup();

    return evidence;
}