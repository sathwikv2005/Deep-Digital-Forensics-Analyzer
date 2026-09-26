#include "browserCollector.h"

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <chrono>
#include <filesystem>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

#include "sqlite3.h"

#pragma comment(lib, "Ws2_32.lib")

namespace fs = std::filesystem;

namespace {

constexpr long long WINDOWS_EPOCH_OFFSET = 11644473600000000LL;
constexpr long long THIRTY_DAYS_MICROSECONDS =
    30LL * 24LL * 60LL * 60LL * 1000000LL;

std::string chromeTimeToIso(long long chromeTime) {
    if (chromeTime == 0) {
        return "";
    }

    long long unixMicroseconds = chromeTime - WINDOWS_EPOCH_OFFSET;

    if (unixMicroseconds < 0) {
        return "";
    }

    time_t seconds = unixMicroseconds / 1000000;

    tm utcTime{};

    if (gmtime_s(&utcTime, &seconds) != 0) {
        return "";
    }

    char buffer[64]{};

    strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &utcTime);

    return buffer;
}

long long getCurrentChromeTime() {
    auto now = std::chrono::system_clock::now();

    auto unixMicroseconds =
        std::chrono::duration_cast<std::chrono::microseconds>(
            now.time_since_epoch())
            .count();

    return unixMicroseconds + WINDOWS_EPOCH_OFFSET;
}

bool isWithinLast30Days(long long chromeTime, long long currentChromeTime) {
    if (chromeTime <= 0) {
        return false;
    }

    return chromeTime >= currentChromeTime - THIRTY_DAYS_MICROSECONDS;
}

std::string getTempDatabasePath(const std::string& name) {
    wchar_t tempPath[MAX_PATH]{};

    DWORD length = GetTempPathW(MAX_PATH, tempPath);

    if (length == 0 || length >= MAX_PATH) {
        return "";
    }

    fs::path path(tempPath);

    path /= "deep_forensics_" + name + "_" +
            std::to_string(GetCurrentProcessId()) + ".db";

    return path.string();
}

bool copyDatabase(const fs::path& source, fs::path& destination,
                  const std::string& name) {
    std::string path = getTempDatabasePath(name);

    if (path.empty()) {
        return false;
    }

    destination = path;

    std::error_code error;

    fs::remove(destination, error);

    return CopyFileW(source.wstring().c_str(), destination.wstring().c_str(),
                     FALSE);
}

std::string extractDomain(const std::string& url) {
    if (url.empty()) {
        return "";
    }

    size_t start = 0;

    if (url.rfind("https://", 0) == 0) {
        start = 8;
    } else if (url.rfind("http://", 0) == 0) {
        start = 7;
    } else {
        return "";
    }

    size_t end = url.find('/', start);

    size_t query = url.find('?', start);

    size_t fragment = url.find('#', start);

    if (end == std::string::npos ||
        (query != std::string::npos && query < end)) {
        end = query;
    }

    if (fragment != std::string::npos &&
        (end == std::string::npos || fragment < end)) {
        end = fragment;
    }

    std::string authority = end == std::string::npos
                                ? url.substr(start)
                                : url.substr(start, end - start);

    size_t at = authority.rfind('@');

    if (at != std::string::npos) {
        authority = authority.substr(at + 1);
    }

    if (!authority.empty() && authority.front() == '[') {
        size_t closing = authority.find(']');

        if (closing != std::string::npos) {
            return authority.substr(1, closing - 1);
        }
    }

    size_t colon = authority.find(':');

    if (colon != std::string::npos) {
        authority = authority.substr(0, colon);
    }

    return authority;
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

        if (!inet_ntop(current->ai_family, address, buffer, sizeof(buffer))) {
            continue;
        }

        std::string ip(buffer);

        bool duplicate = false;

        for (const auto& existing : addresses) {
            if (existing == ip) {
                duplicate = true;
                break;
            }
        }

        if (!duplicate) {
            addresses.push_back(std::move(ip));
        }
    }

    freeaddrinfo(result);

    return addresses;
}

std::string getText(sqlite3_stmt* statement, int column) {
    const unsigned char* value = sqlite3_column_text(statement, column);

    if (!value) {
        return "";
    }

    return reinterpret_cast<const char*>(value);
}

std::string getDownloadState(int state) {
    switch (state) {
        case 0:
            return "IN_PROGRESS";

        case 1:
            return "COMPLETE";

        case 2:
            return "CANCELLED";

        case 3:
            return "INTERRUPTED";

        default:
            return "UNKNOWN";
    }
}

void collectHistory(sqlite3* database, const std::string& profileName,
                    std::vector<Evidence>& evidence) {
    std::unordered_map<std::string, std::vector<std::string> > dnsCache;

    long long currentChromeTime = getCurrentChromeTime();

    const char* query =
        "SELECT "
        "visits.visit_time, "
        "urls.url, "
        "urls.title "
        "FROM visits "
        "JOIN urls ON visits.url = urls.id "
        "WHERE visits.visit_time >= ? "
        "ORDER BY visits.visit_time ASC;";

    sqlite3_stmt* statement = nullptr;

    if (sqlite3_prepare_v2(database, query, -1, &statement, nullptr) !=
        SQLITE_OK) {
        std::cerr << "Failed to prepare Chrome history query\n";
        return;
    }

    long long cutoff = currentChromeTime - THIRTY_DAYS_MICROSECONDS;

    sqlite3_bind_int64(statement, 1, cutoff);

    size_t collected = 0;

    while (sqlite3_step(statement) == SQLITE_ROW) {
        long long visitTime = sqlite3_column_int64(statement, 0);

        std::string url = getText(statement, 1);

        std::string title = getText(statement, 2);

        if (!isWithinLast30Days(visitTime, currentChromeTime)) {
            continue;
        }

        BrowserHistoryEvidence data;

        data.url = url;
        data.domain = extractDomain(url);
        data.title = title;

        if (!data.domain.empty()) {
            auto cacheEntry = dnsCache.find(data.domain);

            if (cacheEntry != dnsCache.end()) {
                data.resolvedIps = cacheEntry->second;
            } else {
                data.resolvedIps = resolveDomain(data.domain);

                dnsCache[data.domain] = data.resolvedIps;
            }
        }

        Evidence item;

        item.type = EvidenceType::BrowserHistory;

        item.id = "browser-" + std::to_string(evidence.size() + 1);

        item.source = "Chrome Browser";

        item.timestamp = chromeTimeToIso(visitTime);

        item.description = "Visited " + url;

        if (!title.empty()) {
            item.description += " (" + title + ")";
        }

        item.raw = "profile=" + profileName + "; url=" + url +
                   "; domain=" + data.domain + "; title=" + title;

        if (!data.resolvedIps.empty()) {
            item.raw += "; resolved_ips=";

            for (size_t i = 0; i < data.resolvedIps.size(); ++i) {
                if (i > 0) {
                    item.raw += ",";
                }

                item.raw += data.resolvedIps[i];
            }
        }

        item.data = std::move(data);

        evidence.push_back(std::move(item));

        ++collected;

        if (collected % 1000 == 0) {
        }
    }

    sqlite3_finalize(statement);
}

void collectDownloads(sqlite3* database, const std::string& profileName,
                      std::vector<Evidence>& evidence) {
    long long currentChromeTime = getCurrentChromeTime();

    long long cutoff = currentChromeTime - THIRTY_DAYS_MICROSECONDS;

    const char* query =
        "SELECT "
        "d.id, "
        "d.start_time, "
        "d.end_time, "
        "d.current_path, "
        "d.target_path, "
        "d.received_bytes, "
        "d.total_bytes, "
        "d.state, "
        "d.danger_type, "
        "d.interrupt_reason, "
        "d.referrer, "
        "d.mime_type, "
        "d.original_mime_type, "
        "d.opened "
        "FROM downloads d "
        "WHERE d.start_time >= ? "
        "ORDER BY d.start_time ASC;";

    sqlite3_stmt* statement = nullptr;

    if (sqlite3_prepare_v2(database, query, -1, &statement, nullptr) !=
        SQLITE_OK) {
        std::cerr << "Failed to prepare Chrome downloads query\n";

        return;
    }

    sqlite3_bind_int64(statement, 1, cutoff);

    size_t collected = 0;

    while (sqlite3_step(statement) == SQLITE_ROW) {
        sqlite3_int64 downloadId = sqlite3_column_int64(statement, 0);

        long long startTime = sqlite3_column_int64(statement, 1);

        long long endTime = sqlite3_column_int64(statement, 2);

        std::string currentPath = getText(statement, 3);

        std::string targetPath = getText(statement, 4);

        uint64_t receivedBytes =
            static_cast<uint64_t>(sqlite3_column_int64(statement, 5));

        uint64_t totalBytes =
            static_cast<uint64_t>(sqlite3_column_int64(statement, 6));

        int state = sqlite3_column_int(statement, 7);

        int dangerType = sqlite3_column_int(statement, 8);

        int interruptReason = sqlite3_column_int(statement, 9);

        std::string referrer = getText(statement, 10);

        std::string mimeType = getText(statement, 11);

        std::string originalMimeType = getText(statement, 12);

        int opened = sqlite3_column_int(statement, 13);

        if (!isWithinLast30Days(startTime, currentChromeTime)) {
            continue;
        }

        std::string url;

        const char* urlQuery =
            "SELECT url "
            "FROM downloads_url_chains "
            "WHERE id = ? "
            "ORDER BY chain_index DESC "
            "LIMIT 1;";

        sqlite3_stmt* urlStatement = nullptr;

        if (sqlite3_prepare_v2(database, urlQuery, -1, &urlStatement,
                               nullptr) == SQLITE_OK) {
            sqlite3_bind_int64(urlStatement, 1, downloadId);

            if (sqlite3_step(urlStatement) == SQLITE_ROW) {
                url = getText(urlStatement, 0);
            }
        }

        sqlite3_finalize(urlStatement);

        BrowserDownloadEvidence data;

        data.url = url;
        data.domain = extractDomain(url);
        data.referrer = referrer;

        data.filePath = !currentPath.empty() ? currentPath : targetPath;

        if (data.filePath.empty()) {
            data.filePath = targetPath;
        }

        if (!data.filePath.empty()) {
            data.fileName = fs::path(data.filePath).filename().string();
        }

        data.receivedBytes = receivedBytes;

        data.totalBytes = totalBytes;

        data.state = getDownloadState(state);

        data.dangerType = std::to_string(dangerType);

        data.interruptReason = std::to_string(interruptReason);

        Evidence item;
        item.type = EvidenceType::BrowserDownload;

        item.id = "download-" + std::to_string(evidence.size() + 1);

        item.source = "Chrome Browser";

        item.timestamp = chromeTimeToIso(startTime);

        item.description = "Downloaded " + data.fileName;

        if (!url.empty()) {
            item.description += " from " + url;
        }

        item.raw = "profile=" + profileName +
                   "; download_id=" + std::to_string(downloadId) +
                   "; url=" + url + "; path=" + data.filePath +
                   "; state=" + data.state +
                   "; received=" + std::to_string(receivedBytes) +
                   "; total=" + std::to_string(totalBytes) +
                   "; danger_type=" + std::to_string(dangerType) +
                   "; interrupt_reason=" + std::to_string(interruptReason) +
                   "; referrer=" + referrer + "; mime_type=" + mimeType +
                   "; original_mime_type=" + originalMimeType +
                   "; opened=" + std::to_string(opened);

        item.data = std::move(data);

        evidence.push_back(std::move(item));

        ++collected;
    }

    sqlite3_finalize(statement);
}

void collectProfile(const fs::path& profilePath,
                    std::vector<Evidence>& evidence) {
    fs::path historyPath = profilePath / "History";

    if (!fs::exists(historyPath)) {
        return;
    }

    fs::path tempDatabase;

    if (!copyDatabase(historyPath, tempDatabase, "chrome_history")) {
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

    std::string profileName = profilePath.filename().string();

    collectHistory(database, profileName, evidence);

    collectDownloads(database, profileName, evidence);

    sqlite3_close(database);

    std::error_code error;

    fs::remove(tempDatabase, error);
}

}  // namespace

std::vector<Evidence> BrowserCollector::collect() {
    std::vector<Evidence> evidence;

    WSADATA wsaData{};

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "[Browser] Failed to initialize Winsock\n";

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