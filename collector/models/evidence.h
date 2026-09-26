#pragma once

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

enum class EvidenceType {
    BrowserHistory,
    BrowserDownload,
    Process,
    NetworkConnection,
    File,
    EventLog
};

struct BrowserHistoryEvidence {
    std::string url;
    std::string domain;
    std::string title;

    std::vector<std::string> resolvedIps;
};

struct BrowserDownloadEvidence {
    std::string url;
    std::string domain;
    std::string referrer;

    std::string filePath;
    std::string fileName;

    uint64_t receivedBytes = 0;
    uint64_t totalBytes = 0;

    std::string state;
    std::string dangerType;
    std::string interruptReason;
};

struct ProcessEvidence {
    uint32_t processId = 0;
    uint32_t parentProcessId = 0;

    std::string processName;
    std::string processPath;
    std::string parentProcessName;

    std::string commandLine;
    std::string username;
};

struct NetworkConnectionEvidence {
    uint32_t processId = 0;

    std::string processName;

    std::string localIp;
    uint16_t localPort = 0;

    std::string remoteIp;
    uint16_t remotePort = 0;

    std::string state;
};

struct FileEvidence {
    std::string filePath;
    std::string fileName;

    uint64_t size = 0;

    std::string createdAt;
    std::string modifiedAt;
    std::string accessedAt;

    std::string sha256;
};

struct EventLogEvidence {
    std::string channel;
    uint32_t eventId = 0;

    std::string provider;
    std::string level;

    uint32_t processId = 0;
    std::string computer;

    std::string message;
};

using EvidenceData =
    std::variant<BrowserHistoryEvidence, BrowserDownloadEvidence,
                 ProcessEvidence, NetworkConnectionEvidence, FileEvidence,
                 EventLogEvidence>;

struct Evidence {
    std::string id;

    EvidenceType type;

    std::string source;
    std::string timestamp;
    std::string description;

    EvidenceData data;

    std::string raw;

    std::vector<std::string> tags;
    std::vector<std::string> relatedEvidence;
};