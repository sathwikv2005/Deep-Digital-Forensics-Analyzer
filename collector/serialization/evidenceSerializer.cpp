#include "evidenceSerializer.h"

#include <filesystem>
#include <fstream>
#include <type_traits>

#include "nlohmann/json.hpp"

using json = nlohmann::json;

namespace {

template <typename T>
std::string evidenceType() {
    if constexpr (std::is_same_v<T, BrowserHistoryEvidence>) {
        return "BrowserHistory";
    } else if constexpr (std::is_same_v<T, BrowserDownloadEvidence>) {
        return "BrowserDownload";
    } else if constexpr (std::is_same_v<T, ProcessEvidence>) {
        return "Process";
    } else if constexpr (std::is_same_v<T, NetworkConnectionEvidence>) {
        return "NetworkConnection";
    } else if constexpr (std::is_same_v<T, FileEvidence>) {
        return "File";
    } else if constexpr (std::is_same_v<T, EventLogEvidence>) {
        return "EventLog";
    }

    return "Unknown";
}

json serializeData(const BrowserHistoryEvidence& data) {
    return {{"url", data.url},
            {"domain", data.domain},
            {"title", data.title},
            {"resolvedIps", data.resolvedIps}};
}

json serializeData(const BrowserDownloadEvidence& data) {
    return {{"url", data.url},
            {"domain", data.domain},
            {"referrer", data.referrer},
            {"filePath", data.filePath},
            {"fileName", data.fileName},
            {"receivedBytes", data.receivedBytes},
            {"totalBytes", data.totalBytes},
            {"state", data.state},
            {"dangerType", data.dangerType},
            {"interruptReason", data.interruptReason}};
}

json serializeData(const ProcessEvidence& data) {
    return {{"processId", data.processId},
            {"parentProcessId", data.parentProcessId},
            {"processName", data.processName},
            {"processPath", data.processPath},
            {"parentProcessName", data.parentProcessName},
            {"commandLine", data.commandLine},
            {"username", data.username}};
}

json serializeData(const NetworkConnectionEvidence& data) {
    return {{"processId", data.processId}, {"processName", data.processName},
            {"localIp", data.localIp},     {"localPort", data.localPort},
            {"remoteIp", data.remoteIp},   {"remotePort", data.remotePort},
            {"state", data.state}};
}

json serializeData(const FileEvidence& data) {
    return {{"filePath", data.filePath},
            {"fileName", data.fileName},
            {"size", data.size},
            {"createdAt", data.createdAt},
            {"modifiedAt", data.modifiedAt},
            {"accessedAt", data.accessedAt},
            {"sha256", data.sha256}};
}

json serializeData(const EventLogEvidence& data) {
    return {{"channel", data.channel},     {"eventId", data.eventId},
            {"provider", data.provider},   {"level", data.level},
            {"processId", data.processId}, {"computer", data.computer},
            {"message", data.message}};
}

json serializeEvidenceData(const EvidenceData& data) {
    return std::visit(
        [](const auto& value) -> json { return serializeData(value); }, data);
}

std::string getEvidenceType(const EvidenceData& data) {
    return std::visit(
        [](const auto& value) {
            return evidenceType<std::decay_t<decltype(value)>>();
        },
        data);
}

}  // namespace

bool EvidenceSerializer::write(const std::string& path,
                               const std::vector<Evidence>& evidence) {
    json output = json::array();

    for (const auto& item : evidence) {
        json object = {{"id", item.id},
                       {"source", item.source},
                       {"timestamp", item.timestamp},
                       {"type", getEvidenceType(item.data)},
                       {"description", item.description},
                       {"data", serializeEvidenceData(item.data)},
                       {"raw", item.raw},
                       {"tags", item.tags},
                       {"relatedEvidence", item.relatedEvidence}};

        output.push_back(std::move(object));
    }

    std::filesystem::path filePath(path);

    if (filePath.has_parent_path()) {
        std::filesystem::create_directories(filePath.parent_path());
    }

    std::ofstream file(filePath, std::ios::out | std::ios::trunc);

    if (!file.is_open()) {
        return false;
    }

    file << output.dump(4);

    if (file.fail()) {
        file.close();
        return false;
    }

    file.close();

    return true;
}