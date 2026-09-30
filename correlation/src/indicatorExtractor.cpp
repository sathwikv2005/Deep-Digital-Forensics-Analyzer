#include "indicatorExtractor.h"

#include <algorithm>
#include <cctype>
#include <string>

namespace {

void addUnique(std::vector<std::string>& values, const std::string& value) {
    if (value.empty()) return;

    if (std::find(values.begin(), values.end(), value) == values.end()) {
        values.push_back(value);
    }
}

void addString(const json& data, const char* key,
               std::vector<std::string>& values) {
    if (!data.contains(key)) return;

    if (!data[key].is_string()) return;

    addUnique(values, data[key].get<std::string>());
}

std::string lower(std::string value) {
    std::transform(
        value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    return value;
}

std::string normalizeProcessName(const std::string& process) {
    if (process.empty()) return {};

    std::string value = lower(process);

    const size_t slash = value.find_last_of("\\/");

    if (slash != std::string::npos) value = value.substr(slash + 1);

    return value;
}

const json& getEvidenceData(const EvidenceNode& node) {
    static const json empty = json::object();

    if (!node.data.contains("data")) return empty;

    if (!node.data["data"].is_object()) return empty;

    return node.data["data"];
}

}  // namespace

Indicators IndicatorExtractor::extract(const EvidenceNode& node) {
    Indicators indicators;

    if (node.category == "BrowserHistory") {
        extractBrowserHistory(node, indicators);

    } else if (node.category == "BrowserDownload") {
        extractBrowserDownload(node, indicators);

    } else if (node.category == "Process") {
        extractProcess(node, indicators);

    } else if (node.category == "NetworkConnection") {
        extractNetwork(node, indicators);

    } else if (node.category == "File") {
        extractFile(node, indicators);

    } else if (node.category == "EventLog") {
        extractEventLog(node, indicators);
    }

    return indicators;
}

void IndicatorExtractor::extractBrowserHistory(const EvidenceNode& node,
                                               Indicators& indicators) {
    const auto& data = getEvidenceData(node);

    addString(data, "url", indicators.urls);

    addString(data, "domain", indicators.domains);

    if (data.contains("resolvedIps") && data["resolvedIps"].is_array()) {
        for (const auto& ip : data["resolvedIps"]) {
            if (ip.is_string()) {
                addUnique(indicators.ips, ip.get<std::string>());
            }
        }
    }
}

void IndicatorExtractor::extractBrowserDownload(const EvidenceNode& node,
                                                Indicators& indicators) {
    const auto& data = getEvidenceData(node);

    addString(data, "url", indicators.urls);

    addString(data, "domain", indicators.domains);

    addString(data, "filePath", indicators.files);

    addString(data, "fileName", indicators.files);
}

void IndicatorExtractor::extractProcess(const EvidenceNode& node,
                                        Indicators& indicators) {
    const auto& data = getEvidenceData(node);

    /*
     * Process identity is normalized to the
     * executable filename.
     *
     * C:\Windows\System32\cmd.exe
     *              ↓
     *           cmd.exe
     *
     * This allows Windows Security process
     * telemetry to correlate with network
     * telemetry that may only contain cmd.exe.
     */
    if (data.contains("processName") && data["processName"].is_string()) {
        const std::string process =
            normalizeProcessName(data["processName"].get<std::string>());

        addUnique(indicators.processes, process);
    }

    /*
     * Keep the complete process path as a
     * file/path indicator.
     */
    addString(data, "processPath", indicators.files);

    /*
     * Do NOT add parentProcessName to the
     * process identity index.
     *
     * Parent-child relationships should be
     * analyzed separately by ProcessTreeRule.
     */

    addString(data, "username", indicators.users);
}

void IndicatorExtractor::extractNetwork(const EvidenceNode& node,
                                        Indicators& indicators) {
    const auto& data = getEvidenceData(node);

    addString(data, "localIp", indicators.ips);

    addString(data, "remoteIp", indicators.ips);

    /*
     * Normalize network process names in the
     * exact same way as Windows process events.
     */
    if (data.contains("processName") && data["processName"].is_string()) {
        const std::string process =
            normalizeProcessName(data["processName"].get<std::string>());

        addUnique(indicators.processes, process);
    }
}

void IndicatorExtractor::extractFile(const EvidenceNode& node,
                                     Indicators& indicators) {
    const auto& data = getEvidenceData(node);

    addString(data, "filePath", indicators.files);

    addString(data, "fileName", indicators.files);

    addString(data, "sha256", indicators.hashes);
}

void IndicatorExtractor::extractEventLog(const EvidenceNode& node,
                                         Indicators& indicators) {
    const auto& data = getEvidenceData(node);

    if (data.contains("computer") && data["computer"].is_string()) {
        addUnique(indicators.hosts, data["computer"].get<std::string>());
    }
}