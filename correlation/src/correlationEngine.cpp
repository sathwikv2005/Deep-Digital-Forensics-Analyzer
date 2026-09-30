#include "correlationEngine.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iostream>
#include <unordered_map>
#include <unordered_set>

namespace {

constexpr uint64_t THIRTY_DAYS_MS = 30ULL * 24ULL * 60ULL * 60ULL * 1000ULL;

constexpr uint64_t MAX_TIME_DELTA = 30ULL * 60ULL * 1000ULL;

constexpr uint64_t BEHAVIOR_TIME_WINDOW = 60ULL * 1000ULL;

constexpr size_t MAX_INDEX_SIZE = 100;

constexpr size_t FILE_BURST_THRESHOLD = 5;

int findRoot(std::vector<int>& parent, int node) {
    if (parent[node] == node) {
        return node;
    }

    parent[node] = findRoot(parent, parent[node]);

    return parent[node];
}

void unite(std::vector<int>& parent,
           std::vector<std::unordered_set<std::string>>& componentIndicators,
           int a, int b) {
    int rootA = findRoot(parent, a);
    int rootB = findRoot(parent, b);

    if (rootA == rootB) {
        return;
    }

    parent[rootB] = rootA;

    componentIndicators[rootA].insert(componentIndicators[rootB].begin(),
                                      componentIndicators[rootB].end());

    componentIndicators[rootB].clear();
}

std::string normalizeSource(const std::string& source) {
    std::string result = source;

    std::transform(
        result.begin(), result.end(), result.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    return result;
}

std::string normalizeProcessName(std::string value) {
    std::transform(
        value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    size_t slash = value.find_last_of("\\/");

    if (slash != std::string::npos) {
        value = value.substr(slash + 1);
    }

    return value;
}

bool isProcessCategory(const std::string& category) {
    std::string value = category;

    std::transform(
        value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    return value == "process";
}

bool isNetworkCategory(const std::string& category) {
    std::string value = category;

    std::transform(
        value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    return value == "networkconnection" || value == "network";
}

bool isFileCategory(const std::string& category) {
    std::string value = category;

    std::transform(
        value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    return value == "file";
}

std::string getProcessName(const EvidenceNode& event) {
    if (!event.data.is_object()) {
        return "";
    }

    if (event.data.contains("data") && event.data["data"].is_object()) {
        const auto& data = event.data["data"];

        if (data.contains("processName")) {
            return data.value("processName", "");
        }

        if (data.contains("processPath")) {
            return data.value("processPath", "");
        }
    }

    if (event.data.contains("processName")) {
        return event.data.value("processName", "");
    }

    return "";
}

uint32_t getProcessId(const EvidenceNode& event) {
    if (!event.data.is_object()) {
        return 0;
    }

    if (event.data.contains("data") && event.data["data"].is_object()) {
        return event.data["data"].value("processId", 0U);
    }

    return event.data.value("processId", 0U);
}

uint32_t getParentProcessId(const EvidenceNode& event) {
    if (!event.data.is_object()) {
        return 0;
    }

    if (event.data.contains("data") && event.data["data"].is_object()) {
        return event.data["data"].value("parentProcessId", 0U);
    }

    return event.data.value("parentProcessId", 0U);
}

std::string getParentProcessName(const EvidenceNode& event) {
    if (!event.data.is_object()) {
        return "";
    }

    if (event.data.contains("data") && event.data["data"].is_object()) {
        return event.data["data"].value("parentProcessName", "");
    }

    return event.data.value("parentProcessName", "");
}

std::string getFilePath(const EvidenceNode& event) {
    if (!event.data.is_object()) {
        return "";
    }

    if (event.data.contains("data") && event.data["data"].is_object()) {
        return event.data["data"].value("filePath", "");
    }

    return event.data.value("filePath", "");
}

std::string getRemoteIp(const EvidenceNode& event) {
    if (!event.data.is_object()) {
        return "";
    }

    if (event.data.contains("data") && event.data["data"].is_object()) {
        return event.data["data"].value("remoteIp", "");
    }

    return event.data.value("remoteIp", "");
}

std::string getCategory(const EvidenceNode& event) {
    if (!event.category.empty()) {
        return event.category;
    }

    if (event.data.is_object()) {
        return event.data.value("category", "");
    }

    return "";
}

void addEventIds(Correlation& correlation, const std::vector<size_t>& indices,
                 const std::vector<EvidenceNode>& events) {
    std::unordered_set<std::string> seen;

    for (size_t index : indices) {
        const std::string& id = events[index].id;

        if (id.empty()) {
            continue;
        }

        if (seen.insert(id).second) {
            correlation.eventIds.push_back(id);
        }
    }
}

void addIndicator(Correlation& correlation, const std::string& indicator) {
    if (indicator.empty()) {
        return;
    }

    if (std::find(correlation.indicators.begin(), correlation.indicators.end(),
                  indicator) == correlation.indicators.end()) {
        correlation.indicators.push_back(indicator);
    }
}

void addSource(Correlation& correlation, const std::string& source) {
    if (source.empty()) {
        return;
    }

    std::string normalized = normalizeSource(source);

    for (const auto& existing : correlation.sources) {
        if (normalizeSource(existing) == normalized) {
            return;
        }
    }

    correlation.sources.push_back(source);
}

bool isSuspiciousProcessName(const std::string& processName) {
    std::string name = normalizeProcessName(processName);

    return name == "powershell.exe" || name == "pwsh.exe" ||
           name == "cmd.exe" || name == "wscript.exe" ||
           name == "cscript.exe" || name == "mshta.exe" ||
           name == "rundll32.exe" || name == "regsvr32.exe";
}

bool isShellProcess(const std::string& processName) {
    std::string name = normalizeProcessName(processName);

    return name == "powershell.exe" || name == "pwsh.exe" || name == "cmd.exe";
}

}  // namespace

CorrelationEngine::CorrelationEngine(const std::vector<EvidenceNode>& events)
    : events(events) {
    std::sort(this->events.begin(), this->events.end(),
              [](const EvidenceNode& a, const EvidenceNode& b) {
                  return a.timestampMs < b.timestampMs;
              });

    filterToRecentEvents();

    rules.push_back(std::make_unique<TemporalRule>(30 * 1000));

    rules.push_back(std::make_unique<EntityRule>());

    buildIndexes();
}

std::vector<Correlation> CorrelationEngine::analyze() { return runRules(); }

void CorrelationEngine::filterToRecentEvents() {
    if (events.empty()) {
        return;
    }

    uint64_t latestTimestamp = events.back().timestampMs;

    uint64_t cutoff =
        latestTimestamp > THIRTY_DAYS_MS ? latestTimestamp - THIRTY_DAYS_MS : 0;

    auto it =
        std::lower_bound(events.begin(), events.end(), cutoff,
                         [](const EvidenceNode& event, uint64_t timestamp) {
                             return event.timestampMs < timestamp;
                         });

    size_t removed = static_cast<size_t>(std::distance(events.begin(), it));

    events.erase(events.begin(), it);

    std::cout << "[Correlation] Evidence window: 30 days\n";

    std::cout << "[Correlation] Latest evidence: " << latestTimestamp << '\n';

    std::cout << "[Correlation] Events removed: " << removed << '\n';

    std::cout << "[Correlation] Events retained: " << events.size() << '\n';
}

void CorrelationEngine::buildIndexes() {
    if (events.empty()) {
        return;
    }

    std::cout << "[Correlation] Extracting indicators from " << events.size()
              << " events...\n";

    indicators.resize(events.size());

    int lastProgress = -1;

    for (size_t i = 0; i < events.size(); ++i) {
        indicators[i] = IndicatorExtractor::extract(events[i]);

        for (const auto& domain : indicators[i].domains) {
            addToIndex(domainIndex, domain, i);
        }

        for (const auto& ip : indicators[i].ips) {
            addToIndex(ipIndex, ip, i);
        }

        for (const auto& file : indicators[i].files) {
            addToIndex(fileIndex, file, i);
        }

        for (const auto& process : indicators[i].processes) {
            addToIndex(processIndex, process, i);
        }

        for (const auto& hash : indicators[i].hashes) {
            addToIndex(hashIndex, hash, i);
        }

        int progress = static_cast<int>(((i + 1) * 100) / events.size());

        if (progress != lastProgress && progress % 10 == 0) {
            std::cout << "[Correlation] Extraction: " << progress << "%\n";

            lastProgress = progress;
        }
    }

    std::cout << "[Correlation] Indicator extraction complete.\n";

    std::cout << "[Correlation] Index sizes: "
              << "domains=" << domainIndex.size() << ", ips=" << ipIndex.size()
              << ", files=" << fileIndex.size()
              << ", processes=" << processIndex.size()
              << ", hashes=" << hashIndex.size() << '\n';
}

void CorrelationEngine::addToIndex(
    std::unordered_map<std::string, std::vector<size_t>>& index,
    const std::string& key, size_t eventIndex) {
    if (key.empty()) {
        return;
    }

    index[key].push_back(eventIndex);
}

void CorrelationEngine::processIndicatorIndex(
    const std::unordered_map<std::string, std::vector<size_t>>& index,
    const std::string& indicatorType, std::vector<Correlation>& results) {
    if (index.empty()) {
        return;
    }

    std::cout << "[Correlation] Processing " << indicatorType << " index ("
              << index.size() << " indicators)...\n";

    size_t processedIndicators = 0;
    size_t skippedCommon = 0;
    size_t clusters = 0;

    int lastProgress = -1;

    for (const auto& [indicator, eventIndices] : index) {
        ++processedIndicators;

        int progress =
            static_cast<int>((processedIndicators * 100) / index.size());

        if (progress != lastProgress && progress % 10 == 0) {
            std::cout << "[Correlation] " << indicatorType << ": " << progress
                      << "% | correlations: " << results.size() << '\n';

            lastProgress = progress;
        }

        if (eventIndices.size() < 2) {
            continue;
        }

        if (eventIndices.size() > MAX_INDEX_SIZE) {
            ++skippedCommon;
            continue;
        }

        std::vector<size_t> cluster;

        uint64_t clusterStart = events[eventIndices[0]].timestampMs;

        uint64_t clusterEnd = clusterStart;

        for (size_t eventIndex : eventIndices) {
            const auto& event = events[eventIndex];

            if (event.timestampMs - clusterStart <= MAX_TIME_DELTA) {
                cluster.push_back(eventIndex);

                clusterEnd = event.timestampMs;

            } else {
                if (cluster.size() >= 2) {
                    Correlation correlation;

                    correlation.id =
                        "corr-" + std::to_string(results.size() + 1);

                    correlation.type = "ENTITY_CLUSTER";

                    correlation.severity = "INFO";

                    correlation.confidence = 0.75;

                    correlation.startTime = clusterStart;

                    correlation.endTime = clusterEnd;

                    addEventIds(correlation, cluster, events);

                    addIndicator(correlation, indicator);

                    correlation.reason =
                        "Multiple evidence events "
                        "reference the same " +
                        indicatorType +
                        " indicator within a "
                        "30-minute activity window.";

                    results.push_back(std::move(correlation));

                    ++clusters;
                }

                cluster.clear();

                cluster.push_back(eventIndex);

                clusterStart = event.timestampMs;

                clusterEnd = event.timestampMs;
            }
        }

        if (cluster.size() >= 2) {
            Correlation correlation;

            correlation.id = "corr-" + std::to_string(results.size() + 1);

            correlation.type = "ENTITY_CLUSTER";

            correlation.severity = "INFO";

            correlation.confidence = 0.75;

            correlation.startTime = clusterStart;

            correlation.endTime = clusterEnd;

            addEventIds(correlation, cluster, events);

            addIndicator(correlation, indicator);

            correlation.reason =
                "Multiple evidence events "
                "reference the same " +
                indicatorType +
                " indicator within a "
                "30-minute activity window.";

            results.push_back(std::move(correlation));

            ++clusters;
        }
    }

    std::cout << "[Correlation] Finished " << indicatorType
              << " index. Clusters: " << clusters
              << ", skipped common indicators: " << skippedCommon << '\n';
}

void CorrelationEngine::processCrossSourceIndex(
    const std::unordered_map<std::string, std::vector<size_t>>& index,
    const std::string& indicatorType, std::vector<int>& parent,
    std::vector<std::unordered_set<std::string>>& componentIndicators) {
    if (index.empty()) {
        return;
    }

    std::cout << "[Correlation] Cross-source processing " << indicatorType
              << " index (" << index.size() << " indicators)...\n";

    size_t processedIndicators = 0;
    size_t skippedCommon = 0;

    int lastProgress = -1;

    for (const auto& [indicator, eventIndices] : index) {
        ++processedIndicators;

        int progress =
            static_cast<int>((processedIndicators * 100) / index.size());

        if (progress != lastProgress && progress % 10 == 0) {
            std::cout << "[Correlation] Cross-source " << indicatorType << ": "
                      << progress << "%\n";

            lastProgress = progress;
        }

        if (eventIndices.size() < 2) {
            continue;
        }

        if (eventIndices.size() > MAX_INDEX_SIZE) {
            ++skippedCommon;
            continue;
        }

        for (size_t i = 0; i < eventIndices.size(); ++i) {
            size_t firstIndex = eventIndices[i];

            for (size_t j = i + 1; j < eventIndices.size(); ++j) {
                size_t secondIndex = eventIndices[j];

                uint64_t difference = events[secondIndex].timestampMs -
                                      events[firstIndex].timestampMs;

                if (difference > MAX_TIME_DELTA) {
                    break;
                }

                std::string firstSource =
                    normalizeSource(events[firstIndex].source);

                std::string secondSource =
                    normalizeSource(events[secondIndex].source);

                if (firstSource.empty() || secondSource.empty()) {
                    continue;
                }

                if (firstSource == secondSource) {
                    continue;
                }

                unite(parent, componentIndicators, static_cast<int>(firstIndex),
                      static_cast<int>(secondIndex));

                int root = findRoot(parent, static_cast<int>(firstIndex));

                componentIndicators[root].insert(indicatorType + ":" +
                                                 indicator);
            }
        }
    }

    std::cout << "[Correlation] Finished cross-source " << indicatorType
              << " index. Skipped common indicators: " << skippedCommon << '\n';
}

void CorrelationEngine::runCrossSourceCorrelations(
    std::vector<Correlation>& results) {
    if (events.empty()) {
        return;
    }

    std::cout << "[Correlation] Building cross-source "
                 "activity graph...\n";

    std::vector<int> parent(events.size());

    std::vector<std::unordered_set<std::string>> componentIndicators(
        events.size());

    for (size_t i = 0; i < events.size(); ++i) {
        parent[i] = static_cast<int>(i);
    }

    processCrossSourceIndex(domainIndex, "domain", parent, componentIndicators);

    processCrossSourceIndex(ipIndex, "IP", parent, componentIndicators);

    processCrossSourceIndex(fileIndex, "file", parent, componentIndicators);

    processCrossSourceIndex(processIndex, "process", parent,
                            componentIndicators);

    processCrossSourceIndex(hashIndex, "SHA256", parent, componentIndicators);

    std::unordered_map<int, std::vector<size_t>> components;

    for (size_t i = 0; i < events.size(); ++i) {
        int root = findRoot(parent, static_cast<int>(i));

        components[root].push_back(i);
    }

    size_t generated = 0;

    for (const auto& [root, eventIndices] : components) {
        if (eventIndices.size() < 2) {
            continue;
        }

        std::unordered_map<std::string, std::string> sources;

        for (size_t index : eventIndices) {
            std::string source = normalizeSource(events[index].source);

            if (!source.empty()) {
                sources[source] = events[index].source;
            }
        }

        if (sources.size() < 2) {
            continue;
        }

        uint64_t startTime = events[eventIndices.front()].timestampMs;

        uint64_t endTime = startTime;

        for (size_t index : eventIndices) {
            startTime = std::min(startTime, events[index].timestampMs);

            endTime = std::max(endTime, events[index].timestampMs);
        }

        Correlation correlation;

        correlation.id = "corr-" + std::to_string(results.size() + 1);

        correlation.type = "CROSS_SOURCE_ACTIVITY";

        correlation.severity = "INFO";

        if (sources.size() == 2) {
            correlation.confidence = 0.70;
        } else if (sources.size() == 3) {
            correlation.confidence = 0.80;
        } else {
            correlation.confidence = 0.85;
        }

        correlation.startTime = startTime;

        correlation.endTime = endTime;

        addEventIds(correlation, eventIndices, events);

        for (const auto& [normalized, original] : sources) {
            addSource(correlation, original);
        }

        for (const auto& indicator : componentIndicators[root]) {
            addIndicator(correlation, indicator);
        }

        std::sort(correlation.sources.begin(), correlation.sources.end());

        std::sort(correlation.indicators.begin(), correlation.indicators.end());

        correlation.reason =
            "Evidence from multiple sources "
            "forms a connected activity chain "
            "through shared forensic indicators "
            "within a 30-minute activity window.";

        results.push_back(std::move(correlation));

        ++generated;
    }

    std::cout << "[Correlation] Cross-source activities: " << generated << '\n';
}

static void generateProcessTreeCorrelations(
    const std::vector<EvidenceNode>& events,
    std::vector<Correlation>& results) {
    std::unordered_map<uint32_t, std::vector<size_t>> processesByPid;

    for (size_t i = 0; i < events.size(); ++i) {
        if (!isProcessCategory(getCategory(events[i]))) {
            continue;
        }

        uint32_t pid = getProcessId(events[i]);

        if (pid != 0) {
            processesByPid[pid].push_back(i);
        }
    }

    std::unordered_set<std::string> generatedChains;

    for (size_t i = 0; i < events.size(); ++i) {
        if (!isProcessCategory(getCategory(events[i]))) {
            continue;
        }

        uint32_t childPid = getProcessId(events[i]);

        uint32_t parentPid = getParentProcessId(events[i]);

        if (childPid == 0 || parentPid == 0) {
            continue;
        }

        auto parentIt = processesByPid.find(parentPid);

        if (parentIt == processesByPid.end()) {
            continue;
        }

        for (size_t parentIndex : parentIt->second) {
            if (events[parentIndex].timestampMs > events[i].timestampMs) {
                continue;
            }

            if (events[i].timestampMs - events[parentIndex].timestampMs >
                BEHAVIOR_TIME_WINDOW) {
                continue;
            }

            std::string parentName = getProcessName(events[parentIndex]);

            std::string childName = getProcessName(events[i]);

            std::string key =
                std::to_string(parentPid) + ":" + std::to_string(childPid);

            if (!generatedChains.insert(key).second) {
                continue;
            }

            Correlation correlation;

            correlation.id = "corr-" + std::to_string(results.size() + 1);

            correlation.type = "PROCESS_TREE";

            correlation.severity = "INFO";

            correlation.confidence = 0.85;

            correlation.startTime = events[parentIndex].timestampMs;

            correlation.endTime = events[i].timestampMs;

            correlation.eventIds.push_back(events[parentIndex].id);

            correlation.eventIds.push_back(events[i].id);

            addIndicator(correlation, parentName);

            addIndicator(correlation, childName);

            addIndicator(correlation,
                         "parent-pid:" + std::to_string(parentPid));

            addIndicator(correlation, "child-pid:" + std::to_string(childPid));

            addSource(correlation, events[parentIndex].source);

            addSource(correlation, events[i].source);

            correlation.reason =
                "A process was created by another "
                "process, forming a parent-child "
                "execution relationship.";

            results.push_back(std::move(correlation));
        }
    }
}

static void generateProcessNetworkCorrelations(
    const std::vector<EvidenceNode>& events,
    std::vector<Correlation>& results) {
    std::unordered_map<uint32_t, std::vector<size_t>> processEvents;

    std::unordered_map<uint32_t, std::vector<size_t>> networkEvents;

    for (size_t i = 0; i < events.size(); ++i) {
        if (isProcessCategory(getCategory(events[i]))) {
            uint32_t pid = getProcessId(events[i]);

            if (pid != 0) {
                processEvents[pid].push_back(i);
            }
        }

        if (isNetworkCategory(getCategory(events[i]))) {
            uint32_t pid = getProcessId(events[i]);

            if (pid != 0) {
                networkEvents[pid].push_back(i);
            }
        }
    }

    std::unordered_set<std::string> generated;

    for (const auto& [pid, networks] : networkEvents) {
        auto processIt = processEvents.find(pid);

        if (processIt == processEvents.end()) {
            continue;
        }

        for (size_t networkIndex : networks) {
            const auto& network = events[networkIndex];

            for (size_t processIndex : processIt->second) {
                const auto& process = events[processIndex];

                uint64_t difference =
                    network.timestampMs > process.timestampMs
                        ? network.timestampMs - process.timestampMs
                        : process.timestampMs - network.timestampMs;

                if (difference > BEHAVIOR_TIME_WINDOW) {
                    continue;
                }

                std::string processName = getProcessName(process);

                std::string remoteIp = getRemoteIp(network);

                std::string key = std::to_string(pid) + ":" + remoteIp;

                if (!generated.insert(key).second) {
                    continue;
                }

                Correlation correlation;

                correlation.id = "corr-" + std::to_string(results.size() + 1);

                correlation.type = "PROCESS_NETWORK";

                correlation.severity = "INFO";

                correlation.confidence = 0.88;

                correlation.startTime =
                    std::min(process.timestampMs, network.timestampMs);

                correlation.endTime =
                    std::max(process.timestampMs, network.timestampMs);

                correlation.eventIds.push_back(process.id);

                correlation.eventIds.push_back(network.id);

                addIndicator(correlation, processName);

                addIndicator(correlation, "pid:" + std::to_string(pid));

                addIndicator(correlation, remoteIp);

                addSource(correlation, process.source);

                addSource(correlation, network.source);

                correlation.reason =
                    "A network connection was "
                    "directly associated with the "
                    "process that generated it.";

                results.push_back(std::move(correlation));
            }
        }
    }
}

static void generateFileActivityCorrelations(
    const std::vector<EvidenceNode>& events,
    std::vector<Correlation>& results) {
    std::vector<size_t> fileEvents;

    for (size_t i = 0; i < events.size(); ++i) {
        if (isFileCategory(getCategory(events[i]))) {
            fileEvents.push_back(i);
        }
    }

    if (fileEvents.size() < FILE_BURST_THRESHOLD) {
        return;
    }

    size_t start = 0;

    while (start < fileEvents.size()) {
        size_t end = start;

        uint64_t startTime = events[fileEvents[start]].timestampMs;

        while (end + 1 < fileEvents.size()) {
            uint64_t nextTime = events[fileEvents[end + 1]].timestampMs;

            if (nextTime - startTime > BEHAVIOR_TIME_WINDOW) {
                break;
            }

            ++end;
        }

        size_t count = end - start + 1;

        if (count >= FILE_BURST_THRESHOLD) {
            std::vector<size_t> cluster;

            for (size_t i = start; i <= end; ++i) {
                cluster.push_back(fileEvents[i]);
            }

            Correlation correlation;

            correlation.id = "corr-" + std::to_string(results.size() + 1);

            correlation.type = "FILE_ACTIVITY";

            correlation.severity = "INFO";

            correlation.confidence = 0.82;

            correlation.startTime = events[fileEvents[start]].timestampMs;

            correlation.endTime = events[fileEvents[end]].timestampMs;

            addEventIds(correlation, cluster, events);

            addIndicator(correlation, "file-count:" + std::to_string(count));

            addSource(correlation, events[fileEvents[start]].source);

            correlation.reason =
                "A burst of multiple file "
                "activities was observed within "
                "a short activity window.";

            results.push_back(std::move(correlation));
        }

        start = end + 1;
    }
}

static void generateSuspiciousActivityChains(
    const std::vector<EvidenceNode>& events,
    std::vector<Correlation>& results) {
    std::vector<size_t> processEvents;
    std::vector<size_t> networkEvents;
    std::vector<size_t> fileEvents;

    for (size_t i = 0; i < events.size(); ++i) {
        std::string category = getCategory(events[i]);

        if (isProcessCategory(category)) {
            processEvents.push_back(i);
        } else if (isNetworkCategory(category)) {
            networkEvents.push_back(i);
        } else if (isFileCategory(category)) {
            fileEvents.push_back(i);
        }
    }

    for (size_t processIndex : processEvents) {
        std::string processName = getProcessName(events[processIndex]);

        if (!isSuspiciousProcessName(processName)) {
            continue;
        }

        uint32_t pid = getProcessId(events[processIndex]);

        if (pid == 0) {
            continue;
        }

        bool hasNetwork = false;
        bool hasFiles = false;

        std::vector<size_t> relatedEvents;

        relatedEvents.push_back(processIndex);

        std::string remoteIp;

        for (size_t networkIndex : networkEvents) {
            uint32_t networkPid = getProcessId(events[networkIndex]);

            if (networkPid != pid) {
                continue;
            }

            uint64_t difference = events[networkIndex].timestampMs >
                                          events[processIndex].timestampMs
                                      ? events[networkIndex].timestampMs -
                                            events[processIndex].timestampMs
                                      : events[processIndex].timestampMs -
                                            events[networkIndex].timestampMs;

            if (difference > BEHAVIOR_TIME_WINDOW) {
                continue;
            }

            hasNetwork = true;

            relatedEvents.push_back(networkIndex);

            remoteIp = getRemoteIp(events[networkIndex]);

            break;
        }

        for (size_t fileIndex : fileEvents) {
            uint64_t difference =
                events[fileIndex].timestampMs > events[processIndex].timestampMs
                    ? events[fileIndex].timestampMs -
                          events[processIndex].timestampMs
                    : events[processIndex].timestampMs -
                          events[fileIndex].timestampMs;

            if (difference > BEHAVIOR_TIME_WINDOW) {
                continue;
            }

            hasFiles = true;

            relatedEvents.push_back(fileIndex);

            if (relatedEvents.size() >= 8) {
                break;
            }
        }

        if (!hasNetwork && !hasFiles) {
            continue;
        }

        Correlation correlation;

        correlation.id = "corr-" + std::to_string(results.size() + 1);

        correlation.type = "SUSPICIOUS_ACTIVITY_CHAIN";

        correlation.severity = "HIGH";

        double confidence = 0.75;

        if (hasNetwork) {
            confidence += 0.10;
        }

        if (hasFiles) {
            confidence += 0.10;
        }

        correlation.confidence = std::min(confidence, 0.95);

        correlation.startTime = events[processIndex].timestampMs;

        correlation.endTime = correlation.startTime;

        for (size_t index : relatedEvents) {
            correlation.startTime =
                std::min(correlation.startTime, events[index].timestampMs);

            correlation.endTime =
                std::max(correlation.endTime, events[index].timestampMs);
        }

        addEventIds(correlation, relatedEvents, events);

        addIndicator(correlation, processName);

        addIndicator(correlation, "pid:" + std::to_string(pid));

        if (!remoteIp.empty()) {
            addIndicator(correlation, remoteIp);
        }

        if (hasNetwork) {
            correlation.reason =
                "A shell or script-capable process "
                "was associated with network activity.";

            if (hasFiles) {
                correlation.reason +=
                    " The same activity window also "
                    "contained file activity.";
            }
        } else {
            correlation.reason =
                "A shell or script-capable process "
                "was associated with file activity.";
        }

        addSource(correlation, events[processIndex].source);

        for (size_t index : relatedEvents) {
            addSource(correlation, events[index].source);
        }

        results.push_back(std::move(correlation));
    }
}

std::vector<Correlation> CorrelationEngine::runRules() {
    std::vector<Correlation> results;

    processIndicatorIndex(domainIndex, "domain", results);

    processIndicatorIndex(ipIndex, "IP", results);

    processIndicatorIndex(fileIndex, "file", results);

    processIndicatorIndex(processIndex, "process", results);

    processIndicatorIndex(hashIndex, "SHA256", results);

    size_t beforeCrossSource = results.size();

    runCrossSourceCorrelations(results);

    size_t afterCrossSource = results.size();

    size_t beforeProcessTree = results.size();

    generateProcessTreeCorrelations(events, results);

    size_t processTreeGenerated = results.size() - beforeProcessTree;

    size_t beforeProcessNetwork = results.size();

    generateProcessNetworkCorrelations(events, results);

    size_t processNetworkGenerated = results.size() - beforeProcessNetwork;

    size_t beforeFileActivity = results.size();

    generateFileActivityCorrelations(events, results);

    size_t fileActivityGenerated = results.size() - beforeFileActivity;

    size_t beforeSuspicious = results.size();

    generateSuspiciousActivityChains(events, results);

    size_t suspiciousGenerated = results.size() - beforeSuspicious;

    std::cout << "[Correlation] Entity correlations: " << beforeCrossSource
              << '\n';

    std::cout << "[Correlation] Cross-source correlations: "
              << afterCrossSource - beforeCrossSource << '\n';

    std::cout << "[Correlation] Process tree correlations: "
              << processTreeGenerated << '\n';

    std::cout << "[Correlation] Process-network correlations: "
              << processNetworkGenerated << '\n';

    std::cout << "[Correlation] File activity correlations: "
              << fileActivityGenerated << '\n';

    std::cout << "[Correlation] Suspicious activity chains: "
              << suspiciousGenerated << '\n';

    std::cout << "[Correlation] Total correlations: " << results.size() << '\n';

    return results;
}