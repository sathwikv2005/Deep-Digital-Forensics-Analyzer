#include "correlationEngine.h"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <unordered_set>

#include "indicatorExtractor.h"

namespace {

constexpr uint64_t THIRTY_DAYS_MS = 30ULL * 24ULL * 60ULL * 60ULL * 1000ULL;

constexpr uint64_t MAX_TIME_DELTA = 30ULL * 60ULL * 1000ULL;

constexpr size_t MAX_INDEX_SIZE = 100;

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
    if (events.empty()) return;

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
    std::cout << "[Correlation] Extracting indicators from " << events.size()
              << " events...\n";

    indicators.resize(events.size());

    int lastProgress = -1;

    for (size_t i = 0; i < events.size(); ++i) {
        indicators[i] = IndicatorExtractor::extract(events[i]);

        for (const auto& domain : indicators[i].domains)
            addToIndex(domainIndex, domain, i);

        for (const auto& ip : indicators[i].ips) addToIndex(ipIndex, ip, i);

        for (const auto& file : indicators[i].files)
            addToIndex(fileIndex, file, i);

        for (const auto& process : indicators[i].processes)
            addToIndex(processIndex, process, i);

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
              << ", processes=" << processIndex.size() << '\n';
}

void CorrelationEngine::addToIndex(
    std::unordered_map<std::string, std::vector<size_t>>& index,
    const std::string& key, size_t eventIndex) {
    index[key].push_back(eventIndex);
}

void CorrelationEngine::processIndicatorIndex(
    const std::unordered_map<std::string, std::vector<size_t>>& index,
    const std::string& indicatorType, std::vector<Correlation>& results) {
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

        if (eventIndices.size() < 2) continue;

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

                    for (size_t index : cluster)
                        correlation.eventIds.push_back(events[index].id);

                    correlation.indicators.push_back(indicator);

                    correlation.reason =
                        "Multiple evidence events reference "
                        "the same " +
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

            for (size_t index : cluster)
                correlation.eventIds.push_back(events[index].id);

            correlation.indicators.push_back(indicator);

            correlation.reason =
                "Multiple evidence events reference "
                "the same " +
                indicatorType +
                " indicator within a "
                "30-minute activity window.";

            results.push_back(std::move(correlation));

            ++clusters;
        }
    }

    std::cout << "[Correlation] Finished " << indicatorType << " index. "
              << "Clusters: " << clusters
              << ", skipped common indicators: " << skippedCommon << '\n';
}

std::vector<Correlation> CorrelationEngine::runRules() {
    std::vector<Correlation> results;

    processIndicatorIndex(domainIndex, "domain", results);

    processIndicatorIndex(ipIndex, "IP", results);

    processIndicatorIndex(fileIndex, "file", results);

    processIndicatorIndex(processIndex, "process", results);

    std::cout << "[Correlation] Total correlations: " << results.size() << '\n';

    return results;
}