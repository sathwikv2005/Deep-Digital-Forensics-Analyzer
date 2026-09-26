#include "correlationEngine.h"

#include <algorithm>
#include <memory>

#include "indicatorExtractor.h"

CorrelationEngine::CorrelationEngine(const std::vector<EvidenceNode>& events)
    : events(events) {
    rules.push_back(std::make_unique<TemporalRule>(30 * 1000));

    rules.push_back(std::make_unique<EntityRule>());

    std::sort(this->events.begin(), this->events.end(),
              [](const EvidenceNode& a, const EvidenceNode& b) {
                  return a.timestampMs < b.timestampMs;
              });

    buildIndexes();
}

std::vector<Correlation> CorrelationEngine::analyze() { return runRules(); }

void CorrelationEngine::buildIndexes() {
    for (size_t i = 0; i < events.size(); ++i) {
        Indicators indicators = IndicatorExtractor::extract(events[i]);

        for (const auto& domain : indicators.domains)
            addToIndex(domainIndex, domain, i);

        for (const auto& ip : indicators.ips) addToIndex(ipIndex, ip, i);

        for (const auto& file : indicators.files)
            addToIndex(fileIndex, file, i);

        for (const auto& process : indicators.processes)
            addToIndex(processIndex, process, i);
    }
}

void CorrelationEngine::addToIndex(
    std::unordered_map<std::string, std::vector<size_t>>& index,
    const std::string& key, size_t eventIndex) {
    index[key].push_back(eventIndex);
}

std::vector<Correlation> CorrelationEngine::runRules() {
    std::vector<Correlation> results;

    for (size_t i = 0; i < events.size(); ++i) {
        for (size_t j = i + 1; j < events.size(); ++j) {
            for (const auto& rule : rules) {
                if (!rule->matches(events[i], events[j])) continue;

                Correlation correlation = rule->evaluate(events[i], events[j]);

                correlation.id = "corr-" + std::to_string(results.size() + 1);

                results.push_back(std::move(correlation));
            }
        }
    }

    return results;
}