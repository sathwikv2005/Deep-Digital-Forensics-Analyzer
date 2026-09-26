#include "correlationRule.h"

#include <algorithm>
#include <cmath>

#include "indicatorExtractor.h"

TemporalRule::TemporalRule(uint64_t windowMs) : windowMs(windowMs) {}

bool TemporalRule::matches(const EvidenceNode& first,
                           const EvidenceNode& second) const {
    uint64_t difference;

    if (first.timestampMs > second.timestampMs) {
        difference = first.timestampMs - second.timestampMs;
    } else {
        difference = second.timestampMs - first.timestampMs;
    }

    return difference <= windowMs;
}

Correlation TemporalRule::evaluate(const EvidenceNode& first,
                                   const EvidenceNode& second) const {
    Correlation result;

    result.type = name();
    result.severity = "INFO";

    result.startTime = std::min(first.timestampMs, second.timestampMs);

    result.endTime = std::max(first.timestampMs, second.timestampMs);

    result.eventIds = {first.id, second.id};

    uint64_t difference = result.endTime - result.startTime;

    result.confidence =
        1.0 - (static_cast<double>(difference) / static_cast<double>(windowMs));

    result.confidence = std::clamp(result.confidence, 0.0, 1.0);

    result.reason = "Events occurred within " + std::to_string(difference) +
                    " milliseconds of each other.";

    return result;
}

std::string TemporalRule::name() const { return "TEMPORAL_SEQUENCE"; }

bool EntityRule::matches(const EvidenceNode& first,
                         const EvidenceNode& second) const {
    Indicators a = IndicatorExtractor::extract(first);

    Indicators b = IndicatorExtractor::extract(second);

    auto shared = [](const auto& firstValues, const auto& secondValues) {
        for (const auto& firstValue : firstValues) {
            for (const auto& secondValue : secondValues) {
                if (firstValue == secondValue) {
                    return true;
                }
            }
        }

        return false;
    };

    return shared(a.domains, b.domains) || shared(a.ips, b.ips) ||
           shared(a.files, b.files) || shared(a.processes, b.processes) ||
           shared(a.hashes, b.hashes);
}

Correlation EntityRule::evaluate(const EvidenceNode& first,
                                 const EvidenceNode& second) const {
    Correlation result;

    result.type = name();
    result.severity = "INFO";

    result.startTime = std::min(first.timestampMs, second.timestampMs);

    result.endTime = std::max(first.timestampMs, second.timestampMs);

    result.eventIds = {first.id, second.id};

    Indicators a = IndicatorExtractor::extract(first);

    Indicators b = IndicatorExtractor::extract(second);

    auto addShared = [&](const auto& firstValues, const auto& secondValues) {
        for (const auto& firstValue : firstValues) {
            for (const auto& secondValue : secondValues) {
                if (firstValue == secondValue) {
                    result.indicators.push_back(firstValue);
                }
            }
        }
    };

    addShared(a.domains, b.domains);
    addShared(a.ips, b.ips);
    addShared(a.files, b.files);
    addShared(a.processes, b.processes);
    addShared(a.hashes, b.hashes);

    result.confidence = 0.75;

    result.reason =
        "Events share one or more forensic "
        "indicators.";

    return result;
}

std::string EntityRule::name() const { return "SHARED_ENTITY"; }