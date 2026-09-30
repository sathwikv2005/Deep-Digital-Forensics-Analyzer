#include "riskAggregator.h"

#include <algorithm>
#include <map>
#include <string>

#include "riskScorer.h"

namespace {

void addUnique(std::vector<std::string>& values, const std::string& value) {
    if (value.empty()) return;

    if (std::find(values.begin(), values.end(), value) == values.end()) {
        values.push_back(value);
    }
}

}  // namespace

std::vector<RiskFinding> RiskAggregator::aggregate(
    const RiskContext& context, const std::vector<RiskSignal>& signals) const {
    std::map<std::string, RiskFinding> grouped;

    for (const auto& signal : signals) {
        if (signal.correlationId.empty()) continue;

        const std::string& key = signal.correlationId;

        auto& finding = grouped[key];

        if (finding.id.empty()) {
            finding.id = "risk-" + key;

            finding.type = "BEHAVIORAL_ACTIVITY";
        }

        finding.score += signal.score;

        finding.confidence = std::max(finding.confidence, signal.confidence);

        if (finding.startTime == 0 || signal.startTime < finding.startTime) {
            finding.startTime = signal.startTime;
        }

        if (signal.endTime > finding.endTime) {
            finding.endTime = signal.endTime;
        }

        for (const auto& eventId : signal.eventIds) {
            addUnique(finding.eventIds, eventId);
        }

        for (const auto& indicator : signal.indicators) {
            addUnique(finding.indicators, indicator);
        }

        for (const auto& source : signal.sources) {
            addUnique(finding.sources, source);
        }

        for (const auto& reason : signal.reasons) {
            addUnique(finding.reasons, reason);
        }
    }

    std::vector<RiskFinding> findings;

    for (auto& [key, finding] : grouped) {
        finding.score = std::min(100.0, finding.score);

        finding.severity = RiskScorer::severity(finding.score);

        findings.push_back(std::move(finding));
    }

    std::sort(findings.begin(), findings.end(),
              [](const RiskFinding& a, const RiskFinding& b) {
                  if (a.score != b.score) return a.score > b.score;

                  return a.startTime < b.startTime;
              });

    return findings;
}