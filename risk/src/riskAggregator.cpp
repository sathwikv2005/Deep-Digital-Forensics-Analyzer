#include "riskAggregator.h"

#include <algorithm>
#include <map>
#include <string>

#include "riskScorer.h"

std::vector<RiskFinding> RiskAggregator::aggregate(
    const RiskContext& context, const std::vector<RiskSignal>& signals) const {
    std::map<std::string, RiskFinding> grouped;

    for (const auto& signal : signals) {
        std::string key = signal.correlationId;

        if (key.empty()) continue;

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
            if (std::find(finding.eventIds.begin(), finding.eventIds.end(),
                          eventId) == finding.eventIds.end()) {
                finding.eventIds.push_back(eventId);
            }
        }

        for (const auto& indicator : signal.indicators) {
            if (std::find(finding.indicators.begin(), finding.indicators.end(),
                          indicator) == finding.indicators.end()) {
                finding.indicators.push_back(indicator);
            }
        }

        for (const auto& source : signal.sources) {
            if (std::find(finding.sources.begin(), finding.sources.end(),
                          source) == finding.sources.end()) {
                finding.sources.push_back(source);
            }
        }

        for (const auto& reason : signal.reasons) {
            if (std::find(finding.reasons.begin(), finding.reasons.end(),
                          reason) == finding.reasons.end()) {
                finding.reasons.push_back(reason);
            }
        }
    }

    std::vector<RiskFinding> findings;

    for (auto& [key, finding] : grouped) {
        finding.score = std::min(100.0, finding.score);

        finding.severity = RiskScorer::severity(finding.score);

        findings.push_back(std::move(finding));
    }

    return findings;
}