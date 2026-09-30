#include "crossSourceRiskRule.h"

#include <string>

namespace {

std::string getSeverity(double score) {
    if (score >= 80.0) return "CRITICAL";

    if (score >= 60.0) return "HIGH";

    if (score >= 40.0) return "MEDIUM";

    if (score >= 20.0) return "LOW";

    return "INFO";
}

}  // namespace

std::vector<RiskFinding> CrossSourceRiskRule::evaluate(
    const RiskContext& context) const {
    std::vector<RiskFinding> findings;

    if (!context.correlations.is_array()) return findings;

    for (const auto& correlation : context.correlations) {
        if (correlation.value("type", "") != "CROSS_SOURCE_ACTIVITY") continue;

        RiskFinding finding;

        finding.id = "risk-" + correlation.value("id", "unknown");

        finding.type = "CROSS_SOURCE_ACTIVITY";

        finding.score = 20.0;
        finding.confidence = 0.5;

        finding.startTime = correlation.value("startTime", 0LL);

        finding.endTime = correlation.value("endTime", 0LL);

        finding.eventIds =
            correlation.value("eventIds", std::vector<std::string>{});

        finding.indicators =
            correlation.value("indicators", std::vector<std::string>{});

        finding.sources =
            correlation.value("sources", std::vector<std::string>{});

        finding.reasons.push_back(
            "Evidence from multiple forensic sources is connected.");

        if (finding.sources.size() >= 2) {
            finding.score += 5.0;

            finding.reasons.push_back(
                "Activity is present across multiple evidence sources.");
        }

        finding.severity = getSeverity(finding.score);

        findings.push_back(std::move(finding));
    }

    return findings;
}

std::string CrossSourceRiskRule::name() const { return "CrossSourceRiskRule"; }