#include "networkRule.h"

#include <string>

std::vector<RiskSignal> NetworkRule::evaluate(
    const RiskContext& context) const {
    std::vector<RiskSignal> signals;

    if (!context.correlations.is_array()) return signals;

    for (const auto& correlation : context.correlations) {
        if (correlation.value("type", "") != "CROSS_SOURCE_ACTIVITY") continue;

        const auto eventIds =
            correlation.value("eventIds", std::vector<std::string>{});

        const auto sources =
            correlation.value("sources", std::vector<std::string>{});

        bool hasNetworkSource = false;

        for (const auto& source : sources) {
            if (source == "Windows Network") {
                hasNetworkSource = true;
                break;
            }
        }

        if (!hasNetworkSource) continue;

        RiskSignal signal;

        signal.correlationId = correlation.value("id", "");

        signal.type = "NETWORK_ACTIVITY";

        signal.score = eventIds.size() >= 5 ? 15.0 : 10.0;

        signal.confidence = 0.6;

        signal.startTime = correlation.value("startTime", 0LL);

        signal.endTime = correlation.value("endTime", 0LL);

        signal.eventIds = eventIds;

        signal.indicators =
            correlation.value("indicators", std::vector<std::string>{});

        signal.sources = sources;

        signal.reasons.push_back(
            "Process activity is associated with network activity.");

        signals.push_back(std::move(signal));
    }

    return signals;
}

std::string NetworkRule::name() const { return "NetworkRule"; }