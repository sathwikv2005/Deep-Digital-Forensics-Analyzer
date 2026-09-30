#include "networkRule.h"

#include <string>

std::vector<RiskSignal> NetworkRule::evaluate(
    const RiskContext& context) const {
    std::vector<RiskSignal> signals;

    for (const auto& activity : context.activities) {
        if (activity.networkEvents == 0) continue;

        RiskSignal signal;

        signal.correlationId = activity.id;

        signal.type = "NETWORK_ACTIVITY";

        if (activity.networkEvents >= 10)
            signal.score = 10.0;
        else if (activity.networkEvents >= 3)
            signal.score = 5.0;
        else
            signal.score = 2.0;

        signal.confidence = 0.6;

        signal.startTime = activity.startTime;

        signal.endTime = activity.endTime;

        signal.eventIds = activity.eventIds;

        signal.indicators = activity.indicators;

        signal.sources = activity.sources;

        signal.reasons.push_back(
            "Process activity is associated with network activity.");

        signals.push_back(std::move(signal));
    }

    return signals;
}

std::string NetworkRule::name() const { return "NetworkRule"; }