#include "networkRule.h"

#include "behaviorScorer.h"

std::vector<RiskSignal> NetworkRule::evaluate(
    const RiskContext& context) const {
    std::vector<RiskSignal> signals;

    for (const auto& activity : context.activities) {
        if (activity.networkEvents == 0) continue;

        RiskSignal signal;

        signal.correlationId = activity.id;

        signal.type = "NETWORK_ACTIVITY";

        signal.score = BehaviorScorer::networkScore(activity.networkEvents);

        signal.confidence = 0.60;

        signal.startTime = activity.startTime;

        signal.endTime = activity.endTime;

        signal.eventIds = activity.eventIds;

        signal.indicators = activity.indicators;

        signal.sources = activity.sources;

        signal.reasons.push_back(
            "Process activity is associated "
            "with network activity.");

        if (activity.networkEvents >= 10) {
            signal.reasons.push_back(
                "Multiple network events were observed "
                "within the correlated activity.");
        }

        signals.push_back(std::move(signal));
    }

    return signals;
}

std::string NetworkRule::name() const { return "NetworkRule"; }