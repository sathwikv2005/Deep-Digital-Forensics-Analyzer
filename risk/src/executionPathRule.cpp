#include "executionPathRule.h"

#include <algorithm>
#include <cctype>
#include <string>

#include "behaviorScorer.h"

std::vector<RiskSignal> ExecutionPathRule::evaluate(
    const RiskContext& context) const {
    std::vector<RiskSignal> signals;

    for (const auto& activity : context.activities) {
        double bestScore = 0.0;
        std::string bestPath;

        for (const auto& path : activity.paths) {
            const double score = BehaviorScorer::pathScore(path);

            if (score > bestScore) {
                bestScore = score;
                bestPath = path;
            }
        }

        if (bestScore <= 0.0) continue;

        RiskSignal signal;

        signal.correlationId = activity.id;

        signal.type = "EXECUTION_PATH";

        signal.score = bestScore;

        signal.confidence = 0.75;

        signal.startTime = activity.startTime;

        signal.endTime = activity.endTime;

        signal.eventIds = activity.eventIds;

        signal.sources = activity.sources;

        signal.indicators.push_back("path:" + bestPath);

        signal.reasons.push_back(
            "Executable or file activity originated "
            "from a user-writable application data "
            "or temporary location.");

        signals.push_back(std::move(signal));
    }

    return signals;
}

std::string ExecutionPathRule::name() const { return "ExecutionPathRule"; }