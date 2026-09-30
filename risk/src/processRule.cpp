#include "processRule.h"

#include <algorithm>
#include <cctype>
#include <string>

#include "behaviorScorer.h"

namespace {

std::string lower(std::string value) {
    std::transform(
        value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    return value;
}

}  // namespace

std::vector<RiskSignal> ProcessRule::evaluate(
    const RiskContext& context) const {
    std::vector<RiskSignal> signals;

    for (const auto& activity : context.activities) {
        double bestProcessScore = 0.0;
        std::string bestProcess;

        for (const auto& process : activity.processes) {
            const double score = BehaviorScorer::processScore(process);

            if (score > bestProcessScore) {
                bestProcessScore = score;
                bestProcess = process;
            }
        }

        double bestPathScore = 0.0;
        std::string bestPath;

        for (const auto& path : activity.paths) {
            const double score = BehaviorScorer::pathScore(path);

            if (score > bestPathScore) {
                bestPathScore = score;
                bestPath = path;
            }
        }

        const double networkScore =
            BehaviorScorer::networkScore(activity.networkEvents);

        const bool suspiciousProcess = bestProcessScore > 0.0;

        const bool suspiciousPath = bestPathScore > 0.0;

        const bool networkActivity = activity.networkEvents > 0;

        const bool downloadActivity = activity.downloadEvents > 0;

        const double combinationScore =
            BehaviorScorer::combinationBonus(suspiciousProcess, suspiciousPath,
                                             networkActivity, downloadActivity);

        const double totalScore =
            bestProcessScore + bestPathScore + networkScore + combinationScore;

        if (totalScore <= 0.0) continue;

        RiskSignal signal;

        signal.correlationId = activity.id;

        signal.type = "BEHAVIORAL_ACTIVITY";

        signal.score = totalScore;

        signal.confidence = 0.75;

        if (suspiciousProcess) signal.confidence = 0.85;

        if (suspiciousProcess && networkActivity) signal.confidence = 0.90;

        signal.startTime = activity.startTime;

        signal.endTime = activity.endTime;

        signal.eventIds = activity.eventIds;

        signal.sources = activity.sources;

        signal.indicators = activity.indicators;

        if (suspiciousProcess) {
            signal.indicators.push_back("process:" + bestProcess);

            if (bestProcessScore >= 35.0) {
                signal.reasons.push_back(
                    "Process is capable of "
                    "script, command, or proxy execution.");
            } else {
                signal.reasons.push_back(
                    "Process can execute "
                    "application-controlled code.");
            }
        }

        if (suspiciousPath) {
            signal.indicators.push_back("path:" + bestPath);

            signal.reasons.push_back(
                "Executable or file activity originated "
                "from a user-writable application data "
                "or temporary location.");
        }

        if (networkActivity) {
            signal.reasons.push_back(
                "Process activity is associated "
                "with network activity.");
        }

        if (downloadActivity) {
            signal.reasons.push_back(
                "Browser or application download "
                "activity is associated with this activity.");
        }

        if (suspiciousProcess && networkActivity) {
            signal.reasons.push_back(
                "Suspicious process activity is "
                "associated with network communication.");
        }

        if (suspiciousProcess && suspiciousPath) {
            signal.reasons.push_back(
                "Suspicious process execution is "
                "associated with a user-writable path.");
        }

        if (downloadActivity && suspiciousProcess) {
            signal.reasons.push_back(
                "A potentially executable process "
                "is associated with download activity.");
        }

        signals.push_back(std::move(signal));
    }

    return signals;
}

std::string ProcessRule::name() const { return "ProcessRule"; }