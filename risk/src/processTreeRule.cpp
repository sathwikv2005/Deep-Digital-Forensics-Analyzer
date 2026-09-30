#include "processTreeRule.h"

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

std::string executableName(const std::string& process) {
    std::string value = lower(process);

    const size_t slash = value.find_last_of("\\/");

    if (slash != std::string::npos) value = value.substr(slash + 1);

    return value;
}

void addUnique(std::vector<std::string>& values, const std::string& value) {
    if (value.empty()) return;

    if (std::find(values.begin(), values.end(), value) == values.end()) {
        values.push_back(value);
    }
}

}  // namespace

std::vector<RiskSignal> ProcessTreeRule::evaluate(
    const RiskContext& context) const {
    std::vector<RiskSignal> signals;

    for (const auto& activity : context.activities) {
        if (activity.parentProcesses.empty() || activity.processes.empty()) {
            continue;
        }

        double bestScore = 0.0;

        std::string bestParent;
        std::string bestChild;

        for (const auto& parent : activity.parentProcesses) {
            for (const auto& child : activity.processes) {
                const double score =
                    BehaviorScorer::processTreeScore(parent, child);

                if (score > bestScore) {
                    bestScore = score;
                    bestParent = parent;
                    bestChild = child;
                }
            }
        }

        if (bestScore <= 0.0) continue;

        RiskSignal signal;

        signal.correlationId = activity.id;

        signal.type = "PROCESS_SPAWN";

        signal.score = bestScore;

        signal.confidence = 0.80;

        signal.startTime = activity.startTime;

        signal.endTime = activity.endTime;

        signal.eventIds = activity.eventIds;

        signal.sources = activity.sources;

        signal.indicators = activity.indicators;

        addUnique(signal.indicators, "parent:" + bestParent);

        addUnique(signal.indicators, "child:" + bestChild);

        const std::string childName = executableName(bestChild);

        if (childName == "cmd.exe" || childName == "powershell.exe" ||
            childName == "pwsh.exe") {
            signal.reasons.push_back(
                "A process spawned a command or "
                "script interpreter.");
        } else {
            signal.reasons.push_back(
                "A process spawned an execution "
                "proxy or scripting interpreter.");
        }

        if (activity.networkEvents > 0) {
            signal.score += 15.0;

            signal.reasons.push_back(
                "The spawned execution activity "
                "is associated with network communication.");

            signal.confidence = 0.90;
        }

        if (activity.downloadEvents > 0) {
            signal.score += 15.0;

            signal.reasons.push_back(
                "The process activity is associated "
                "with download activity.");
        }

        signals.push_back(std::move(signal));
    }

    return signals;
}

std::string ProcessTreeRule::name() const { return "ProcessTreeRule"; }