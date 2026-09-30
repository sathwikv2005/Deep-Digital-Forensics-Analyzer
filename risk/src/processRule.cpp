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

void addUnique(std::vector<std::string>& values, const std::string& value) {
    if (value.empty()) return;

    if (std::find(values.begin(), values.end(), value) == values.end()) {
        values.push_back(value);
    }
}

}  // namespace

std::vector<RiskSignal> ProcessRule::evaluate(
    const RiskContext& context) const {
    std::vector<RiskSignal> signals;

    for (const auto& activity : context.activities) {
        double processScore = 0.0;

        std::string bestProcess;

        for (const auto& process : activity.processes) {
            const double score = BehaviorScorer::processScore(process);

            if (score > processScore) {
                processScore = score;
                bestProcess = process;
            }
        }

        double pathScore = 0.0;

        std::string bestPath;

        for (const auto& path : activity.paths) {
            const double score = BehaviorScorer::pathScore(path);

            if (score > pathScore) {
                pathScore = score;
                bestPath = path;
            }
        }

        const bool suspiciousProcess = processScore > 0.0;

        const bool suspiciousPath = pathScore > 0.0;

        const bool networkActivity = activity.networkEvents > 0;

        const bool downloadActivity = activity.downloadEvents > 0;

        const double networkScore =
            BehaviorScorer::networkScore(activity.networkEvents);

        const double combinationScore =
            BehaviorScorer::combinationBonus(suspiciousProcess, suspiciousPath,
                                             networkActivity, downloadActivity);

        double crossSourceScore = 0.0;

        if (activity.sources.size() >= 2) crossSourceScore = 5.0;

        const double totalScore = processScore + pathScore + networkScore +
                                  combinationScore + crossSourceScore;

        if (totalScore <= 0.0) continue;

        RiskSignal signal;

        signal.correlationId = activity.id;

        signal.type = "BEHAVIORAL_ACTIVITY";

        signal.score = totalScore;

        signal.confidence = 0.65;

        if (suspiciousProcess) signal.confidence = 0.75;

        if (suspiciousProcess && networkActivity) {
            signal.confidence = 0.85;
        }

        if (suspiciousProcess && suspiciousPath && networkActivity) {
            signal.confidence = 0.90;
        }

        signal.startTime = activity.startTime;

        signal.endTime = activity.endTime;

        signal.eventIds = activity.eventIds;

        signal.sources = activity.sources;

        signal.indicators = activity.indicators;

        if (!bestProcess.empty()) {
            addUnique(signal.indicators, "process:" + bestProcess);

            const std::string name = lower(bestProcess);

            const size_t slash = name.find_last_of("\\/");

            const std::string executable =
                slash == std::string::npos ? name : name.substr(slash + 1);

            if (executable == "powershell.exe" || executable == "pwsh.exe") {
                signal.reasons.push_back("PowerShell activity was observed.");

            } else if (executable == "cmd.exe" || executable == "wscript.exe" ||
                       executable == "cscript.exe" ||
                       executable == "mshta.exe" ||
                       executable == "rundll32.exe" ||
                       executable == "regsvr32.exe") {
                signal.reasons.push_back(
                    "Process is capable of script, "
                    "command, or proxy execution.");

            } else if (executable == "python.exe" ||
                       executable == "python3.exe") {
                signal.reasons.push_back(
                    "Python interpreter activity was observed.");
            }
        }

        if (!bestPath.empty()) {
            addUnique(signal.indicators, "path:" + bestPath);

            signal.reasons.push_back(
                "Executable or file activity originated "
                "from a user-writable location.");
        }

        if (networkActivity && (suspiciousProcess || suspiciousPath)) {
            signal.reasons.push_back(
                "Suspicious execution activity is "
                "associated with network communication.");
        }

        if (downloadActivity && suspiciousProcess) {
            signal.reasons.push_back(
                "Process activity is associated "
                "with download activity.");
        }

        if (suspiciousProcess && suspiciousPath) {
            signal.reasons.push_back(
                "Suspicious process execution is "
                "associated with a user-writable path.");
        }

        if (activity.sources.size() >= 2) {
            signal.reasons.push_back(
                "Activity was observed across "
                "multiple forensic sources.");
        }

        signals.push_back(std::move(signal));
    }

    return signals;
}

std::string ProcessRule::name() const { return "ProcessRule"; }