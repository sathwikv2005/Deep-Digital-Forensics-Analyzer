#include "processRule.h"

#include <algorithm>
#include <cctype>
#include <string>

namespace {

std::string lower(std::string value) {
    std::transform(
        value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    return value;
}

double scoreProcess(const std::string& process) {
    const std::string name = lower(process);

    if (name == "powershell.exe" || name == "pwsh.exe") return 30.0;

    if (name == "cmd.exe" || name == "wscript.exe" || name == "cscript.exe" ||
        name == "mshta.exe" || name == "rundll32.exe" || name == "regsvr32.exe")
        return 25.0;

    if (name == "python.exe" || name == "python3.exe") return 10.0;

    return 0.0;
}

}  // namespace

std::vector<RiskSignal> ProcessRule::evaluate(
    const RiskContext& context) const {
    std::vector<RiskSignal> signals;

    for (const auto& activity : context.activities) {
        for (const auto& process : activity.processes) {
            const double score = scoreProcess(process);

            if (score <= 0.0) continue;

            RiskSignal signal;

            signal.correlationId = activity.id;

            signal.type = "PROCESS_CONTEXT";

            signal.score = score;

            signal.confidence = 0.8;

            signal.startTime = activity.startTime;

            signal.endTime = activity.endTime;

            signal.eventIds = activity.eventIds;

            signal.indicators.push_back("process:" + process);

            signal.sources = activity.sources;

            if (score >= 25.0) {
                signal.reasons.push_back(
                    "Process is capable of script or command execution.");
            } else {
                signal.reasons.push_back(
                    "Process can execute application-controlled code.");
            }

            signals.push_back(std::move(signal));
        }
    }

    return signals;
}

std::string ProcessRule::name() const { return "ProcessRule"; }