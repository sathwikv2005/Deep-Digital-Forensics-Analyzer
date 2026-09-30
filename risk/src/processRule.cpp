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

std::string processName(const std::string& indicator) {
    const std::string prefix = "process:";

    if (indicator.rfind(prefix, 0) == 0) return indicator.substr(prefix.size());

    return indicator;
}

double scoreProcess(const std::string& process) {
    const std::string name = lower(process);

    if (name == "powershell.exe" || name == "pwsh.exe") return 40.0;

    if (name == "cmd.exe" || name == "wscript.exe" || name == "cscript.exe" ||
        name == "mshta.exe" || name == "rundll32.exe" || name == "regsvr32.exe")
        return 35.0;

    if (name == "python.exe" || name == "python3.exe") return 20.0;

    if (name == "chrome.exe" || name == "msedge.exe" || name == "firefox.exe" ||
        name == "explorer.exe" || name == "code.exe")
        return 5.0;

    return 15.0;
}

}  // namespace

std::vector<RiskSignal> ProcessRule::evaluate(
    const RiskContext& context) const {
    std::vector<RiskSignal> signals;

    if (!context.correlations.is_array()) return signals;

    for (const auto& correlation : context.correlations) {
        if (correlation.value("type", "") != "CROSS_SOURCE_ACTIVITY") continue;

        const auto indicators =
            correlation.value("indicators", std::vector<std::string>{});

        for (const auto& indicator : indicators) {
            if (indicator.rfind("process:", 0) != 0) continue;

            const std::string process = processName(indicator);

            const double score = scoreProcess(process);

            RiskSignal signal;

            signal.correlationId = correlation.value("id", "");

            signal.type = "PROCESS_CONTEXT";

            signal.score = score;

            signal.confidence = 0.7;

            signal.startTime = correlation.value("startTime", 0LL);

            signal.endTime = correlation.value("endTime", 0LL);

            signal.eventIds =
                correlation.value("eventIds", std::vector<std::string>{});

            signal.indicators.push_back(indicator);

            signal.sources =
                correlation.value("sources", std::vector<std::string>{});

            if (score >= 35.0) {
                signal.reasons.push_back(
                    "Process is capable of script or command execution.");
            } else if (score >= 20.0) {
                signal.reasons.push_back(
                    "Process can execute application-controlled code.");
            } else {
                signal.reasons.push_back(
                    "Process is commonly observed in normal activity.");
            }

            signals.push_back(std::move(signal));
        }
    }

    return signals;
}

std::string ProcessRule::name() const { return "ProcessRule"; }