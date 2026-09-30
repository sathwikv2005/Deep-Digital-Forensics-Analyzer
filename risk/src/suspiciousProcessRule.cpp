#include "suspiciousProcessRule.h"

#include <algorithm>
#include <cctype>
#include <string>

namespace {

std::string toLower(std::string value) {
    std::transform(
        value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    return value;
}

std::string getProcessName(const std::string& indicator) {
    const std::string prefix = "process:";

    if (indicator.rfind(prefix, 0) == 0)
        return indicator.substr(prefix.length());

    return indicator;
}

double getProcessScore(const std::string& process) {
    const std::string name = toLower(process);

    if (name == "pwsh.exe" || name == "powershell.exe") {
        return 40.0;
    }

    if (name == "cmd.exe" || name == "wscript.exe" || name == "cscript.exe" ||
        name == "mshta.exe" || name == "rundll32.exe" ||
        name == "regsvr32.exe") {
        return 35.0;
    }

    if (name == "python.exe" || name == "python3.exe") {
        return 20.0;
    }

    if (name == "chrome.exe" || name == "msedge.exe" || name == "firefox.exe" ||
        name == "explorer.exe" || name == "code.exe") {
        return 5.0;
    }

    return 15.0;
}

std::string getSeverity(double score) {
    if (score >= 80.0) return "CRITICAL";

    if (score >= 60.0) return "HIGH";

    if (score >= 40.0) return "MEDIUM";

    if (score >= 20.0) return "LOW";

    return "INFO";
}

}  // namespace

std::vector<RiskFinding> SuspiciousProcessRule::evaluate(
    const RiskContext& context) const {
    std::vector<RiskFinding> findings;

    if (!context.correlations.is_array()) return findings;

    for (const auto& correlation : context.correlations) {
        if (correlation.value("type", "") != "CROSS_SOURCE_ACTIVITY") continue;

        const auto indicators =
            correlation.value("indicators", std::vector<std::string>{});

        for (const auto& indicator : indicators) {
            if (indicator.rfind("process:", 0) != 0) continue;

            const std::string process = getProcessName(indicator);

            const double score = getProcessScore(process);

            RiskFinding finding;

            finding.id = "risk-process-" + correlation.value("id", "unknown");

            finding.type = "SUSPICIOUS_PROCESS_ACTIVITY";

            finding.score = score;

            finding.confidence = 0.7;

            finding.startTime = correlation.value("startTime", 0LL);

            finding.endTime = correlation.value("endTime", 0LL);

            finding.eventIds =
                correlation.value("eventIds", std::vector<std::string>{});

            finding.indicators.push_back(indicator);

            finding.sources =
                correlation.value("sources", std::vector<std::string>{});

            if (score >= 40.0) {
                finding.reasons.push_back(
                    "Process belongs to an interpreter or "
                    "system utility commonly associated with "
                    "script or command execution.");
            } else if (score >= 20.0) {
                finding.reasons.push_back(
                    "Process can execute scripts or "
                    "application-controlled code.");
            } else {
                finding.reasons.push_back(
                    "Process activity is considered common "
                    "or lower risk based on process context.");
            }

            finding.reasons.push_back(
                "Process activity was observed across "
                "multiple forensic sources.");

            finding.severity = getSeverity(finding.score);

            findings.push_back(std::move(finding));
        }
    }

    return findings;
}

std::string SuspiciousProcessRule::name() const {
    return "SuspiciousProcessRule";
}