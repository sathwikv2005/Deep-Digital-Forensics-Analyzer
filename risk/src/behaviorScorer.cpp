#include "behaviorScorer.h"

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

}  // namespace

double BehaviorScorer::processScore(const std::string& process) {
    const std::string name = lower(process);

    if (name == "powershell.exe" || name == "pwsh.exe") return 30.0;

    if (name == "cmd.exe" || name == "wscript.exe" || name == "cscript.exe" ||
        name == "mshta.exe" || name == "rundll32.exe" || name == "regsvr32.exe")
        return 25.0;

    if (name == "python.exe" || name == "python3.exe") return 10.0;

    return 0.0;
}

double BehaviorScorer::pathScore(const std::string& path) {
    const std::string value = lower(path);

    if (value.find("\\appdata\\local\\temp\\") != std::string::npos)
        return 30.0;

    if (value.find("\\temp\\") != std::string::npos) return 30.0;

    if (value.find("\\appdata\\roaming\\") != std::string::npos) return 20.0;

    if (value.find("\\appdata\\local\\") != std::string::npos) return 15.0;

    return 0.0;
}

double BehaviorScorer::networkScore(size_t networkEventCount) {
    if (networkEventCount >= 10) return 10.0;

    if (networkEventCount >= 3) return 5.0;

    if (networkEventCount > 0) return 2.0;

    return 0.0;
}

double BehaviorScorer::combinationBonus(bool suspiciousProcess,
                                        bool suspiciousPath,
                                        bool networkActivity,
                                        bool downloadActivity) {
    double score = 0.0;

    if (suspiciousProcess && networkActivity) score += 10.0;

    if (suspiciousProcess && suspiciousPath) score += 15.0;

    if (suspiciousPath && networkActivity) score += 10.0;

    if (downloadActivity && suspiciousProcess) score += 15.0;

    if (downloadActivity && suspiciousPath && networkActivity) score += 20.0;

    return score;
}