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

std::string executableName(const std::string& process) {
    std::string value = lower(process);

    const size_t slash = value.find_last_of("\\/");

    if (slash != std::string::npos) value = value.substr(slash + 1);

    return value;
}

}  // namespace

double BehaviorScorer::processScore(const std::string& process) {
    const std::string name = executableName(process);

    if (name == "powershell.exe" || name == "pwsh.exe") return 25.0;

    if (name == "cmd.exe" || name == "wscript.exe" || name == "cscript.exe" ||
        name == "mshta.exe" || name == "rundll32.exe" || name == "regsvr32.exe")
        return 20.0;

    if (name == "python.exe" || name == "python3.exe") return 8.0;

    return 0.0;
}

double BehaviorScorer::pathScore(const std::string& path) {
    const std::string value = lower(path);

    if (value.find("\\appdata\\local\\programs\\") != std::string::npos)
        return 0.0;

    if (value.find("\\appdata\\local\\temp\\") != std::string::npos)
        return 25.0;

    if (value.find("\\temp\\") != std::string::npos) return 25.0;

    if (value.find("\\appdata\\roaming\\") != std::string::npos) return 20.0;

    if (value.find("\\appdata\\local\\") != std::string::npos) return 5.0;

    return 0.0;
}

double BehaviorScorer::networkScore(size_t networkEventCount) {
    if (networkEventCount >= 20) return 5.0;

    if (networkEventCount >= 10) return 3.0;

    if (networkEventCount >= 3) return 2.0;

    return 0.0;
}

double BehaviorScorer::combinationBonus(bool suspiciousProcess,
                                        bool suspiciousPath,
                                        bool networkActivity,
                                        bool downloadActivity) {
    double score = 0.0;

    if (suspiciousProcess && networkActivity) score += 15.0;

    if (suspiciousProcess && suspiciousPath) score += 20.0;

    if (suspiciousPath && networkActivity) score += 15.0;

    if (downloadActivity && suspiciousProcess) score += 20.0;

    if (downloadActivity && suspiciousPath && networkActivity) score += 30.0;

    return score;
}

double BehaviorScorer::processTreeScore(const std::string& parent,
                                        const std::string& child) {
    const std::string parentName = executableName(parent);
    const std::string childName = executableName(child);

    const bool commandInterpreter =
        childName == "cmd.exe" || childName == "powershell.exe" ||
        childName == "pwsh.exe" || childName == "wscript.exe" ||
        childName == "cscript.exe" || childName == "mshta.exe" ||
        childName == "rundll32.exe" || childName == "regsvr32.exe";

    if (!commandInterpreter) return 0.0;

    if (parentName == "explorer.exe") return 5.0;

    if (parentName == "cmd.exe") return 5.0;

    return 15.0;
}