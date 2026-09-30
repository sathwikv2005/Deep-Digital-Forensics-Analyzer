#include "executionPathRule.h"

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

double pathScore(const std::string& path) {
    const std::string value = lower(path);

    if (value.find("\\appdata\\local\\temp\\") != std::string::npos)
        return 30.0;

    if (value.find("\\temp\\") != std::string::npos) return 30.0;

    if (value.find("\\appdata\\roaming\\") != std::string::npos) return 20.0;

    if (value.find("\\appdata\\local\\") != std::string::npos) return 15.0;

    return 0.0;
}

}  // namespace

std::vector<RiskSignal> ExecutionPathRule::evaluate(
    const RiskContext& context) const {
    std::vector<RiskSignal> signals;

    if (!context.timeline.is_array()) return signals;

    for (const auto& event : context.timeline) {
        const std::string category = event.value("category", "");

        if (category != "Process" && category != "File") continue;

        const std::string description = event.value("description", "");

        const auto raw = event.value("raw", nlohmann::json{});

        std::string path = description;

        if (raw.is_object()) {
            for (const auto& key :
                 {"path", "file", "filePath", "executable", "imagePath"}) {
                if (raw.contains(key) && raw[key].is_string()) {
                    path = raw[key].get<std::string>();

                    break;
                }
            }
        }

        const double score = pathScore(path);

        if (score <= 0.0) continue;

        RiskSignal signal;

        signal.type = "EXECUTION_PATH";

        signal.score = score;

        signal.confidence = 0.75;

        signal.indicators.push_back(path);

        signal.reasons.push_back(
            "Executable or file activity originated "
            "from a user-writable application data location.");

        signals.push_back(std::move(signal));
    }

    return signals;
}

std::string ExecutionPathRule::name() const { return "ExecutionPathRule"; }