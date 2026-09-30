#include "correlationAnalyzer.h"

#include <algorithm>
#include <string>
#include <unordered_map>

namespace {

void addUnique(std::vector<std::string>& values, const std::string& value) {
    if (value.empty()) return;

    if (std::find(values.begin(), values.end(), value) == values.end())
        values.push_back(value);
}

void extractProcessIndicators(const std::vector<std::string>& indicators,
                              std::vector<std::string>& processes) {
    const std::string prefix = "process:";

    for (const auto& indicator : indicators) {
        if (indicator.rfind(prefix, 0) != 0) continue;

        const std::string process = indicator.substr(prefix.size());

        addUnique(processes, process);
    }
}

}  // namespace

std::vector<CorrelationActivity> CorrelationAnalyzer::analyze(
    const nlohmann::json& timeline, const nlohmann::json& correlations) {
    std::vector<CorrelationActivity> activities;

    if (!timeline.is_array() || !correlations.is_array()) return activities;

    std::unordered_map<std::string, nlohmann::json> events;

    for (const auto& event : timeline) {
        const std::string id = event.value("id", "");

        if (!id.empty()) events[id] = event;
    }

    for (const auto& correlation : correlations) {
        CorrelationActivity activity;

        activity.id = correlation.value("id", "");

        if (activity.id.empty()) continue;

        activity.startTime = correlation.value("startTime", 0LL);

        activity.endTime = correlation.value("endTime", 0LL);

        activity.eventIds =
            correlation.value("eventIds", std::vector<std::string>{});

        activity.indicators =
            correlation.value("indicators", std::vector<std::string>{});

        activity.sources =
            correlation.value("sources", std::vector<std::string>{});

        extractProcessIndicators(activity.indicators, activity.processes);

        for (const auto& eventId : activity.eventIds) {
            auto it = events.find(eventId);

            if (it == events.end()) continue;

            const auto& event = it->second;

            const std::string category = event.value("category", "");

            if (category == "NetworkConnection") ++activity.networkEvents;

            if (category == "BrowserDownload") ++activity.downloadEvents;

            if (!event.contains("data") || !event["data"].is_object()) continue;

            const auto& data = event["data"];

            if (!data.contains("data") || !data["data"].is_object()) continue;

            const auto& eventData = data["data"];

            if (eventData.contains("processName") &&
                eventData["processName"].is_string()) {
                addUnique(activity.processes,
                          eventData["processName"].get<std::string>());
            }

            if (eventData.contains("processPath") &&
                eventData["processPath"].is_string()) {
                addUnique(activity.paths,
                          eventData["processPath"].get<std::string>());
            }

            if (eventData.contains("path") && eventData["path"].is_string()) {
                addUnique(activity.paths, eventData["path"].get<std::string>());
            }

            if (eventData.contains("filePath") &&
                eventData["filePath"].is_string()) {
                addUnique(activity.paths,
                          eventData["filePath"].get<std::string>());
            }

            if (eventData.contains("executable") &&
                eventData["executable"].is_string()) {
                addUnique(activity.paths,
                          eventData["executable"].get<std::string>());
            }

            if (eventData.contains("imagePath") &&
                eventData["imagePath"].is_string()) {
                addUnique(activity.paths,
                          eventData["imagePath"].get<std::string>());
            }
        }

        activities.push_back(std::move(activity));
    }

    return activities;
}