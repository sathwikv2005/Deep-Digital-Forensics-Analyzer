#include "timelineConstructor.h"

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <sstream>

TimelineEvent TimelineConstructor::createEvent(const nlohmann::json& item) {
    TimelineEvent event;

    event.id = item.value("id", "");
    event.timestamp = item.value("timestamp", "");
    event.source = item.value("source", "");
    event.category = item.value("category", "");
    event.data = item;

    event.timestampMs = parseTimestamp(event.timestamp);
    event.validTimestamp = event.timestampMs != -1;

    return event;
}

int64_t TimelineConstructor::parseTimestamp(const std::string& timestamp) {
    if (timestamp.empty()) return -1;

    std::string value = timestamp;

    if (!value.empty() && value.back() == 'Z') value.pop_back();

    auto dot = value.find('.');

    std::string fractional;

    if (dot != std::string::npos) {
        fractional = value.substr(dot + 1);
        value = value.substr(0, dot);
    }

    std::tm tm = {};
    std::istringstream stream(value);

    stream >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");

    if (stream.fail()) return -1;

#if defined(_WIN32)
    std::time_t time = _mkgmtime(&tm);
#else
    std::time_t time = timegm(&tm);
#endif

    if (time == -1) return -1;

    int64_t milliseconds = static_cast<int64_t>(time) * 1000;

    if (!fractional.empty()) {
        while (fractional.size() < 3) fractional += '0';

        if (fractional.size() > 3) fractional.resize(3);

        milliseconds += std::stoll(fractional);
    }

    return milliseconds;
}

std::vector<TimelineEvent> TimelineConstructor::construct(
    const std::vector<nlohmann::json>& evidence) {
    std::vector<TimelineEvent> timeline;
    timeline.reserve(evidence.size());

    for (const auto& item : evidence) timeline.push_back(createEvent(item));

    std::stable_sort(timeline.begin(), timeline.end(),
                     [](const TimelineEvent& a, const TimelineEvent& b) {
                         if (!a.validTimestamp) return false;

                         if (!b.validTimestamp) return true;

                         return a.timestampMs < b.timestampMs;
                     });

    return timeline;
}