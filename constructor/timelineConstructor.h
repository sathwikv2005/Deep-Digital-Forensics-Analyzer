#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "nlohmann/json.hpp"

struct TimelineEvent {
    std::string id;
    std::string timestamp;
    std::string source;
    std::string category;
    nlohmann::json data;

    int64_t timestampMs;
    bool validTimestamp;
};

class TimelineConstructor {
   public:
    std::vector<TimelineEvent> construct(
        const std::vector<nlohmann::json>& evidence);

   private:
    TimelineEvent createEvent(const nlohmann::json& item);
    int64_t parseTimestamp(const std::string& timestamp);
};