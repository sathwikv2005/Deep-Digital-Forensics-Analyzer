#pragma once

#include <cstdint>
#include <string>

#include "nlohmann/json.hpp"

using json = nlohmann::json;

struct TimelineEvent {
    std::string id;
    std::string timestamp;
    std::string source;
    std::string category;

    uint64_t timestampMs = 0;
    bool validTimestamp = false;

    json data;
};

class TimelineConstructor {
   public:
    std::vector<TimelineEvent> construct(
        const std::vector<nlohmann::json>& evidence);

   private:
    TimelineEvent createEvent(const nlohmann::json& item);
    std::string getCategory(const nlohmann::json& data);
    int64_t parseTimestamp(const std::string& timestamp);
};