#pragma once

#include <nlohmann/json.hpp>
#include <string>
#include <vector>

struct CorrelationActivity {
    std::string id;

    long long startTime = 0;
    long long endTime = 0;

    std::vector<std::string> eventIds;

    std::vector<std::string> indicators;

    std::vector<std::string> sources;

    std::vector<std::string> processes;

    std::vector<std::string> parentProcesses;

    std::vector<std::string> paths;

    size_t networkEvents = 0;

    size_t downloadEvents = 0;
};

class CorrelationAnalyzer {
   public:
    static std::vector<CorrelationActivity> analyze(
        const nlohmann::json& timeline, const nlohmann::json& correlations);
};