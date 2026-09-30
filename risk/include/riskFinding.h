#pragma once

#include <string>
#include <vector>

struct RiskFinding {
    std::string id;
    std::string type;
    std::string severity;

    double score = 0.0;
    double confidence = 0.0;

    long long startTime = 0;
    long long endTime = 0;

    std::vector<std::string> eventIds;
    std::vector<std::string> indicators;
    std::vector<std::string> sources;
    std::vector<std::string> reasons;
};