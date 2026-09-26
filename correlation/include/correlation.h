#ifndef CORRELATION_H
#define CORRELATION_H

#include <cstdint>
#include <string>
#include <vector>

struct Correlation {
    std::string id;
    std::string type;
    std::string severity;

    double confidence = 0.0;

    uint64_t startTime = 0;
    uint64_t endTime = 0;

    std::vector<std::string> eventIds;
    std::vector<std::string> indicators;

    std::string reason;
};

#endif