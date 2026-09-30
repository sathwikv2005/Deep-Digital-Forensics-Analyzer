#pragma once

#include <string>
#include <vector>

#include "riskContext.h"

struct RiskSignal {
    std::string correlationId;
    std::string type;

    double score = 0.0;
    double confidence = 0.0;

    long long startTime = 0;
    long long endTime = 0;

    std::vector<std::string> eventIds;
    std::vector<std::string> indicators;
    std::vector<std::string> sources;
    std::vector<std::string> reasons;
};

class RiskRule {
   public:
    virtual ~RiskRule() = default;

    virtual std::vector<RiskSignal> evaluate(
        const RiskContext& context) const = 0;

    virtual std::string name() const = 0;
};