#pragma once

#include <string>
#include <vector>

#include "riskContext.h"
#include "riskFinding.h"

class RiskRule {
   public:
    virtual ~RiskRule() = default;

    virtual std::vector<RiskFinding> evaluate(
        const RiskContext& context) const = 0;

    virtual std::string name() const = 0;
};