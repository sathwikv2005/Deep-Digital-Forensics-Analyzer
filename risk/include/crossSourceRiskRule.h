#pragma once

#include <vector>

#include "riskRule.h"

class CrossSourceRiskRule : public RiskRule {
   public:
    std::vector<RiskFinding> evaluate(
        const RiskContext& context) const override;

    std::string name() const override;
};