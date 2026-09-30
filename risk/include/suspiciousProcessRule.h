#pragma once

#include "riskRule.h"

class SuspiciousProcessRule : public RiskRule {
   public:
    std::vector<RiskFinding> evaluate(
        const RiskContext& context) const override;

    std::string name() const override;
};