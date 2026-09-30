#pragma once

#include "riskRule.h"

class ProcessRule : public RiskRule {
   public:
    std::vector<RiskSignal> evaluate(const RiskContext& context) const override;

    std::string name() const override;
};