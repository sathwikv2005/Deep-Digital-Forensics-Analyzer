#pragma once

#include <string>
#include <vector>

#include "riskRule.h"

class ProcessTreeRule : public RiskRule {
   public:
    std::vector<RiskSignal> evaluate(const RiskContext& context) const override;

    std::string name() const override;
};