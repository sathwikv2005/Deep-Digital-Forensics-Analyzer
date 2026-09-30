#pragma once

#include "riskRule.h"

class NetworkRule : public RiskRule {
   public:
    std::vector<RiskSignal> evaluate(const RiskContext& context) const override;

    std::string name() const override;
};