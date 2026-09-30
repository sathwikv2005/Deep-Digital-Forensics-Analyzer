#pragma once

#include <vector>

#include "riskFinding.h"
#include "riskRule.h"

class RiskAggregator {
   public:
    std::vector<RiskFinding> aggregate(
        const RiskContext& context,
        const std::vector<RiskSignal>& signals) const;
};