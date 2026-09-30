#pragma once

#include <string>

class RiskScorer {
   public:
    static std::string severity(double score);

    static double combine(double processScore, double executionScore,
                          double networkScore, double rarityScore,
                          double behaviorScore);
};