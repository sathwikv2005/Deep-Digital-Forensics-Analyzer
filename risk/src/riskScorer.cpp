#include "riskScorer.h"

#include <algorithm>

std::string RiskScorer::severity(double score) {
    if (score >= 80.0) return "CRITICAL";

    if (score >= 60.0) return "HIGH";

    if (score >= 40.0) return "MEDIUM";

    if (score >= 20.0) return "LOW";

    return "INFO";
}

double RiskScorer::combine(double processScore, double executionScore,
                           double networkScore, double rarityScore,
                           double behaviorScore) {
    const double score = processScore + executionScore + networkScore +
                         rarityScore + behaviorScore;

    return std::clamp(score, 0.0, 100.0);
}