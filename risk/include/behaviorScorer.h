#pragma once

#include <string>

class BehaviorScorer {
   public:
    static double processScore(const std::string& process);

    static double pathScore(const std::string& path);

    static double networkScore(size_t networkEventCount);

    static double combinationBonus(bool suspiciousProcess, bool suspiciousPath,
                                   bool networkActivity, bool downloadActivity);
};