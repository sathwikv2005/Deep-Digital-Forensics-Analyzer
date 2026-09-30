#pragma once

#include <memory>
#include <string>
#include <vector>

#include "riskFinding.h"
#include "riskRule.h"

class RiskEngine {
   public:
    RiskEngine(const std::string& timelinePath,
               const std::string& correlationPath);

    void addRule(std::unique_ptr<RiskRule> rule);

    std::vector<RiskFinding> analyze();

    void writeOutput(const std::string& outputPath,
                     const std::vector<RiskFinding>& findings) const;

   private:
    RiskContext context;

    std::vector<std::unique_ptr<RiskRule> > rules;
};