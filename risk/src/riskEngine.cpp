#include "riskEngine.h"

#include <fstream>
#include <stdexcept>

using json = nlohmann::json;

RiskEngine::RiskEngine(const std::string& timelinePath,
                       const std::string& correlationPath) {
    std::ifstream timelineFile(timelinePath);
    std::ifstream correlationFile(correlationPath);

    if (!timelineFile)
        throw std::runtime_error("Failed to open timeline file: " +
                                 timelinePath);

    if (!correlationFile)
        throw std::runtime_error("Failed to open correlation file: " +
                                 correlationPath);

    timelineFile >> context.timeline;
    correlationFile >> context.correlations;
}

void RiskEngine::addRule(std::unique_ptr<RiskRule> rule) {
    rules.push_back(std::move(rule));
}

std::vector<RiskFinding> RiskEngine::analyze() {
    std::vector<RiskFinding> findings;

    for (const auto& rule : rules) {
        auto ruleFindings = rule->evaluate(context);

        findings.insert(findings.end(), ruleFindings.begin(),
                        ruleFindings.end());
    }

    return findings;
}

void RiskEngine::writeOutput(const std::string& outputPath,
                             const std::vector<RiskFinding>& findings) const {
    json output = json::array();

    for (const auto& finding : findings) {
        output.push_back({{"id", finding.id},
                          {"type", finding.type},
                          {"severity", finding.severity},
                          {"score", finding.score},
                          {"confidence", finding.confidence},
                          {"startTime", finding.startTime},
                          {"endTime", finding.endTime},
                          {"eventIds", finding.eventIds},
                          {"indicators", finding.indicators},
                          {"sources", finding.sources},
                          {"reasons", finding.reasons}});
    }

    std::ofstream file(outputPath);

    if (!file)
        throw std::runtime_error("Failed to open risk output file: " +
                                 outputPath);

    file << output.dump(4);
}