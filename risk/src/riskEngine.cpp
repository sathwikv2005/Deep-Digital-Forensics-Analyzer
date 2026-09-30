#include "riskEngine.h"

#include <fstream>
#include <iostream>
#include <stdexcept>

#include "correlationAnalyzer.h"
#include "executionPathRule.h"
#include "networkRule.h"
#include "processRule.h"
#include "processTreeRule.h"
#include "riskAggregator.h"

using json = nlohmann::json;

RiskEngine::RiskEngine(const std::string& timelinePath,
                       const std::string& correlationPath) {
    std::ifstream timelineFile(timelinePath);

    std::ifstream correlationFile(correlationPath);

    if (!timelineFile) {
        throw std::runtime_error("Failed to open timeline file: " +
                                 timelinePath);
    }

    if (!correlationFile) {
        throw std::runtime_error("Failed to open correlation file: " +
                                 correlationPath);
    }

    timelineFile >> context.timeline;

    correlationFile >> context.correlations;

    context.activities =
        CorrelationAnalyzer::analyze(context.timeline, context.correlations);

    std::cout << "[Risk] Timeline events: " << context.timeline.size() << '\n';

    std::cout << "[Risk] Correlations: " << context.correlations.size() << '\n';

    std::cout << "[Risk] Activities: " << context.activities.size() << '\n';
}

void RiskEngine::addRule(std::unique_ptr<RiskRule> rule) {
    rules.push_back(std::move(rule));
}

std::vector<RiskFinding> RiskEngine::analyze() {
    std::vector<RiskSignal> signals;

    for (const auto& rule : rules) {
        auto ruleSignals = rule->evaluate(context);

        std::cout << "[Risk] " << rule->name() << " generated "
                  << ruleSignals.size() << " signals\n";

        signals.insert(signals.end(), ruleSignals.begin(), ruleSignals.end());
    }

    std::cout << "[Risk] Total signals: " << signals.size() << '\n';

    RiskAggregator aggregator;

    auto findings = aggregator.aggregate(context, signals);

    std::cout << "[Risk] Aggregated findings: " << findings.size() << '\n';

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

    if (!file) {
        throw std::runtime_error("Failed to open risk output file: " +
                                 outputPath);
    }

    file << output.dump(4);
}