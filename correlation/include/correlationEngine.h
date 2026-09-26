#ifndef CORRELATION_ENGINE_H
#define CORRELATION_ENGINE_H

#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "correlation.h"
#include "correlationRule.h"
#include "evidenceNode.h"
#include "indicatorExtractor.h"

class CorrelationEngine {
   public:
    explicit CorrelationEngine(const std::vector<EvidenceNode>& events);

    std::vector<Correlation> analyze();

   private:
    std::vector<EvidenceNode> events;
    std::vector<Indicators> indicators;

    std::unordered_map<std::string, std::vector<size_t>> domainIndex;
    std::unordered_map<std::string, std::vector<size_t>> ipIndex;
    std::unordered_map<std::string, std::vector<size_t>> fileIndex;
    std::unordered_map<std::string, std::vector<size_t>> processIndex;
    std::unordered_map<std::string, std::vector<size_t>> hashIndex;

    std::vector<std::unique_ptr<CorrelationRule>> rules;

    void filterToRecentEvents();

    void buildIndexes();

    void addToIndex(std::unordered_map<std::string, std::vector<size_t>>& index,
                    const std::string& key, size_t eventIndex);

    std::vector<Correlation> runRules();

    void processIndicatorIndex(
        const std::unordered_map<std::string, std::vector<size_t>>& index,
        const std::string& indicatorType, std::vector<Correlation>& results);

    void processCrossSourceIndex(
        const std::unordered_map<std::string, std::vector<size_t>>& index,
        const std::string& indicatorType, std::vector<int>& parent,
        std::vector<std::unordered_set<std::string>>& componentIndicators);

    void runCrossSourceCorrelations(std::vector<Correlation>& results);
};

#endif