#ifndef CORRELATION_ENGINE_H
#define CORRELATION_ENGINE_H

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "correlation.h"
#include "correlationRule.h"
#include "evidenceNode.h"

class CorrelationEngine {
   public:
    explicit CorrelationEngine(const std::vector<EvidenceNode>& events);

    std::vector<Correlation> analyze();

   private:
    std::vector<EvidenceNode> events;

    std::unordered_map<std::string, std::vector<size_t>> domainIndex;
    std::unordered_map<std::string, std::vector<size_t>> ipIndex;
    std::unordered_map<std::string, std::vector<size_t>> fileIndex;
    std::unordered_map<std::string, std::vector<size_t>> processIndex;

    void buildIndexes();

    void addToIndex(std::unordered_map<std::string, std::vector<size_t>>& index,
                    const std::string& key, size_t eventIndex);

    std::vector<Correlation> runRules();

    std::vector<std::unique_ptr<CorrelationRule>> rules;
};

#endif