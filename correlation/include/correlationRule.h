#ifndef CORRELATION_RULE_H
#define CORRELATION_RULE_H

#include <string>
#include <vector>

#include "correlation.h"
#include "evidenceNode.h"

class CorrelationRule {
   public:
    virtual ~CorrelationRule() = default;

    virtual bool matches(const EvidenceNode& first,
                         const EvidenceNode& second) const = 0;

    virtual Correlation evaluate(const EvidenceNode& first,
                                 const EvidenceNode& second) const = 0;

    virtual std::string name() const = 0;
};

#endif