#ifndef CORRELATION_RULE_H
#define CORRELATION_RULE_H

#include <string>

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

class TemporalRule : public CorrelationRule {
   public:
    explicit TemporalRule(uint64_t windowMs);

    bool matches(const EvidenceNode& first,
                 const EvidenceNode& second) const override;

    Correlation evaluate(const EvidenceNode& first,
                         const EvidenceNode& second) const override;

    std::string name() const override;

   private:
    uint64_t windowMs;
};

class EntityRule : public CorrelationRule {
   public:
    bool matches(const EvidenceNode& first,
                 const EvidenceNode& second) const override;

    Correlation evaluate(const EvidenceNode& first,
                         const EvidenceNode& second) const override;

    std::string name() const override;
};

#endif