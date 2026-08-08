#pragma once

#include "../core/Collector.h"

class EventLogCollector : public Collector {
   public:
    std::vector<Evidence> collect() override;
};