#pragma once

#include "../core/collector.h"

class NetworkCollector : public Collector {
   public:
    std::vector<Evidence> collect() override;
};