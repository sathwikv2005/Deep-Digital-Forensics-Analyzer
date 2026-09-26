#pragma once

#include "../core/collector.h"

class BrowserCollector : public Collector {
   public:
    std::vector<Evidence> collect() override;
};