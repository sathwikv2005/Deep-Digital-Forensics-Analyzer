#pragma once

#include <vector>

#include "../core/collector.h"

class ProcessCollector {
   public:
    std::vector<Evidence> collect();
};