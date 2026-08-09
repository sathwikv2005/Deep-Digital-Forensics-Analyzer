#pragma once

#include <string>
#include <vector>

#include "../models/evidence.h"
class Collector {
   public:
    virtual ~Collector() = default;

    virtual std::vector<Evidence> collect() = 0;
};