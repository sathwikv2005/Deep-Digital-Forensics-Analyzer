#pragma once

#include <string>
#include <vector>

#include "../models/evidence.h"

class NetworkCollector {
   public:
    std::vector<Evidence> collect();

   private:
    void handleEvent(void* eventHandle);

    std::vector<Evidence> evidence_;
};