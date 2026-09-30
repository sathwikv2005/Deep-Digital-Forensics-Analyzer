#pragma once

#include <mutex>
#include <string>
#include <vector>

#include "../models/evidence.h"

class EventLogCollector {
   public:
    std::vector<Evidence> collect();

   private:
    void collectChannel(const wchar_t* channel);

    void handleEvent(void* eventHandle);

    std::vector<Evidence> evidence_;
    std::mutex mutex_;
};