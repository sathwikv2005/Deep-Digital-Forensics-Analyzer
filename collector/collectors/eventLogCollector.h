#pragma once

#include "../core/Collector.h"

class EventLogCollector : public Collector {
   public:
    bool collect() override;
};