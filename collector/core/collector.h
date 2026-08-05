#pragma once

class Collector {
   public:
    virtual ~Collector() = default;

    virtual bool collect() = 0;
};