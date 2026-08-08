#pragma once

#include <string>
#include <vector>

struct Evidence {
    std::string source;
    std::string timestamp;
    std::string category;
    std::string description;
};

class Collector {
   public:
    virtual ~Collector() = default;

    virtual std::vector<Evidence> collect() = 0;
};