#pragma once

struct Evidence {
    std::string source;
    std::string timestamp;
    std::string category;
    std::string description;
};

class Collector {
   public:
    virtual ~Collector() = default;

    virtual bool collect() = 0;
};