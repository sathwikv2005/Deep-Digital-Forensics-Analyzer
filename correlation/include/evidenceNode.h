#ifndef EVIDENCE_NODE_H
#define EVIDENCE_NODE_H

#include <cstdint>
#include <string>

#include "nlohmann/json.hpp"

using json = nlohmann::json;

struct EvidenceNode {
    std::string id;
    std::string source;
    std::string category;

    std::string timestamp;
    uint64_t timestampMs = 0;

    json data;
};

#endif