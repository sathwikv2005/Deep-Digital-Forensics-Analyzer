#pragma once

#include <nlohmann/json.hpp>

struct RiskContext {
    nlohmann::json timeline;
    nlohmann::json correlations;
};