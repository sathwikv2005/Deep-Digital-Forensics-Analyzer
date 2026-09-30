#pragma once

#include <nlohmann/json.hpp>

#include "correlationAnalyzer.h"

struct RiskContext {
    nlohmann::json timeline;
    nlohmann::json correlations;

    std::vector<CorrelationActivity> activities;
};