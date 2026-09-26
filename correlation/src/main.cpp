#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

#include "correlationEngine.h"
#include "evidenceNode.h"
#include "nlohmann/json.hpp"

using json = nlohmann::json;
namespace fs = std::filesystem;

int main() {
    const fs::path inputPath = "../output/constructor_output/timeline.json";

    const fs::path outputDir = "../output/correlation_output";

    const fs::path outputPath = outputDir / "correlations.json";

    std::ifstream input(inputPath);

    if (!input) {
        std::cerr << "Failed to open timeline: " << inputPath << '\n';

        return 1;
    }

    json timeline;

    try {
        input >> timeline;
    } catch (const json::exception& e) {
        std::cerr << "Failed to parse timeline: " << e.what() << '\n';

        return 1;
    }

    if (!timeline.is_array()) {
        std::cerr << "Timeline must be a JSON array.\n";

        return 1;
    }

    std::vector<EvidenceNode> events;

    events.reserve(timeline.size());

    for (const auto& item : timeline) {
        EvidenceNode event;

        event.id = item.value("id", "");

        event.source = item.value("source", "");

        event.category = item.value("category", "");

        event.timestamp = item.value("timestamp", "");

        event.timestampMs = item.value("timestampMs", 0ULL);

        if (item.contains("data")) {
            event.data = item["data"];
        }

        if (event.id.empty()) {
            continue;
        }

        events.push_back(std::move(event));
    }

    std::cout << "Loaded " << events.size() << " evidence events.\n";

    CorrelationEngine engine(events);

    std::vector<Correlation> correlations = engine.analyze();

    fs::create_directories(outputDir);

    json output = json::array();

    for (const auto& correlation : correlations) {
        output.push_back({{"id", correlation.id},
                          {"type", correlation.type},
                          {"severity", correlation.severity},
                          {"confidence", correlation.confidence},
                          {"startTime", correlation.startTime},
                          {"endTime", correlation.endTime},
                          {"eventIds", correlation.eventIds},
                          {"indicators", correlation.indicators},
                          {"sources", correlation.sources},
                          {"reason", correlation.reason}});
    }

    std::ofstream out(outputPath);

    if (!out) {
        std::cerr << "Failed to create output: " << outputPath << '\n';

        return 1;
    }

    out << output.dump(4);

    std::cout << "Generated " << correlations.size() << " correlations.\n";

    std::cout << "Output: " << outputPath << '\n';

    return 0;
}