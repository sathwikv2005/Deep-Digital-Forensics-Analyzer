#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

#include "nlohmann/json.hpp"
#include "timelineConstructor.h"

using json = nlohmann::json;
namespace fs = std::filesystem;

int main(int argc, char* argv[]) {
    if (argc > 3) {
        std::cerr << "Usage: constructor [input-directory] [output-file]\n";
        return 1;
    }

    const fs::path inputDirectory =
        argc >= 2 ? fs::path(argv[1]) : fs::path("../output/collector_output");

    const fs::path outputFile =
        argc == 3 ? fs::path(argv[2])
                  : fs::path("../output/constructor_output/timeline.json");

    if (!fs::exists(inputDirectory) || !fs::is_directory(inputDirectory)) {
        std::cerr << "Invalid input directory: " << inputDirectory << '\n';
        return 1;
    }

    fs::create_directories(outputFile.parent_path());

    std::vector<json> evidence;

    for (const auto& entry : fs::directory_iterator(inputDirectory)) {
        if (!entry.is_regular_file() || entry.path().extension() != ".json") {
            continue;
        }

        std::ifstream file(entry.path());

        if (!file) {
            std::cerr << "Failed to open: " << entry.path() << '\n';
            continue;
        }

        try {
            json data;
            file >> data;

            if (!data.is_array()) {
                std::cerr << "Skipping non-array JSON: " << entry.path()
                          << '\n';
                continue;
            }

            for (const auto& item : data) evidence.push_back(item);
        } catch (const json::exception& e) {
            std::cerr << "Failed to parse " << entry.path() << ": " << e.what()
                      << '\n';
        }
    }

    TimelineConstructor constructor;
    auto timeline = constructor.construct(evidence);

    json output = json::array();

    for (const auto& event : timeline) {
        output.push_back({{"id", event.id},
                          {"timestamp", event.timestamp},
                          {"source", event.source},
                          {"category", event.category},
                          {"timestampMs", event.timestampMs},
                          {"validTimestamp", event.validTimestamp},
                          {"data", event.data}});
    }

    std::ofstream file(outputFile);

    if (!file) {
        std::cerr << "Failed to create output file: " << outputFile << '\n';
        return 1;
    }

    file << output.dump(4) << '\n';

    std::cout << "Input: " << inputDirectory << '\n';
    std::cout << "Loaded evidence: " << evidence.size() << '\n';
    std::cout << "Timeline events: " << timeline.size() << '\n';
    std::cout << "Output: " << outputFile << '\n';

    return 0;
}