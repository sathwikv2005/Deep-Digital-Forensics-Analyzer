#include "evidenceSerializer.h"

#include <filesystem>
#include <fstream>

#include "nlohmann/json.hpp"

using json = nlohmann::json;

bool EvidenceSerializer::write(const std::string& path,
                               const std::vector<Evidence>& evidence) {
    json output = json::array();

    for (const auto& item : evidence) {
        output.push_back({{"source", item.source},
                          {"timestamp", item.timestamp},
                          {"category", item.category},
                          {"description", item.description},
                          {"raw", item.raw}});
    }

    std::filesystem::path filePath(path);

    if (filePath.has_parent_path()) {
        std::filesystem::create_directories(filePath.parent_path());
    }

    std::ofstream file(filePath, std::ios::out | std::ios::trunc);

    if (!file.is_open()) {
        return false;
    }

    file << output.dump(4);

    if (file.fail()) {
        file.close();
        return false;
    }

    file.close();

    return true;
}