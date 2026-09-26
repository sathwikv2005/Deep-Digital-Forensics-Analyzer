#include "indicatorExtractor.h"

#include <algorithm>
#include <cctype>
#include <regex>
#include <unordered_set>

namespace {

std::string dumpNode(const EvidenceNode& node) {
    std::string text;

    text += node.source;
    text += " ";
    text += node.category;
    text += " ";
    text += node.timestamp;

    if (!node.data.is_null()) text += " " + node.data.dump();

    return text;
}

void addUnique(std::vector<std::string>& values,
               std::unordered_set<std::string>& seen,
               const std::string& value) {
    if (seen.insert(value).second) values.push_back(value);
}

}  // namespace

Indicators IndicatorExtractor::extract(const EvidenceNode& node) {
    Indicators indicators;

    std::string text = dumpNode(node);

    extractUrls(text, indicators);
    extractIps(text, indicators);
    extractFiles(text, indicators);
    extractProcesses(text, indicators);
    extractDomains(indicators);

    return indicators;
}

void IndicatorExtractor::extractUrls(const std::string& text,
                                     Indicators& indicators) {
    static const std::regex pattern(R"(https?://[^\s"'<>]+)",
                                    std::regex::icase);

    std::unordered_set<std::string> seen;

    for (std::sregex_iterator it(text.begin(), text.end(), pattern);
         it != std::sregex_iterator(); ++it) {
        std::string url = it->str();

        while (!url.empty() && (url.back() == ',' || url.back() == '.' ||
                                url.back() == ')' || url.back() == ';')) {
            url.pop_back();
        }

        addUnique(indicators.urls, seen, url);
    }
}

void IndicatorExtractor::extractIps(const std::string& text,
                                    Indicators& indicators) {
    static const std::regex pattern(
        R"(\b(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])){3}\b)");

    std::unordered_set<std::string> seen;

    for (std::sregex_iterator it(text.begin(), text.end(), pattern);
         it != std::sregex_iterator(); ++it) {
        addUnique(indicators.ips, seen, it->str());
    }
}

void IndicatorExtractor::extractFiles(const std::string& text,
                                      Indicators& indicators) {
    static const std::regex pattern(
        R"([A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]+)");

    std::unordered_set<std::string> seen;

    for (std::sregex_iterator it(text.begin(), text.end(), pattern);
         it != std::sregex_iterator(); ++it) {
        addUnique(indicators.files, seen, it->str());
    }
}

void IndicatorExtractor::extractProcesses(const std::string& text,
                                          Indicators& indicators) {
    static const std::regex pattern(R"(\b[A-Za-z0-9_.-]+\.exe\b)",
                                    std::regex::icase);

    std::unordered_set<std::string> seen;

    for (std::sregex_iterator it(text.begin(), text.end(), pattern);
         it != std::sregex_iterator(); ++it) {
        addUnique(indicators.processes, seen, it->str());
    }
}

void IndicatorExtractor::extractDomains(Indicators& indicators) {
    std::unordered_set<std::string> seen;

    static const std::regex pattern(R"(https?://([^/:?#\s]+))",
                                    std::regex::icase);

    for (const auto& url : indicators.urls) {
        std::smatch match;

        if (std::regex_search(url, match, pattern)) {
            std::string domain = match[1].str();

            std::transform(domain.begin(), domain.end(), domain.begin(),
                           [](unsigned char c) {
                               return static_cast<char>(std::tolower(c));
                           });

            addUnique(indicators.domains, seen, domain);
        }
    }
}