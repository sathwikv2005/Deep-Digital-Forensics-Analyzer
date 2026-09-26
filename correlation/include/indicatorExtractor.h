#ifndef INDICATOR_EXTRACTOR_H
#define INDICATOR_EXTRACTOR_H

#include <string>
#include <vector>

#include "evidenceNode.h"

struct Indicators {
    std::vector<std::string> urls;
    std::vector<std::string> domains;
    std::vector<std::string> ips;
    std::vector<std::string> files;
    std::vector<std::string> processes;
    std::vector<std::string> users;
};

class IndicatorExtractor {
   public:
    static Indicators extract(const EvidenceNode& node);

   private:
    static void extractUrls(const std::string& text, Indicators& indicators);
    static void extractIps(const std::string& text, Indicators& indicators);
    static void extractFiles(const std::string& text, Indicators& indicators);
    static void extractProcesses(const std::string& text,
                                 Indicators& indicators);
    static void extractDomains(Indicators& indicators);
};

#endif