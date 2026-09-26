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
    std::vector<std::string> hashes;
    std::vector<std::string> hosts;
};

class IndicatorExtractor {
   public:
    static Indicators extract(const EvidenceNode& node);

   private:
    static void extractBrowserHistory(const EvidenceNode& node,
                                      Indicators& indicators);

    static void extractBrowserDownload(const EvidenceNode& node,
                                       Indicators& indicators);

    static void extractProcess(const EvidenceNode& node,
                               Indicators& indicators);

    static void extractNetwork(const EvidenceNode& node,
                               Indicators& indicators);

    static void extractFile(const EvidenceNode& node, Indicators& indicators);

    static void extractEventLog(const EvidenceNode& node,
                                Indicators& indicators);
};

#endif