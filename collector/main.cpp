#include <filesystem>
#include <iostream>

#include "collectors/browserCollector.h"
#include "collectors/eventLogCollector.h"
#include "collectors/networkCollector.h"
#include "collectors/processCollector.h"
#include "serialization/evidenceSerializer.h"

#define OUTPUT_DIR "../output/collector_output"

int main() {
    try {
        std::filesystem::create_directories(OUTPUT_DIR);

        EventLogCollector eventCollector;
        BrowserCollector browserCollector;
        NetworkCollector networkCollector;
        ProcessCollector processCollector;

        std::cout << "========================================\n";
        std::cout << "Deep AI Digital Forensics Collector\n";
        std::cout << "========================================\n\n";

        std::cout << "[1/4] Collecting Windows event logs...\n";

        auto eventEvidence = eventCollector.collect();

        std::cout << "\n[2/4] Collecting browser history...\n";

        auto browserEvidence = browserCollector.collect();

        std::cout << "\n[3/4] Collecting network events...\n";

        auto networkEvidence = networkCollector.collect();

        std::cout << "\n[4/4] Collecting process events...\n";

        auto processEvidence = processCollector.collect();

        std::cout << "\n========================================\n";
        std::cout << "Collection complete.\n";
        std::cout << "========================================\n\n";

        std::cout << "Collected:\n";

        std::cout << "  Windows events: " << eventEvidence.size() << '\n';

        std::cout << "  Browser events: " << browserEvidence.size() << '\n';

        std::cout << "  Network events: " << networkEvidence.size() << '\n';

        std::cout << "  Process events: " << processEvidence.size() << '\n';

        std::cout << "\nWriting evidence...\n";

        bool success = true;

        success &= EvidenceSerializer::write(OUTPUT_DIR "/event_logs.json",
                                             eventEvidence);

        success &= EvidenceSerializer::write(OUTPUT_DIR "/browser_history.json",
                                             browserEvidence);

        success &= EvidenceSerializer::write(
            OUTPUT_DIR "/network_connections.json", networkEvidence);

        success &= EvidenceSerializer::write(OUTPUT_DIR "/processes.json",
                                             processEvidence);

        if (!success) {
            std::cerr << "Failed to write one or more evidence files.\n";

            return 1;
        }

        std::cout << "\nEvidence written successfully.\n";

    } catch (const std::exception& e) {
        std::cerr << "Collector error: " << e.what() << '\n';

        return 1;
    }

    return 0;
}