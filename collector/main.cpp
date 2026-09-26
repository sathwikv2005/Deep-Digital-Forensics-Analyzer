#include <iostream>

#include "collectors/browserCollector.h"
#include "collectors/eventLogCollector.h"
#include "collectors/networkCollector.h"
#include "collectors/processCollector.h"
#include "serialization/evidenceSerializer.h"

#define OUTPUT_DIR "../output/collector_output"

int main() {
    EventLogCollector eventCollector;
    BrowserCollector browserCollector;
    NetworkCollector networkCollector;
    ProcessCollector processCollector;

    std::cout << "[1/4] Collecting Windows event logs...\n";
    auto eventEvidence = eventCollector.collect();
    std::cout << "      Collected " << eventEvidence.size()
              << " Windows events\n\n";

    std::cout << "[2/4] Collecting browser history...\n";
    auto browserEvidence = browserCollector.collect();
    std::cout << "      Collected " << browserEvidence.size()
              << " browser events\n\n";

    std::cout << "[3/4] Collecting network connections...\n";
    auto networkEvidence = networkCollector.collect();
    std::cout << "      Collected " << networkEvidence.size()
              << " network events\n\n";

    std::cout << "[4/4] Collecting running processes...\n";
    auto processEvidence = processCollector.collect();
    std::cout << "      Collected " << processEvidence.size()
              << " process events\n\n";

    std::cout << "Writing evidence...\n";

    if (!EvidenceSerializer::write(OUTPUT_DIR "/event_logs.json",
                                   eventEvidence)) {
        std::cerr << "Failed to write event logs\n";
        return 1;
    }

    if (!EvidenceSerializer::write(OUTPUT_DIR "/browser_history.json",
                                   browserEvidence)) {
        std::cerr << "Failed to write browser history\n";
        return 1;
    }

    if (!EvidenceSerializer::write(OUTPUT_DIR "/network_connections.json",
                                   networkEvidence)) {
        std::cerr << "Failed to write network connections\n";
        return 1;
    }

    if (!EvidenceSerializer::write(OUTPUT_DIR "/processes.json",
                                   processEvidence)) {
        std::cerr << "Failed to write processes\n";
        return 1;
    }

    std::cout << "\nEvidence written successfully\n";

    return 0;
}