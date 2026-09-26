#include <iostream>

#include "collectors/browserCollector.h"
#include "collectors/eventLogCollector.h"
#include "collectors/networkCollector.h"
#include "serialization/evidenceSerializer.h"

#define OUTPUT_DIR "../output/collector_output"

int main() {
    EventLogCollector eventCollector;
    BrowserCollector browserCollector;
    NetworkCollector networkCollector;

    auto eventEvidence = eventCollector.collect();
    auto browserEvidence = browserCollector.collect();
    auto networkEvidence = networkCollector.collect();

    std::cout << "Collected " << eventEvidence.size() << " Windows events\n";

    std::cout << "Collected " << browserEvidence.size() << " browser events\n";

    std::cout << "Collected " << networkEvidence.size() << " network events\n";

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

    std::cout << "Evidence written successfully\n";

    return 0;
}