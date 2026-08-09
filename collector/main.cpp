#include <iostream>
#include <vector>

#include "collectors/eventLogCollector.h"
#include "serialization/evidenceSerializer.h"

int main() {
    EventLogCollector eventCollector;

    std::vector<Evidence> evidence = eventCollector.collect();

    std::cout << "Collected " << evidence.size() << " events\n";

    if (!EvidenceSerializer::write("output/event_logs.json", evidence)) {
        std::cerr << "Failed to write event logs\n";
        return 1;
    }

    std::cout << "Evidence written successfully\n";

    return 0;
}