#include <iostream>
#include <vector>

#include "collectors/eventLogCollector.h"

int main() {
    EventLogCollector eventCollector;

    std::vector<Evidence> evidence = eventCollector.collect();

    std::cout << "Collected " << evidence.size() << " events\n\n";

    for (const auto& event : evidence) {
        std::cout << "Source: " << event.source << '\n';
        std::cout << "Timestamp: " << event.timestamp << '\n';
        std::cout << "Category: " << event.category << '\n';
        std::cout << "Description:\n" << event.description << '\n';
        std::cout << "Raw:\n" << event.raw << '\n';
        std::cout << "----------------------------------------\n";
    }

    return 0;
}