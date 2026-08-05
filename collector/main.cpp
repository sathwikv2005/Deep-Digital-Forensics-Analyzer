#include <iostream>

#include "collectors/EventLogCollector.h"

int main() {
    EventLogCollector eventCollector;

    if (eventCollector.collect()) {
        std::cout << "Success\n";
    } else {
        std::cout << "Failed\n";
    }

    return 0;
}