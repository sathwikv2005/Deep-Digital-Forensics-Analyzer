#include <filesystem>
#include <iostream>
#include <memory>

#include "executionPathRule.h"
#include "networkRule.h"
#include "processRule.h"
#include "riskEngine.h"

#define TIMELINE_PATH "..\\output\\constructor_output\\timeline.json"
#define CORRELATION_PATH "..\\output\\correlation_output\\correlations.json"
#define OUTPUT_DIR "..\\output\\risk_output"
#define OUTPUT_PATH "..\\output\\risk_output\\risk.json"

int main() {
    try {
        std::filesystem::create_directories(OUTPUT_DIR);

        RiskEngine engine(TIMELINE_PATH, CORRELATION_PATH);

        engine.addRule(std::make_unique<ProcessRule>());

        engine.addRule(std::make_unique<ExecutionPathRule>());

        engine.addRule(std::make_unique<NetworkRule>());

        auto findings = engine.analyze();

        engine.writeOutput(OUTPUT_PATH, findings);

        std::cout << "Risk analysis completed.\n";

        std::cout << "Generated " << findings.size() << " risk findings.\n";

        std::cout << "Output: " << OUTPUT_PATH << '\n';
    } catch (const std::exception& e) {
        std::cerr << "Risk engine error: " << e.what() << '\n';

        return 1;
    }

    return 0;
}