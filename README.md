# Deep Digital Forensics Analyzer

An AI-assisted digital forensics analysis platform designed to collect, process, correlate, and analyze digital evidence from Windows systems.

The project combines **native C++ evidence collection** with structured evidence serialization and an analysis pipeline to help investigators reconstruct system activity and identify potentially significant events.

## Features

- **Windows Event Log Collection**
  - Collects events from Windows Event Log channels using the native Windows Event Log API.
  - Extracts relevant event information into a structured evidence format.

- **Structured Evidence Model**
  - Represents collected forensic artifacts using a common `Evidence` structure.
  - Provides consistent fields such as source, timestamp, category, and description.

- **Evidence Serialization**
  - Serializes collected evidence into JSON for downstream processing and analysis.
  - Uses [nlohmann/json](https://github.com/nlohmann/json).

- **Modular Collector Architecture**
  - Individual forensic data sources are implemented as independent collectors.
  - Designed to make additional collectors easy to add without modifying the existing collection pipeline.

- **AI-Assisted Analysis**
  - Designed to correlate collected evidence and identify suspicious or anomalous activity.
  - Provides a foundation for automated forensic analysis and event reconstruction.

## Architecture

The project follows a modular pipeline:

```text
┌─────────────────────┐
│   Evidence Sources  │
│                     │
│ Windows Event Logs  │
│ File System         │
│ Browser Artifacts   │
│ Network Data        │
│ Other Artifacts     │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│      Collectors     │
│                     │
│  EventLogCollector  │
│  Future Collectors  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Evidence Serializer │
│                     │
│        JSON         │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│   Analysis Engine   │
│                     │
│ Correlation         │
│ Anomaly Detection   │
│ Timeline Analysis   │
│ AI/ML Analysis      │
└─────────────────────┘
```

## Building

### Requirements

- Windows 10/11
- C++ compiler with Windows API support
- CMake
- MinGW or MSVC

The Windows Event Log collector requires the Windows Event Log API and links against:

```text
wevtapi.lib
```

### Build with CMake

```powershell
cmake -S collector -B collector/build -G "MinGW Makefiles"
cmake --build collector/build
```

The resulting binaries will be generated inside the build directory.

## Usage

Run the collector with appropriate permissions:

```powershell
.\collector.exe
```

Collected evidence is serialized into JSON and can then be passed to the analysis pipeline.

Example evidence:

```json
{
	"source": "Windows Event Log",
	"timestamp": "2026-08-12T10:30:00Z",
	"category": "System",
	"description": "System event detected"
}
```

## Collector Development

Collectors are designed around a common interface so that new evidence sources can be added independently.

A collector typically exposes:

```cpp
std::vector<Evidence> collect();
```

This allows the collection layer to return structured evidence rather than raw strings, making the output easier to process, serialize, correlate, and analyze.

### Adding a Collector

A new collector should:

1. Implement the collector interface.
2. Collect artifacts from its target evidence source.
3. Convert artifacts into `Evidence` objects.
4. Return the collected evidence.
5. Integrate with the evidence serialization pipeline.

Collectors include:

- Windows Event Logs
- Windows Registry
- File system metadata
- Browser history
- Prefetch files
- USB device history
- Windows Defender events
- Network artifacts
- Application logs
- Process execution history

## License

This project is licensed under the **MIT License**. See [`LICENSE`](LICENSE) for details.

## Disclaimer

This software is intended for legitimate digital forensics, security research, incident response, and authorized system analysis.

Always obtain appropriate authorization before collecting or analyzing data from a system.
