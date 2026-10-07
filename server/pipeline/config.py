from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

TOOLS = [
    ("COLLECTOR", ROOT / "collector" / "collector.exe"),
    ("CONSTRUCTOR", ROOT / "constructor" / "constructor.exe"),
    ("CORRELATION", ROOT / "correlation" / "correlation.exe"),
    ("RISK", ROOT / "risk" / "risk.exe"),
]

OUTPUTS = {
    "browser_history": ROOT / "output" / "collector_output" / "browser_history.json",
    "event_logs": ROOT / "output" / "collector_output" / "event_logs.json",
    "network_connections": ROOT / "output" / "collector_output" / "network_connections.json",
    "processes": ROOT / "output" / "collector_output" / "processes.json",
    "timeline": ROOT / "output" / "constructor_output" / "timeline.json",
    "correlations": ROOT / "output" / "correlation_output" / "correlations.json",
    "risk": ROOT / "output" / "risk_output" / "risk.json",
}