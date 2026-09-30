import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent

TOOLS = [
    ("COLLECTOR", ROOT / "collector" / "collector.exe"),
    ("CONSTRUCTOR", ROOT / "constructor" / "constructor.exe"),
    ("CORRELATION", ROOT / "correlation" / "correlation.exe"),
    ("RISK", ROOT / "risk" / "risk.exe"),
]


def run_tool(name, executable):
    print("\n" + "=" * 70, flush=True)
    print(f"  RUNNING {name}", flush=True)
    print(f"  {executable}", flush=True)
    print("=" * 70, flush=True)

    if not executable.exists():
        print(f"[ERROR] Executable not found: {executable}", flush=True)
        return False

    try:
        process = subprocess.Popen(
            [str(executable)],
            cwd=executable.parent,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        # Show stdout live while the process is running
        for line in iter(process.stdout.readline, ""):
            print(f"[{name}] {line}", end="", flush=True)

        process.stdout.close()
        process.wait()

        print("\n" + "-" * 70, flush=True)

        if process.returncode != 0:
            print(
                f"[ERROR] {name} exited with code {process.returncode}",
                flush=True
            )
            return False

        print(f"[OK] {name} completed successfully", flush=True)

        return True

    except Exception as e:
        print(f"[ERROR] Failed to run {name}: {e}", flush=True)
        return False


def main():
    print("=" * 70, flush=True)
    print("       DEEP AI DIGITAL FORENSICS ANALYSIS", flush=True)
    print("              Pipeline Runner", flush=True)
    print("=" * 70, flush=True)

    for i, (name, executable) in enumerate(TOOLS):
        success = run_tool(name, executable)

        if not success:
            print("\n[PIPELINE STOPPED]", flush=True)
            sys.exit(1)

        # Wait 1 second before starting the next tool
        if i < len(TOOLS) - 1:
            print(
                f"\n[PIPELINE] Waiting 1 second before starting next tool...",
                flush=True
            )
            time.sleep(1)

    print("\n" + "=" * 70, flush=True)
    print("  ALL TOOLS COMPLETED SUCCESSFULLY", flush=True)
    print("=" * 70, flush=True)


if __name__ == "__main__":
    main()