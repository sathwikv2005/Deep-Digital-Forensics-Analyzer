import ctypes
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


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def relaunch_as_admin():
    script = Path(__file__).resolve()

    params = f'-u "{script}"'

    if len(sys.argv) > 1:
        params += " " + " ".join(
            f'"{arg}"'
            for arg in sys.argv[1:]
        )

    result = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        params,
        str(ROOT),
        1
    )

    if result <= 32:
        print(
            "[ERROR] Failed to request Administrator privileges.",
            flush=True
        )
        input("\nPress ENTER to exit...")
        sys.exit(1)

    sys.exit(0)


def run_tool(name, executable):
    print("\n" + "=" * 70, flush=True)
    print(f"  RUNNING {name}", flush=True)
    print(f"  {executable}", flush=True)
    print("=" * 70, flush=True)

    if not executable.exists():
        print(
            f"[ERROR] Executable not found: {executable}",
            flush=True
        )
        return False

    try:
        process = subprocess.Popen(
            [str(executable)],
            cwd=str(executable.parent),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        while True:
            line = process.stdout.readline()

            if line:
                print(
                    f"[{name}] {line}",
                    end="",
                    flush=True
                )

            if process.poll() is not None:
                remaining = process.stdout.read()

                if remaining:
                    print(
                        f"[{name}] {remaining}",
                        end="",
                        flush=True
                    )

                break

        process.stdout.close()

        return_code = process.wait()

        print("\n" + "-" * 70, flush=True)

        if return_code != 0:
            print(
                f"[ERROR] {name} exited with code {return_code}",
                flush=True
            )
            return False

        print(
            f"[OK] {name} completed successfully",
            flush=True
        )

        return True

    except Exception as e:
        print(
            f"[ERROR] Failed to run {name}: {e}",
            flush=True
        )
        return False


def main():
    if not is_admin():
        print(
            "[PIPELINE] Requesting Administrator privileges...",
            flush=True
        )

        relaunch_as_admin()

    print("=" * 70, flush=True)
    print(
        "       DEEP AI DIGITAL FORENSICS ANALYSIS",
        flush=True
    )
    print(
        "              Pipeline Runner",
        flush=True
    )
    print("=" * 70, flush=True)

    print(
        "\n[PIPELINE] Running with Administrator privileges.",
        flush=True
    )

    print(
        f"[PIPELINE] Root: {ROOT}",
        flush=True
    )

    for i, (name, executable) in enumerate(TOOLS):

        success = run_tool(
            name,
            executable
        )

        if not success:
            print(
                "\n[PIPELINE STOPPED]",
                flush=True
            )

            input("\nPress ENTER to close...")
            sys.exit(1)

        if i < len(TOOLS) - 1:
            print(
                "\n[PIPELINE] Waiting 1 second before "
                "starting next tool...",
                flush=True
            )

            time.sleep(1)

    print("\n" + "=" * 70, flush=True)

    print(
        "  ALL TOOLS COMPLETED SUCCESSFULLY",
        flush=True
    )

    print("=" * 70, flush=True)

    input("\nPress ENTER to close...")


if __name__ == "__main__":
    main()