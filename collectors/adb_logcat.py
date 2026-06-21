import subprocess
from pathlib import Path
from datetime import datetime


def build_adb_command(device_serial=None):
    command = ["adb"]

    if device_serial:
        command.extend(["-s", device_serial])

    return command


def get_pid_by_package(package_name, device_serial=None):
    command = build_adb_command(device_serial)
    command.extend(["shell", "pidof", package_name])

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    if result.returncode != 0 or not result.stdout.strip():
        return None

    return result.stdout.strip().split()[0]


def capture_logcat(package=None, device_serial=None):
    """
    Captures Android logcat in continuous mode.
    Press CTRL+C to stop capture and continue to analysis.
    """
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if device_serial:
        output_file = output_dir / f"logcat_{device_serial}_{timestamp}.txt"
    else:
        output_file = output_dir / f"logcat_{timestamp}.txt"

    command = build_adb_command(device_serial)
    command.append("logcat")

    if package:
        pid = get_pid_by_package(package, device_serial=device_serial)

        if pid:
            command = build_adb_command(device_serial)
            command.extend(["logcat", "--pid", pid])
            print(f"[+] Capturing logcat for package {package} with PID {pid}")
        else:
            print(f"[!] Could not find PID for package: {package}")
            print("[!] Capturing full logcat instead.")

    if device_serial:
        print(f"[+] Target device: {device_serial}")

    print("[+] Starting logcat capture. Press CTRL+C to stop.")
    print(f"[+] Saving to: {output_file}")

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="ignore",
        bufsize=1
    )

    try:
        with open(output_file, "w", encoding="utf-8", errors="ignore") as file:
            for line in process.stdout:
                file.write(line)

    except KeyboardInterrupt:
        print("\n[+] Stopping logcat capture...")

    finally:
        process.terminate()

        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()

    print(f"[+] Logcat captured: {output_file}")

    return str(output_file)