import subprocess
from pathlib import Path
from datetime import datetime


def build_adb_command(device_serial=None):
    command = ["adb"]

    if device_serial:
        command.extend(["-s", device_serial])

    return command


def capture_dmesg(device_serial=None):
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if device_serial:
        output_file = output_dir / f"dmesg_{device_serial}_{timestamp}.txt"
    else:
        output_file = output_dir / f"dmesg_{timestamp}.txt"

    command = build_adb_command(device_serial)
    command.extend(["shell", "dmesg"])

    if device_serial:
        print(f"[+] Target device: {device_serial}")

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        errors="ignore"
    )

    content = result.stdout.strip()
    error = result.stderr.strip()

    if not content:
        print("[!] Could not capture dmesg output.")

        if error:
            print(f"[!] adb error: {error}")

        content = (
            "DMESG_CAPTURE_FAILED\n"
            "Possible causes: device without root, restricted kernel dmesg access, "
            "restricted Android build, or insufficient permissions.\n"
        )

    output_file.write_text(content, encoding="utf-8", errors="ignore")

    print(f"[+] dmesg captured: {output_file}")

    return str(output_file)