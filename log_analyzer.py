import argparse
from pathlib import Path

from parsers.android_logcat import parse_logcat_file
from parsers.dmesg import parse_dmesg_file
from collectors.adb_logcat import capture_logcat
from collectors.adb_dmesg import capture_dmesg

from detectors.android_sensitive_data import detect_sensitive_data
from detectors.android_crashes import detect_android_crashes
from detectors.android_security import detect_android_security
from detectors.kernel_security import detect_kernel_security

from reports.report_generator import generate_report


def run_detectors(events, log_type):
    findings = []

    if log_type == "logcat":
        findings.extend(detect_sensitive_data(events))
        findings.extend(detect_android_crashes(events))
        findings.extend(detect_android_security(events))

    elif log_type == "dmesg":
        findings.extend(detect_kernel_security(events))

    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Log Analyzer - Android logcat, dmesg and web log analysis tool"
    )

    parser.add_argument("--file", help="Path to log file")
    parser.add_argument("--type", choices=["logcat", "dmesg", "apache", "nginx", "generic"], help="Log type")
    parser.add_argument("--capture-logcat", action="store_true", help="Capture logcat from connected Android device")
    parser.add_argument("--capture-dmesg", action="store_true", help="Capture dmesg from connected Android device")
    parser.add_argument(
    "-s",
    "--serial",
    "--barcode",
    dest="device_serial",
    help="ADB device serial/barcode. Use when multiple devices are connected."
    )
    parser.add_argument("--package", help="Android package name to filter logcat by PID")
    parser.add_argument("--output", default="output/report.json", help="Output JSON report path")
    parser.add_argument("--text-output", default=None, help="Output TXT report path")
    parser.add_argument("--max-findings", type=int, default=20, help="Max findings to show per severity in terminal/TXT report")

    args = parser.parse_args()

    log_file = args.file
    log_type = args.type

    if args.capture_logcat:
        log_file = capture_logcat(
        package=args.package,
        device_serial=args.device_serial
    )
        log_type = "logcat"

    elif args.capture_dmesg: 
        log_file = capture_dmesg(
        device_serial=args.device_serial
    )
        log_type = "dmesg"

    if not log_file or not log_type:
        parser.error("You must provide --file and --type, or use --capture-logcat / --capture-dmesg")

    if log_type == "logcat":
        events = parse_logcat_file(log_file)
    elif log_type == "dmesg":
        events = parse_dmesg_file(log_file)
    else:
        raise NotImplementedError(f"Parser for {log_type} is not implemented yet")

    findings = run_detectors(events, log_type)

    generate_report(
        events=events,
        findings=findings,
        output_path=args.output,
        source=log_type,
        text_output_path=args.text_output,
        max_findings_per_severity=args.max_findings
    )

if __name__ == "__main__":
    main()