# Log Analyzer

Log Analyzer is a Python CLI tool focused on Android security testing and mobile pentest log analysis.

The tool captures and analyzes Android `logcat` and `dmesg` logs, detects relevant security-related events, highlights possible sensitive data exposure, and generates readable reports in both terminal/TXT and JSON formats.

This project was created as a lightweight MVP to help analyze large Android logs more efficiently during mobile application security assessments.

---

## Features

Current MVP 0.1 features:

* Analyze saved Android logcat files
* Capture Android logcat continuously through ADB
* Capture logcat from a specific package using PID filtering
* Select a specific Android device when multiple devices are connected
* Attempt to capture Android dmesg logs through ADB
* Parse Android logcat events
* Parse dmesg/kernel log events
* Detect possible sensitive data exposure in logcat
* Detect Android crashes and exceptions
* Detect Android security-related events
* Detect kernel/security-related events in dmesg
* Generate JSON report
* Generate TXT report with terminal-style output
* Show log level summary
* Show log level legend
* Show severity summary
* Show severity legend
* Show top logcat tags
* Sort findings by severity

---

## Project Structure

```text
log-analyzer/
├── log_analyzer.py
├── collectors/
│   ├── __init__.py
│   ├── adb_logcat.py
│   └── adb_dmesg.py
├── parsers/
│   ├── __init__.py
│   ├── android_logcat.py
│   ├── dmesg.py
│   ├── apache.py
│   ├── nginx.py
│   └── generic.py
├── detectors/
│   ├── __init__.py
│   ├── android_sensitive_data.py
│   ├── android_crashes.py
│   ├── android_security.py
│   ├── kernel_security.py
│   ├── brute_force.py
│   ├── directory_scan.py
│   ├── sqli.py
│   ├── xss.py
│   └── lfi.py
├── reports/
│   ├── __init__.py
│   └── report_generator.py
└── output/
    ├── report.json
    └── report.txt
```

---

## Requirements

* Python 3.10+
* Android Debug Bridge

Check if ADB is available:

```bash
adb version
```

Check connected devices:

```bash
adb devices
```

Example:

```text
List of devices attached
XYZ123	device
ABC987	device
```

---

## Usage

### Analyze a saved logcat file

```bash
python log_analyzer.py --file logcat_test.txt --type logcat
```

### Analyze a saved dmesg file

```bash
python log_analyzer.py --file dmesg_test.txt --type dmesg
```

### Capture logcat continuously

```bash
python log_analyzer.py --capture-logcat
```

The capture runs continuously.

Press `CTRL+C` to stop the capture and continue to the analysis phase.

### Capture logcat from a specific device

Use `-b` or `--barcode` with the ADB device serial:

```bash
python log_analyzer.py --capture-logcat -b XYZ123
```

Equivalent ADB behavior:

```bash
adb -s XYZ123 logcat
```

### Capture logcat from a specific package

```bash
python log_analyzer.py --capture-logcat --package com.example.app
```

### Capture logcat from a specific package and device

```bash
python log_analyzer.py --capture-logcat --package com.example.app -b XYZ123
```

The tool will try to resolve the app PID using:

```bash
adb -s XYZ123 shell pidof com.example.app
```

Then it captures logcat using PID filtering.

### Capture dmesg

```bash
python log_analyzer.py --capture-dmesg
```

### Capture dmesg from a specific device

```bash
python log_analyzer.py --capture-dmesg -b XYZ123
```

Equivalent ADB behavior:

```bash
adb -s XYZ123 shell dmesg
```

Note: On many Android devices, especially non-rooted production builds, `dmesg` access may be restricted.

### Custom report output path

```bash
python log_analyzer.py --file logcat_test.txt --type logcat --output output/my_report.json --text-output output/my_report.txt
```

### Increase findings displayed per severity

```bash
python log_analyzer.py --file logcat_test.txt --type logcat --max-findings 50
```

---

## Log Level Legend

Android logcat uses single-letter log levels:

```text
V: Verbose - highly detailed logs, usually used for deep debugging
D: Debug - debugging information
I: Info - normal informational event
W: Warning - warning or unexpected behavior, not necessarily an error
E: Error - execution error
F: Fatal - fatal error or critical crash
```

---

## Severity Legend

The tool uses its own severity classification.

Important: Severity does not mean a vulnerability is confirmed. It means the finding should be prioritized for manual review.

```text
CRITICAL: Extremely relevant event. May indicate a critical crash, kernel panic, critical leak, or severe failure.
HIGH: High priority for manual review. May indicate sensitive data, token, credential, crash, or critical behavior.
MEDIUM: Relevant finding, but context is required to confirm impact.
LOW: Low priority. Useful for analysis, but usually not an issue by itself.
INFO: Contextual information. Useful during investigation, but not a vulnerability by itself.
```

---

## Example Output

```text
=================================
LOG ANALYZER REPORT
=================================

Source: logcat
Total events: 197312
Findings: 10077

[LOG LEVELS]
I: 91225
D: 59539
W: 21665
E: 15270
V: 9608

[LOG LEVEL LEGEND]
V: Verbose - highly detailed logs, usually used for deep debugging
D: Debug - debugging information
I: Info - normal informational event
W: Warning - warning or unexpected behavior, not necessarily an error
E: Error - execution error
F: Fatal - fatal error or critical crash

[TOP TAGS]
CompatibilityChangeReporter: 6120
WindowManager: 4715
ActivityManager: 3696

[SEVERITY SUMMARY]
HIGH: 12
MEDIUM: 120
INFO: 90

[FINDINGS BY SEVERITY]

========== HIGH (12) ==========

[HIGH] Possible sensitive data leaked in logcat
Detector: android_sensitive_data
Matched: Authorization Bearer token
Tag: OkHttp
Line: Authorization: Bearer eyJhbGciOi...
```

---

## Current Detectors

### Android Sensitive Data

Looks for possible exposure of:

* Password values
* Access tokens
* Refresh tokens
* Authorization Bearer tokens
* JWT tokens
* API keys
* Client secrets
* Session or cookie values
* Possible CPF values
* Possible email addresses

### Android Crashes

Looks for:

* Fatal exceptions
* ANR events
* NullPointerException
* SecurityException
* ActivityNotFoundException

### Android Security Events

Looks for:

* Permission Denial
* Permission denied
* Components not exported
* Required permissions
* SELinux denial
* Cleartext HTTP traffic
* SSL handshake errors
* Certificate validation errors
* Keystore-related events

### Kernel Security / dmesg

Looks for:

* SELinux AVC denials
* Audit events
* Capability events
* Segfaults
* Kernel panic
* Kernel oops
* Binder events
* Killed or exited services

---

## Important Notes

This tool is intended to support mobile security analysis and pentest workflows.

Findings are not automatically confirmed vulnerabilities.

A finding marked as `HIGH` means it should be reviewed first, not that it is definitely exploitable or reportable.

Manual validation is still required.

---

## Known Limitations

MVP 0.1 limitations:

* Some false positives may still appear in sensitive data detection
* Generic keywords such as `token` or `secret` may require manual review
* dmesg capture may fail on restricted or non-rooted Android devices
* Web log parsers and detectors are included in the structure but are not the main focus yet
* No confidence score is available yet
* No triage explanation is available yet
* No HTML report is available yet

---

## Roadmap

Suggested next steps for MVP 0.2:

* Add confidence level to findings
* Add reason field explaining why each finding was created
* Add triage hints for manual validation
* Reduce false positives in sensitive data detection
* Add Android-specific allowlist for noisy system tags
* Add Android-specific allowlist for benign terms
* Separate contextual findings from possible security issues
* Improve token and secret detection
* Add CSV export
* Add HTML report
* Add interactive mode
* Add custom terms and regex search mode

---

## Example Commands

```bash
python log_analyzer.py --file logcat_test.txt --type logcat
```

```bash
python log_analyzer.py --capture-logcat
```

```bash
python log_analyzer.py --capture-logcat -s XYZ123
```

```bash
python log_analyzer.py --capture-logcat --package com.example.app -s XYZ123
```

```bash
python log_analyzer.py --capture-dmesg -s XYZ123
```

```bash
python log_analyzer.py --file dmesg_test.txt --type dmesg
```

```bash
python log_analyzer.py --file logcat_test.txt --type logcat --max-findings 50
```

---

## Status

Current version: MVP 0.1

Status: Functional MVP focused on Android logcat and dmesg analysis.
