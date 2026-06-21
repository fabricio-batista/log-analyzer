import json
from pathlib import Path
from collections import Counter, defaultdict

SEVERITY_LEGEND = {
    "CRITICAL": "Extremely relevant event. May indicate a serious crash, kernel panic, critical leak, or serious failure.",
    "HIGH": "High priority for manual review. May indicate sensitive data, token, credential, crash, or critical behavior.",
    "MEDIUM": "Relevant finding, but needs context to confirm impact.",
    "LOW": "Low priority. May be useful for analysis, but usually does not indicate a problem on its own.",
    "INFO": "Contextual information. Helps in the investigation, but does not represent a vulnerability on its own."
}

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4
}


def severity_sort_key(finding):
    return SEVERITY_ORDER.get(finding.get("severity", "INFO"), 99)


def group_findings_by_severity(findings):
    grouped = defaultdict(list)

    for finding in sorted(findings, key=severity_sort_key):
        grouped[finding.get("severity", "INFO")].append(finding)

    return grouped


def format_terminal_report(events, findings, source, max_findings_per_severity=20):
    lines = []

    lines.append("")
    lines.append("=================================")
    lines.append("LOG ANALYZER REPORT")
    lines.append("=================================")
    lines.append("")

    lines.append(f"Source: {source}")
    lines.append(f"Total events: {len(events)}")
    lines.append(f"Findings: {len(findings)}")

    if source == "logcat":
        levels = Counter(event.get("level") for event in events if event.get("level"))
        tags = Counter(event.get("tag") for event in events if event.get("tag"))

        lines.append("")
        lines.append("[LOG LEVELS]")
        for level, count in levels.most_common():
            lines.append(f"{level}: {count}")

        lines.append("")
        lines.append("[TOP TAGS]")
        for tag, count in tags.most_common(10):
            lines.append(f"{tag}: {count}")

    severity_count = Counter(finding.get("severity", "INFO") for finding in findings)

    lines.append("")
    lines.append("[SEVERITY SUMMARY]")
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severity_count.get(severity, 0)
        if count:
            lines.append(f"{severity}: {count}")

    lines.append("")
    lines.append("[SEVERITY LEGEND]")
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        description = SEVERITY_LEGEND.get(severity)
        if description:
            lines.append(f"{severity}: {description}")

    detector_count = Counter(finding.get("detector", "unknown") for finding in findings)

    lines.append("")
    lines.append("[DETECTOR SUMMARY]")
    for detector, count in detector_count.most_common():
        lines.append(f"{detector}: {count}")

    grouped = group_findings_by_severity(findings)

    lines.append("")
    lines.append("[FINDINGS BY SEVERITY]")

    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        severity_findings = grouped.get(severity, [])

        if not severity_findings:
            continue

        lines.append("")
        lines.append(f"========== {severity} ({len(severity_findings)}) ==========")

        for finding in severity_findings[:max_findings_per_severity]:
            lines.append("")
            lines.append(f"[{finding.get('severity')}] {finding.get('title')}")
            lines.append(f"Detector: {finding.get('detector')}")
            lines.append(f"Matched: {finding.get('matched')}")

            if finding.get("evidence"):
                lines.append(f"Evidence: {finding.get('evidence')}")

            if finding.get("tag"):
                lines.append(f"Tag: {finding.get('tag')}")

            if finding.get("pid"):
                lines.append(f"PID: {finding.get('pid')}")

            lines.append(f"Line: {finding.get('line')}")

        remaining = len(severity_findings) - max_findings_per_severity

        if remaining > 0:
            lines.append("")
            lines.append(
                f"... {remaining} more {severity} findings hidden. "
                f"Check JSON report for full details."
            )

    return "\n".join(lines)


def generate_report(
    events,
    findings,
    output_path,
    source,
    text_output_path=None,
    max_findings_per_severity=20
):
    output = {
        "summary": {
            "source": source,
            "total_events": len(events),
            "findings_count": len(findings)
        },
        "findings": findings
    }

    output_file = Path(output_path)
    output_file.parent.mkdir(exist_ok=True)

    output_file.write_text(
        json.dumps(output, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    report_text = format_terminal_report(
        events=events,
        findings=findings,
        source=source,
        max_findings_per_severity=max_findings_per_severity
    )

    print(report_text)

    if text_output_path is None:
        text_output_path = output_file.with_suffix(".txt")

    text_output_file = Path(text_output_path)
    text_output_file.parent.mkdir(exist_ok=True)

    text_output_file.write_text(
        report_text,
        encoding="utf-8",
        errors="ignore"
    )

    print(f"\n[+] JSON report saved to: {output_file}")
    print(f"[+] TXT report saved to: {text_output_file}")