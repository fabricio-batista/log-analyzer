import re


CRASH_PATTERNS = [
    {
        "name": "Fatal exception",
        "regex": re.compile(r"FATAL EXCEPTION", re.IGNORECASE),
        "severity": "HIGH"
    },
    {
        "name": "ANR",
        "regex": re.compile(r"\bANR\b|Application Not Responding", re.IGNORECASE),
        "severity": "HIGH"
    },
    {
        "name": "NullPointerException",
        "regex": re.compile(r"NullPointerException", re.IGNORECASE),
        "severity": "MEDIUM"
    },
    {
        "name": "SecurityException",
        "regex": re.compile(r"SecurityException", re.IGNORECASE),
        "severity": "MEDIUM"
    },
    {
        "name": "ActivityNotFoundException",
        "regex": re.compile(r"ActivityNotFoundException", re.IGNORECASE),
        "severity": "LOW"
    }
]


def detect_android_crashes(events):
    findings = []

    for event in events:
        message = event.get("message", "")

        for pattern in CRASH_PATTERNS:
            if pattern["regex"].search(message):
                findings.append({
                    "severity": pattern["severity"],
                    "detector": "android_crashes",
                    "title": "Android crash or exception detected",
                    "matched": pattern["name"],
                    "tag": event.get("tag"),
                    "pid": event.get("pid"),
                    "line": event.get("raw")
                })

    return findings