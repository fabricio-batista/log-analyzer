import re


KERNEL_PATTERNS = [
    {
        "name": "SELinux AVC denial",
        "regex": re.compile(r"avc:\s*denied", re.IGNORECASE),
        "severity": "MEDIUM"
    },
    {
        "name": "Audit event",
        "regex": re.compile(r"\baudit\b", re.IGNORECASE),
        "severity": "INFO"
    },
    {
        "name": "Capability event",
        "regex": re.compile(r"\bcapability\b", re.IGNORECASE),
        "severity": "INFO"
    },
    {
        "name": "Segfault",
        "regex": re.compile(r"segfault", re.IGNORECASE),
        "severity": "HIGH"
    },
    {
        "name": "Kernel panic/oops",
        "regex": re.compile(r"kernel panic|Oops", re.IGNORECASE),
        "severity": "CRITICAL"
    },
    {
        "name": "Binder event",
        "regex": re.compile(r"\bbinder\b", re.IGNORECASE),
        "severity": "INFO"
    },
    {
        "name": "Service exited/killed",
        "regex": re.compile(r"service .* exited|killed", re.IGNORECASE),
        "severity": "MEDIUM"
    }
]


def detect_kernel_security(events):
    findings = []

    for event in events:
        message = event.get("message", "")

        for pattern in KERNEL_PATTERNS:
            if pattern["regex"].search(message):
                findings.append({
                    "severity": pattern["severity"],
                    "detector": "kernel_security",
                    "title": "Kernel/security-related event detected",
                    "matched": pattern["name"],
                    "line": event.get("raw")
                })

    return findings