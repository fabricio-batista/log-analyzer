import re


def build_finding(event, severity, matched, evidence):
    return {
        "severity": severity,
        "detector": "android_sensitive_data",
        "title": "Possible sensitive data leaked in logcat",
        "matched": matched,
        "evidence": evidence,
        "tag": event.get("tag"),
        "pid": event.get("pid"),
        "line": event.get("raw")
    }


SENSITIVE_PATTERNS = [
    {
        "name": "Password value",
        "regex": re.compile(
            r"\b(password|passwd|pwd)\b\s*[:=]\s*[^\s,;]{3,}",
            re.IGNORECASE
        ),
        "severity": "HIGH"
    },
    {
        "name": "Access token value",
        "regex": re.compile(
            r"\b(access_token|refresh_token|auth_token|id_token|token)\b\s*[:=]\s*[a-zA-Z0-9._\-+/=]{8,}",
            re.IGNORECASE
        ),
        "severity": "HIGH"
    },
    {
        "name": "Authorization Bearer token",
        "regex": re.compile(
            r"\bAuthorization\b\s*:\s*Bearer\s+[a-zA-Z0-9._\-+/=]{8,}",
            re.IGNORECASE
        ),
        "severity": "HIGH"
    },
    {
        "name": "JWT token",
        "regex": re.compile(
            r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b"
        ),
        "severity": "HIGH"
    },
    {
        "name": "API key value",
        "regex": re.compile(
            r"\b(api_key|apikey|x-api-key|client_secret|secret_key)\b\s*[:=]\s*[a-zA-Z0-9._\-+/=]{8,}",
            re.IGNORECASE
        ),
        "severity": "HIGH"
    },
    {
        "name": "Session/Cookie value",
        "regex": re.compile(
            r"\b(cookie|sessionid|session_id|session_token)\b\s*[:=]\s*[a-zA-Z0-9._\-+/=]{8,}",
            re.IGNORECASE
        ),
        "severity": "MEDIUM"
    },
    {
        "name": "Possible CPF",
        "regex": re.compile(
            r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b"
        ),
        "severity": "MEDIUM"
    },
    {
        "name": "Possible email address",
        "regex": re.compile(
            r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
        ),
        "severity": "MEDIUM"
    }
]


ANDROID_FALSE_POSITIVE_EMAIL_PATTERNS = [
    re.compile(r"\bandroid\.[a-zA-Z0-9_.-]+@\d", re.IGNORECASE),
    re.compile(r"\bvendor\.[a-zA-Z0-9_.-]+@\d", re.IGNORECASE),
    re.compile(r"\bcom\.android\.[a-zA-Z0-9_.-]+@\d", re.IGNORECASE),
    re.compile(r"\bcom\.google\.android\.[a-zA-Z0-9_.-]+@\d", re.IGNORECASE),
]


NOISY_TAGS_FOR_EMAIL = {
    "PackageManager",
    "HidlServiceManagement"
}


def is_false_positive_email(event, message):
    tag = event.get("tag")

    if tag in NOISY_TAGS_FOR_EMAIL:
        return True

    for pattern in ANDROID_FALSE_POSITIVE_EMAIL_PATTERNS:
        if pattern.search(message):
            return True

    return False


def detect_sensitive_data(events):
    findings = []

    for event in events:
        message = event.get("message", "")
        raw = event.get("raw", "")

        for pattern in SENSITIVE_PATTERNS:
            match = pattern["regex"].search(message)

            if not match:
                continue

            if pattern["name"] == "Possible email address":
                if is_false_positive_email(event, message):
                    continue

            evidence = match.group(0)

            findings.append(
                build_finding(
                    event=event,
                    severity=pattern["severity"],
                    matched=pattern["name"],
                    evidence=evidence
                )
            )

    return findings