import re


ANDROID_SECURITY_PATTERNS = [
    {
        "name": "Permission Denial",
        "regex": re.compile(r"Permission Denial|Permission denied", re.IGNORECASE),
        "severity": "MEDIUM"
    },
    {
        "name": "Component not exported",
        "regex": re.compile(r"not exported from uid|not exported", re.IGNORECASE),
        "severity": "INFO"
    },
    {
        "name": "Requires permission",
        "regex": re.compile(r"requires .*permission", re.IGNORECASE),
        "severity": "INFO"
    },
    {
        "name": "SELinux denial",
        "regex": re.compile(r"avc:\s*denied|SELinux", re.IGNORECASE),
        "severity": "MEDIUM"
    },
    {
        "name": "Cleartext HTTP traffic",
        "regex": re.compile(r"Cleartext HTTP traffic", re.IGNORECASE),
        "severity": "MEDIUM"
    },
    {
        "name": "SSL handshake error",
        "regex": re.compile(r"SSLHandshakeException|CertPathValidatorException|Trust anchor", re.IGNORECASE),
        "severity": "INFO"
    },
    {
        "name": "Keystore event",
        "regex": re.compile(r"AndroidKeyStore|KeyStore|EncryptedSharedPreferences", re.IGNORECASE),
        "severity": "INFO"
    }
]


def detect_android_security(events):
    findings = []

    for event in events:
        message = event.get("message", "")

        for pattern in ANDROID_SECURITY_PATTERNS:
            if pattern["regex"].search(message):
                findings.append({
                    "severity": pattern["severity"],
                    "detector": "android_security",
                    "title": "Android security-related event detected",
                    "matched": pattern["name"],
                    "tag": event.get("tag"),
                    "pid": event.get("pid"),
                    "line": event.get("raw")
                })

    return findings