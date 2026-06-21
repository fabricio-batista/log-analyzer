import re


LOGCAT_PATTERN = re.compile(
    r"^(?P<timestamp>\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"(?P<pid>\d+)\s+"
    r"(?P<tid>\d+)\s+"
    r"(?P<level>[VDIWEF])\s+"
    r"(?P<tag>[^:]+):\s?"
    r"(?P<message>.*)$"
)


def parse_logcat_line(line):
    match = LOGCAT_PATTERN.match(line)

    if not match:
        return {
            "source": "logcat",
            "parsed": False,
            "raw": line.rstrip("\n"),
            "message": line.rstrip("\n")
        }

    data = match.groupdict()
    data["source"] = "logcat"
    data["parsed"] = True
    data["raw"] = line.rstrip("\n")

    return data


def parse_logcat_file(file_path):
    events = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            if line.strip():
                events.append(parse_logcat_line(line))

    return events