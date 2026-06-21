import re


DMESG_PATTERN = re.compile(
    r"^\[\s*(?P<kernel_time>\d+\.\d+)\]\s?(?P<message>.*)$"
)


def parse_dmesg_line(line):
    match = DMESG_PATTERN.match(line)

    if not match:
        return {
            "source": "dmesg",
            "parsed": False,
            "raw": line.rstrip("\n"),
            "message": line.rstrip("\n")
        }

    data = match.groupdict()
    data["source"] = "dmesg"
    data["parsed"] = True
    data["raw"] = line.rstrip("\n")

    return data


def parse_dmesg_file(file_path):
    events = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            if line.strip():
                events.append(parse_dmesg_line(line))

    return events