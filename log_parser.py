import os
from collections import Counter
from datetime import datetime

LOG_FILE_PATH = "logs/waf.log"

def parse_logs():
    if not os.path.exists(LOG_FILE_PATH):
        return {
            "timestamps": [],
            "ip_counts": {},
            "pattern_counts": {}
        }

    timestamps = []
    ip_counter = Counter()
    pattern_counter = Counter()

    with open(LOG_FILE_PATH, "r") as f:
        for line in f:
            # Example: [BLOCKED] Time=2025-07-21T14:33:58.123456, IP=127.0.0.1, Payload=..., Reason=...
            if "Time=" in line and "IP=" in line and "Reason=" in line:
                try:
                    parts = line.strip().split(", ")
                    time_part = parts[0].split("Time=")[1].strip()
                    ip_part = parts[1].split("IP=")[1].strip()
                    reason_part = parts[3].split("Reason=")[1].strip()

                    timestamps.append(time_part)
                    ip_counter[ip_part] += 1
                    pattern_counter[reason_part] += 1
                except IndexError:
                    continue  # Malformed line

    return {
        "timestamps": timestamps,
        "ip_counts": dict(ip_counter),
        "pattern_counts": dict(pattern_counter)
    }

def get_raw_logs():
    if not os.path.exists(LOG_FILE_PATH):
        return []
    with open(LOG_FILE_PATH, "r") as f:
        return f.readlines()
