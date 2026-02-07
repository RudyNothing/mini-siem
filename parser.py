import re
from datetime import datetime

LOG_FILE = "logs/auth.log"

timestamp_pattern = re.compile(r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+\d{2}:\d{2})')


event_patterns = {
    "ssh_failed_invalid": re.compile(r'Failed password for invalid user (?P<user>\w+) from (?P<ip>[\d\.]+)'),
    "ssh_failed_valid": re.compile(r'Failed password for (?P<user>\w+) from (?P<ip>[\d\.]+)'),
    "ssh_accepted": re.compile(r'Accepted password for (?P<user>\w+) from (?P<ip>[\d\.]+)'),
    "pam_failure": re.compile(r'pam_unix\(sshd:auth\): authentication failure'),
    "sudo_command": re.compile(r'sudo: (?P<user>\w+) : .* COMMAND=(?P<command>.+)')
}

events = []

with open(LOG_FILE,"r") as file:
    for line in file:
        ts_match = timestamp_pattern.search(line)
        timestamp = ts_match.group("timestamp") if ts_match else "UNKNOWN"
        
        for event_type, pattern in event_patterns.items():
            match = pattern.search(line)
            if match:
                data = match.groupdict()
                
                events.append({
                    "timestamp": timestamp,
                    "event_type": event_type,
                    "user": data.get("user","N/A"),
                    "ip": data.get("ip","LOCAL"),
                    "command": data.get("command","N/A")
                })
                
for e in events:
    print(e)