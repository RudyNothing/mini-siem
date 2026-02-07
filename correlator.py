from collections import defaultdict
from datetime import datetime, timedelta
import re
import csv

LOG_FILE = "logs/auth.log"

alerted_ips = set()



#Regex Pattern
timestamp_pattern = re.compile(r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+\d{2}:\d{2})')

failed_pattern = re.compile(r'Failed password .* from (?P<ip>[\d\.]+)')

accepted_pattern = re.compile(r'Accepted password .* from (?P<ip>[\d\.]+)')

failed_attempts = defaultdict(list)
alerts = []

with open(LOG_FILE, "r") as file:
    for line in file:
        ts_match = timestamp_pattern.search(line)
        if not ts_match:
            continue
        
        timestamp = datetime.fromisoformat(ts_match.group("timestamp"))
        
        failed_match = failed_pattern.search(line)
        accepted_match = accepted_pattern.search(line)
        
        if failed_match:
            ip = failed_match.group("ip")
            failed_attempts[ip].append(timestamp)
            
        if accepted_match:
            ip = accepted_match.group("ip")
            
            if ip in failed_attempts:
                recent_failures = [ t for t in failed_attempts[ip]
                                   if timestamp - t <= timedelta(minutes=2)
                                ]
                if len(recent_failures) >= 3:
                   alerts.append({
                                    "type": "POSSIBLE_COMPROMISE",
                                    "severity": "CRITICAL",
                                    "ip": ip,
                                    "failures": len(recent_failures),
                                    "time": timestamp.isoformat()
                                })

                    
#Detect brute force
for ip, times in failed_attempts.items():
    times.sort()   
    for i in range(len(times)):
        window = [t for t in times
                  if times[i] <= t <=times[i] + timedelta(minutes=2)
                ]
        if len(window) >= 5:
            alerts.append({
                "type": "BRUTE_FORCE",
                "ip": ip,
                "failures": len(window),
                "start": times[i]
            })
            break
    
if ip not in alerted_ips:
    alerts.append({...})
    alerted_ips.add(ip)

    
for alert in alerts:
    print(alert)
    


alerts = [a for a in alerts if isinstance(a, dict)]
#CSV Exports

if alerts:
    with open("alerts.csv", "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=alerts[0].keys())
        writer.writeheader()
        writer.writerows(alerts)
    
    print("Alerts exported to alerts.csv")
else:
    print("No alerts to export")
