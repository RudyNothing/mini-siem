
# 🛡️ Mini SIEM – Log Analysis & Intrusion Detection System

## 📌 Overview

This project is a **Mini Security Information and Event Management (SIEM)** system built using **Python**.
It simulates real-world SOC workflows by collecting, parsing, correlating, and analyzing **Linux authentication logs** to detect suspicious activities such as **brute-force attacks** and **possible account compromise**.

The system was tested using a **Kali Linux attacker** and an **Ubuntu Server victim**, generating realistic SSH and privilege-escalation logs in a controlled lab environment.

---

## 🎯 Objectives

* Simulate real authentication attacks in a safe lab.
* Parse real Ubuntu `auth.log` files.
* Correlate security events over time.
* Detect suspicious login patterns.
* Generate structured security alerts.

---

## 🏗️ Architecture

```
Kali Linux (Attacker)
        |
        v
Ubuntu Server (Victim)
        |
   auth.log
        |
        v
Log Parser (parser.py)
        |
        v
Correlation Engine (correlator.py)
        |
        v
Security Alerts (alerts.csv)
```

---

## ⚙️ Tech Stack

* **Language**: Python 3
* **OS**: Kali Linux, Ubuntu Server
* **Logs**: `/var/log/auth.log`
* **Libraries**:

  * `re` – log pattern matching
  * `datetime` – time-window analysis
  * `collections` – efficient event tracking
  * `csv` – alert export

---

## 🔍 Detection Logic

### 1️⃣ Brute-Force Detection

* Multiple failed SSH login attempts
* Same source IP
* Occurring within a short time window

### 2️⃣ Possible Account Compromise

* Successful SSH login
* Preceded by multiple failed attempts
* Same source IP

---

## 🚨 Sample Alert Output

```json
{
  "type": "POSSIBLE_COMPROMISE",
  "severity": "CRITICAL",
  "ip": "10.0.2.15",
  "failures": 3,
  "time": "2026-01-26T12:26:37+05:30"
}
```

Alerts are also exported to a CSV file for further analysis.

---

## 📂 Project Structure

```
mini-siem/
├── logs/
│   └── auth.log
├── parser.py
├── correlator.py
├── alerts.csv
└── README.md
```

---

## 🧪 Lab Setup

* **Attacker**: Kali Linux
* **Victim**: Ubuntu Server with SSH enabled
* Attacks simulated:

  * Invalid user login attempts
  * Repeated failed SSH logins
  * Successful login after failures
  * Privilege escalation attempts using `sudo`

All testing was performed in an isolated virtual lab.

---

## 🧠 Key Learnings

* Real-world logs are noisy and inconsistent.
* Timestamp normalization is critical.
* Correlation provides more value than raw logs.
* Rule-based detection is widely used in SOCs.
* Small regex mistakes can break detections.

---

## 🚀 Future Enhancements

* Add severity scoring for all alert types.
* Integrate MITRE ATT&CK mapping.
* Build a Streamlit dashboard.
* Add real-time log ingestion.
* Email or webhook-based alerting.
