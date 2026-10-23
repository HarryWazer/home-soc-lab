# Home SOC Lab — Attack Detection & Incident Response
A self-built virtual Security Operations Center lab integrating Windows endpoint telemetry with Wazuh SIEM detection, simulating four real-world attack techniques and documenting each one as a full incident response case, mapped to MITRE ATT&CK.
## Overview
This project simulates a small corporate environment with an attacker and a defender operating side by side. Four attack scenarios were executed, detected (or deliberately not detected, to study visibility gaps), analyzed, and documented as formal incident reports — the way a junior SOC analyst would in a real investigation.
## Architecture
```
┌─────────────────┐
│   Kali Linux    │
│   Attacker      │
│  192.168.56.30  │
└────────┬────────┘
         │ attacks
         ▼
┌─────────────────────┐
│   Windows 11 VM     │
│   Victim / Endpoint │
│   192.168.56.20     │
└──────────┬───────────┘
         │ logs / events (Wazuh agent)
         ▼
┌─────────────────────┐
│       Wazuh          │
│   SIEM / XDR Server   │
│   192.168.56.10       │
└──────────┬───────────┘
         │ alerts
         ▼
┌─────────────────────┐
│   SOC Dashboard       │
│   Investigation        │
└─────────────────────┘
```
All three machines run in VirtualBox on an isolated Host-only network (`192.168.56.0/24`), with no bridged access to the physical network, so that attack traffic never leaves the lab.
## Tech Stack
- **SIEM/XDR:** Wazuh 4.14.8 (manager, indexer, dashboard)
- **Victim:** Windows 11 Enterprise Evaluation, Wazuh agent
- **Attacker:** Kali Linux (Hydra, Nmap, xfreerdp)
- **Virtualization:** Oracle VirtualBox, Host-only networking
## Attack Scenarios
| # | Scenario | Technique | Detected? | Report |
|---|---|---|---|---|
| 1 | RDP Brute Force | T1110.001 — Password Guessing | ✅ Yes | [INC-001](incidents/INC-001.md) |
| 2 | Suspicious PowerShell | T1057, T1059.001, T1003.001 | ⚠️ Partial | [INC-002](incidents/INC-002.md) |
| 3 | Persistence (Scheduled Task) | T1053.005 | ✅ Yes | [INC-003](incidents/INC-003.md) |
| 4 | Network Reconnaissance | T1595.001, T1046, T1018 | ❌ No (documented gap) | [INC-004](incidents/INC-004.md) |
Each report includes: detection source, timeline, raw evidence, root-cause analysis, MITRE ATT&CK mapping, and recommended remediation — not just "ran a tool, saw an alert."
Greek-language versions of all four reports are also included (`INC-00X_el.md`).
## Key Findings
- **Weak credentials defeat defense-in-depth.** A password identical to the username made the brute-force attack in INC-001 trivial, despite a correctly logging SIEM.
- **Base64 obfuscation does not defeat PowerShell Script Block Logging** — Windows decodes and logs the final command regardless of encoding (INC-002).
- **Not every alert in a time window is attacker-driven.** Wazuh's own SCA module generated PowerShell telemetry that coincided with the test window in INC-002 and had to be excluded during triage — a realistic false-positive lesson.
- **Visibility gaps have different root causes, and different fixes.** INC-002 and INC-003 were blocked by *disabled Windows audit settings* (fixable via configuration). INC-004 was blocked by a *missing Wazuh decoder* for the native Windows Firewall log format (not fixable by configuration alone — requires custom rule development or a different monitoring approach).
- **Collection is not detection.** In INC-004, the Wazuh agent actively read the relevant log file end-to-end, yet zero alerts were generated — a reminder to validate the full pipeline (agent → server → decoder → rule → index) before trusting a monitoring control.
See [mitre/attack-mapping.md](mitre/attack-mapping.md) for the full consolidated MITRE ATT&CK coverage summary across all four scenarios.
## Repository Structure
```
home-soc-lab/
├── incidents/          # Full incident reports (English + Greek)
├── mitre/              # Consolidated MITRE ATT&CK mapping
├── screenshots/         # Evidence captured during each scenario
└── README.md
```
## About
Built as a hands-on follow-up to an academic thesis on OpenSearch-based DoS/DDoS detection with machine learning, to gain practical experience in SOC analyst workflows: log collection, detection engineering, false-positive triage, and incident documentation — distinct from, and complementary to, the ML-focused thesis work.
**Author:** Harry Kotsis
