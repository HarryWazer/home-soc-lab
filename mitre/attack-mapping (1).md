# MITRE ATT&CK Mapping — Home SOC Lab
This document consolidates the MITRE ATT&CK techniques identified across all four attack scenarios simulated in this lab, with references to the detailed incident reports.
## Summary Table
| # | Scenario | Tactic | Technique | ID | Detected by Wazuh? | Incident |
|---|---|---|---|---|---|---|
| 1 | Brute Force (RDP) | Credential Access | Brute Force: Password Guessing | T1110.001 | ✅ Yes (rule 60122) | [INC-001](../incidents/INC-001.md) |
| 2 | Suspicious PowerShell | Discovery | Process Discovery | T1057 | ✅ Yes (rule 91815) | [INC-002](../incidents/INC-002.md) |
| 2 | Suspicious PowerShell | Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | ⚠️ Partial (general technique; not directly tagged by matched rule) | [INC-002](../incidents/INC-002.md) |
| 2 | Suspicious PowerShell | Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 | ❌ No (manual mapping; no corresponding alert confirmed) | [INC-002](../incidents/INC-002.md) |
| 3 | Persistence | Execution | Scheduled Task/Job | T1053.005 | ✅ Yes (rule 60228) | [INC-003](../incidents/INC-003.md) |
| 3 | Persistence | Persistence | Scheduled Task/Job | T1053.005 | ✅ Yes (rule 60228) | [INC-003](../incidents/INC-003.md) |
| 3 | Persistence | Privilege Escalation | Scheduled Task/Job | T1053.005 | ✅ Yes (rule 60228) | [INC-003](../incidents/INC-003.md) |
| 4 | Network Reconnaissance | Reconnaissance | Active Scanning: Scanning IP Blocks | T1595.001 | ❌ No (decoder gap, see INC-004) | [INC-004](../incidents/INC-004.md) |
| 4 | Network Reconnaissance | Discovery | Network Service Discovery | T1046 | ❌ No (decoder gap, see INC-004) | [INC-004](../incidents/INC-004.md) |
| 4 | Network Reconnaissance | Discovery | Remote System Discovery | T1018 | ❌ No (decoder gap, see INC-004) | [INC-004](../incidents/INC-004.md) |
## Coverage by Tactic
| Tactic | Techniques Covered | Scenarios |
|---|---|---|
| Reconnaissance | Active Scanning (T1595.001) | #4 |
| Discovery | Process Discovery (T1057), Network Service Discovery (T1046), Remote System Discovery (T1018) | #2, #4 |
| Execution | Command and Scripting Interpreter: PowerShell (T1059.001), Scheduled Task/Job (T1053.005) | #2, #3 |
| Persistence | Scheduled Task/Job (T1053.005) | #3 |
| Privilege Escalation | Scheduled Task/Job (T1053.005) | #3 |
| Credential Access | Brute Force: Password Guessing (T1110.001), OS Credential Dumping: LSASS Memory (T1003.001) | #1, #2 |
## Detection Rate Summary
Out of **10 technique instances** mapped across the four scenarios:
- **5** were fully detected by Wazuh's out-of-the-box ruleset (brute force, process discovery, and all three tactics of the scheduled task persistence event)
- **1** was partially covered (PowerShell execution — detected indirectly, not tagged with its own specific MITRE technique by the matched rule)
- **4** were **not detected**, split across two distinct root causes:
  - **Configuration gap** (visibility not enabled by default): LSASS credential-access reconnaissance in INC-002 — Script Block Logging captured the command but no specific rule flagged the LSASS access pattern itself
  - **Decoder gap** (log collected but not parsed/indexed): all three reconnaissance techniques in INC-004 — the Windows Firewall log was actively read by the agent but had no server-side decoder to interpret it
## Key Takeaway
This lab demonstrates that **detection coverage is not binary** — a SIEM can have excellent out-of-the-box rules for some log sources (Windows Event Log via `eventchannel`, as seen across INC-001–INC-003) while having **zero coverage** for others (native text-based logs like `pfirewall.log`, as seen in INC-004), even when the underlying telemetry is being collected. Validating detection end-to-end (generate event → confirm it is logged → confirm it is collected → confirm it is parsed → confirm it is alerted on) is essential before trusting any monitoring control, rather than assuming that "the agent is running" or "the log source is enabled" is sufficient.
