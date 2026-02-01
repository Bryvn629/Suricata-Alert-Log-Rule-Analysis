# Suricata — Alert, Log, and Rule Analysis (SOC Lab)

This project documents a hands-on SOC investigation using Suricata to examine IDS alerts, analyze EVE JSON logs, and review detection rule behavior.

## Objective
- Examine Suricata alerts
- Correlate alert data with HTTP and flow logs
- Determine true vs false positives
- Identify opportunities for rule tuning to improve detection accuracy

## Skills Demonstrated
Suricata (IDS), EVE JSON log analysis, alert triage, network log correlation, rule review and tuning.

## Lab Summary
A Suricata alert triggered on HTTP GET traffic from an internal host. Investigation required correlating alert data with HTTP metadata and flow logs to determine whether the traffic was malicious or benign.

See full report in: `docs/lab-report.md
