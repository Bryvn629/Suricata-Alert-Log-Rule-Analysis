Suricata IDS Alert & Log Analysis — SOC Investigation Lab
Lab Overview

This project demonstrates a real-world Security Operations Center (SOC) workflow using Suricata EVE JSON logs. The lab walks through the full investigation lifecycle:

Alert → Triage → Correlate Logs → Determine True/False Positive → Tune Detection Rule

The objective is to show practical skills used by SOC analysts to validate alerts, reduce false positives, and improve detection fidelity.

Skills Demonstrated

IDS alert triage using Suricata signatures

Deep analysis of EVE JSON logs (alert, http, flow)

Log correlation using src_ip, dest_ip, flow_id, and timestamps

Investigation methodology to determine alert validity

Detection engineering through rule tuning

Command-line log analysis using jq

Basic automation for log summarization

Investigation Scenario

A Suricata alert triggered on HTTP traffic flagged as suspicious. The task was to determine whether the traffic was malicious or benign by correlating multiple log types within the same flow.

Results & Findings

Alert Observed: ET POLICY Suspicious HTTP Request (sid <SID>)

Initial Hypothesis: Possible malicious download or command-and-control behavior

Correlation Method: Matched alert, http, and flow events using:

src_ip and dest_ip

flow_id

Timestamp proximity

Key Evidence:

HTTP hostname and URL path

HTTP user agent

Flow packet direction and byte counts

Disposition: False Positive — traffic was legitimate software update communication

Tuning Action: Modified rule to include host match and flow direction requirement

Outcome: Eliminated repeated benign alerts while preserving detection capability

Evidence Samples (Sanitized)

### Alert Event
```json
{
  "event_type": "alert",
  "src_ip": "10.0.0.5",
  "dest_ip": "93.184.216.34",
  "alert": { "signature": "ET POLICY Suspicious HTTP Request", "severity": 2 }
}
HTTP Event
{
  "event_type": "http",
  "hostname": "example.com",
  "url": "/update/check",
  "http_user_agent": "Windows-Update-Agent"

Flow Event
 "event_type": "flow",
  "flow_id": 123456789,
  "proto": "TCP"

How to Reproduce
Place the log file in /samples/eve.json and run:
 jq 'select(.event_type=="alert")' eve.json
jq 'select(.event_type=="http")' eve.json
jq 'select(.event_type=="flow")' eve.json

What This Proves
	•	IDS alert triage
	•	Log correlation
	•	False positive identification
	•	Detection rule tuning

