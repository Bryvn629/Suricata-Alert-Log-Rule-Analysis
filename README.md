# Suricata IDS Alert, EVE Log Correlation & Rule Tuning — SOC Investigation Lab

## Case Summary (TL;DR)

A Suricata IDS alert flagged HTTP traffic as suspicious. By correlating `alert`, `http`, and `flow` EVE logs using `flow_id`, `src_ip`, and timestamps, the activity was confirmed to be legitimate Windows update traffic. The alert was determined to be a **False Positive**, and the Suricata rule was tuned to prevent similar benign alerts while preserving detection accuracy.

## Lab Overview
This project demonstrates a real Security Operations Center (SOC) workflow using Suricata EVE JSON logs:
Alert → Triage → Correlate Logs → Determine False/True Positive → Tune Detection Rule

## Results & Findings
- Alert Observed: ET POLICY Suspicious HTTP Request
- Correlated alert, http, and flow logs using src_ip, dest_ip, timestamps, and flow_id
- Determined traffic was a False Positive caused by legitimate update traffic
- Tuned detection rule to prevent repeat benign alerts

## Evidence Samples (Sanitized)

## Example Command Output

Command:
jq 'select(.event_type=="alert")' samples/eve.json

Output:
{
  "timestamp": "2026-02-01T10:15:21.001Z",
  "event_type": "alert",
  "src_ip": "10.0.0.5",
  "dest_ip": "93.184.216.34",
  "proto": "TCP",
  "flow_id": 123456789,
  "alert": {
    "signature": "ET POLICY Suspicious HTTP Request",
    "severity": 2
  }
}


Command:
jq 'select(.event_type=="http")' samples/eve.json

Output:
{
  "timestamp": "2026-02-01T10:15:21.120Z",
  "event_type": "http",
  "src_ip": "10.0.0.5",
  "dest_ip": "93.184.216.34",
  "hostname": "example.com",
  "url": "/update/check",
  "http_user_agent": "Windows-Update-Agent",
  "flow_id": 123456789
}


Command:
jq 'select(.event_type=="flow")' samples/eve.json

Output:
{
  "timestamp": "2026-02-01T10:15:21.300Z",
  "event_type": "flow",
  "src_ip": "10.0.0.5",
  "dest_ip": "93.184.216.34",
  "proto": "TCP",
  "flow_id": 123456789,
  "flow": {
    "pkts_toserver": 12,
    "pkts_toclient": 10
  }
}


Command:
jq 'select(.flow_id==123456789)' samples/eve.json

Output:
{
  "event_type": "alert",
  "flow_id": 123456789
}
{
  "event_type": "http",
  "flow_id": 123456789
}
{
  "event_type": "flow",
  "flow_id": 123456789
}

### Viewing Alert Logs

### Alert Event
{"event_type":"alert","src_ip":"10.0.0.5","dest_ip":"93.184.216.34","alert":{"signature":"ET POLICY Suspicious HTTP Request","severity":2},"flow_id":123456789}

### HTTP Event
{"event_type":"http","hostname":"example.com","url":"/update/check","http_user_agent":"Windows-Update-Agent","flow_id":123456789}

### Flow Event
{"event_type":"flow","proto":"TCP","flow":{"pkts_toserver":12,"pkts_toclient":10},"flow_id":123456789}

## Investigation Summary

- **Initial Hypothesis:** Alert might indicate malicious activity.
- **Evidence Correlated:** HTTP requests and flow logs showed this was legitimate update traffic.
- **Conclusion:** Determined to be a **False Positive**.
- **Rule Tuning Result:** Adjusted rule conditions — reduced benign alerts without impacting detection of genuine threats.

## Tools & Commands Used

/var/log/suricata/eve.json

sudo cat /var/log/suricata/eve.json
sudo cp /var/log/suricata/eve.json ~/eve.json

jq 'select(.event_type=="alert")' eve.json
jq 'select(.event_type=="http")' eve.json
jq 'select(.event_type=="flow")' eve.json

## Repository Structure
README.md
docs/lab-report.md
samples/eve.json
scripts/log_summary.sh
suricata/rule-tuning.rules

## How to Review This Project

1. Start with the Case Summary at the top.
2. Review the Evidence Samples shown above.
3. Navigate to `docs/lab-report.md` for the full investigation walkthrough.
4. Open `samples/eve.json` to see the raw EVE logs used.
5. Review `suricata/rule-tuning.rules` to see how detection was improved.
