# Suricata IDS Alert, EVE Log Correlation & Rule Tuning — SOC Investigation Lab

## Lab Overview
This project demonstrates a real Security Operations Center (SOC) workflow using Suricata EVE JSON logs:
Alert → Triage → Correlate Logs → Determine False/True Positive → Tune Detection Rule

## Results & Findings
- Alert Observed: ET POLICY Suspicious HTTP Request
- Correlated alert, http, and flow logs using src_ip, dest_ip, timestamps, and flow_id
- Determined traffic was a False Positive caused by legitimate update traffic
- Tuned detection rule to prevent repeat benign alerts

## Evidence Samples (Sanitized)

### Alert Event
{"event_type":"alert","src_ip":"10.0.0.5","dest_ip":"93.184.216.34","alert":{"signature":"ET POLICY Suspicious HTTP Request","severity":2},"flow_id":123456789}

### HTTP Event
{"event_type":"http","hostname":"example.com","url":"/update/check","http_user_agent":"Windows-Update-Agent","flow_id":123456789}

### Flow Event
{"event_type":"flow","proto":"TCP","flow":{"pkts_toserver":12,"pkts_toclient":10},"flow_id":123456789}

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
