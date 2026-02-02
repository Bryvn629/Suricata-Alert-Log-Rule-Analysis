# Lab Report — Suricata Alert and Log Investigation

## Evidence

```json
{
  "event_type": "alert",
  "src_ip": "172.21.224.2",
  "dest_ip": "142.250.1.139",
  "proto": "TCP",
  "alert": {
    "signature": "GET on wire",
    "severity": 3
  },
  "http": {
    "hostname": "opensource.google.com",
    "http_user_agent": "curl/7.74.0",
    "http_method": "GET",
    "status": 301,
    "redirect": "https://opensource.google/"
  }
}

Findings

Suricata generated an alert for the “GET on wire” signature when an internal host initiated HTTP traffic to an external server.

HTTP metadata revealed the User-Agent curl/7.74.0, indicating command-line or scripted traffic rather than normal browser activity.

Flow data showed minimal packets and bytes transferred, consistent with a simple web request. The server response was a 301 redirect to HTTPS, confirming legitimate web infrastructure.

Outcome and Analyst Assessment

Determination: False Positive

The alert was triggered by generic HTTP GET behavior. Log correlation confirmed the traffic was benign.

Action Taken:

Documented the alert as a false positive

Identified rule sensitivity to non-malicious HTTP behavior

Recommended rule tuning to reduce alert noise

Key Takeaway

This investigation demonstrated the importance of validating IDS alerts through multi-log correlation before determining malicious intent.

Full Investigation Walkthrough

## Step 1 — Review the Alert
The Suricata alert flagged HTTP traffic as suspicious. Initial review showed the signature matched a common update pattern.

## Step 2 — Analyze HTTP Logs
Reviewed `hostname`, `url`, and `http_user_agent`. Observed the traffic was consistent with legitimate software update behavior.

## Step 3 — Correlate Flow Logs
Matched `flow_id`, `src_ip`, and `dest_ip` between alert and HTTP events to confirm they belonged to the same session.

## Step 4 — Determine Disposition
Based on the evidence, determined this was a False Positive.

## Step 5 — Rule Tuning
Modified the rule to include host matching and flow direction to prevent benign traffic from triggering alerts.

# Full Investigation Walkthrough — Suricata EVE Log Analysis

## Objective

Demonstrate how a SOC analyst investigates an IDS alert using Suricata EVE JSON logs by correlating multiple event types to determine whether traffic is malicious or benign, and then improving detection accuracy through rule tuning.

---

## Step 1 — Initial Alert Review

While reviewing Suricata alerts, an event triggered with the signature:

ET POLICY Suspicious HTTP Request

This signature indicates HTTP traffic that matches patterns commonly seen in potentially malicious activity. At first glance, this could represent:

- Malware beaconing
- Suspicious file download
- Command-and-control communication

At this stage, the alert is treated as potentially malicious until proven otherwise.

---

## Step 2 — Investigating the HTTP Event

Using jq, HTTP logs were filtered from the EVE file:

jq 'select(.event_type=="http")' eve.json

The following key fields were reviewed:

- hostname
- url
- http_user_agent

### Findings

- Hostname resolved to example.com
- URL path: /update/check
- User agent identified as Windows-Update-Agent

These indicators strongly suggest legitimate software update traffic rather than malicious communication.

---

## Step 3 — Correlating Flow Data

Next, flow logs were examined:

jq 'select(.event_type=="flow")' eve.json
jq 'select(.flow_id==123456789)' eve.json

### Findings

- Packet counts were low and balanced between client and server
- No large data transfer occurred
- Traffic direction matched a client requesting data from a server (to_server)

This behavior is consistent with routine update checks and not data exfiltration or C2 activity.

---

## Step 4 — Correlation Across Logs

The following fields were used to confirm all events belonged to the same session:

- src_ip
- dest_ip
- flow_id
- timestamp proximity

By matching these fields across alert, http, and flow events, it was confirmed that the alert and HTTP request were part of the same benign session.

---

## Step 5 — Determination

### Initial Hypothesis
The alert indicated possible malicious HTTP traffic.

### Evidence-Based Conclusion
All correlated evidence pointed to legitimate update traffic.

Final Disposition: FALSE POSITIVE

---

## Step 6 — Detection Rule Tuning

Because legitimate update traffic triggered the alert, the Suricata rule required refinement.

### Original Rule
alert http any any -> any any (msg:"Suspicious HTTP Request"; content:"/update"; sid:1000001;)

### Tuned Rule
alert http any any -> any any (msg:"Suspicious HTTP Request"; content:"/update"; http.host; flow:to_server; sid:1000001;)

### Why This Works

- Requires host validation
- Requires proper traffic direction
- Prevents benign update traffic from matching the rule

---

## Lessons Learned

This investigation highlights critical SOC skills:

- Alerts alone do not prove malicious activity
- Multiple log sources must be correlated
- Understanding normal network behavior is essential
- Detection rules must be continuously improved to reduce noise

---

## Summary

This lab demonstrates a complete SOC investigation workflow:

Alert → Log Analysis → Correlation → Decision → Rule Improvement

The ability to interpret raw IDS logs and improve detection accuracy is a core skill for security analysts and SOC professionals.
