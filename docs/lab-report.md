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
