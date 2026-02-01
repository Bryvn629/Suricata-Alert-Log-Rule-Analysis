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
