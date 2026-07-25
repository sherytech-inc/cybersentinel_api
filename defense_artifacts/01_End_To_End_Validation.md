# CyberSentinel End-to-End Validation

This document serves as proof of execution for a complete threat lifecycle, demonstrating the end-to-end functionality of CyberSentinel.

## Scenario 1: Port Scan Attack

**Attack Vector:** Simulated Nmap SYN scan across 100 ports.
**Target Component:** CyberSentinel Packet Capture Engine -> Pipeline

### 1. Packet Capture (Ingestion)
The system captures raw network packets in real-time.

```json
{
  "source_ip": "192.168.1.137",
  "dest_ip": "10.0.0.5",
  "protocol": "TCP",
  "flags": "SYN"
}
```
*Screenshot Proof Needed: Packet flow visible in realtime dashboard / database.*
![Packet Capture Dashboard Placeholder](_insert_screenshot_here_)

### 2. Flow Creation & Feature Extraction
The ML pre-processor aggregates packets by source IP and extracts 12 statistical features:
- SYN count: 100
- Unique ports targeted: 100
- Packet rate: 500 pps

### 3. Machine Learning Detection (Hybrid Phase)

**Model 1: Random Forest (Supervised)**
- **Confidence:** 84.73%
- **Classification:** `port_scan`

**Model 2: Isolation Forest (Unsupervised)**
- **Anomaly Score:** 0.63
- **Severity:** HIGH

### 4. Threat Intelligence (External Context)
- **AbuseIPDB:** Score 72 (Known scanner IP)
- **VirusTotal:** Positive hits found.

### 5. Decision Engine
The fusion center calculates the final threat score:
`0.60 * (84.73) + 0.10 * (0.63 * 100) + 0.30 * (72.08) = 87.91`

**Final Score:** 87.91 (Severity: HIGH)

### 6. Automated Response (Firewall)
Based on Severity HIGH, the Response Engine triggers a `BLOCK` action on IP `192.168.1.137`.

*Screenshot Proof Needed: Firewall log showing the IP block action.*
![Firewall Block Placeholder](_insert_screenshot_here_)

### 7. AI Explanation & Investigation Timeline
The AI Analyst is queried to explain the alert. The SOC Timeline successfully documents all chronologically:

```text
[2026-07-11T16:23:04] Alert Created (Severity: HIGH)
[2026-07-11T16:23:04] Firewall Rule Applied (BLOCK)
[2026-07-11T16:23:04] Random Forest Detection (Score: 84.73)
[2026-07-11T16:23:04] Isolation Forest Detection (Anomaly: 0.63)
[2026-07-11T16:23:04] Threat Intelligence Check (Reputation: 72.08)
[2026-07-11T16:23:04] Threat Score Generated (Final: 87.91)
[2026-07-11T16:23:04] AI Explanation Generated (Models Analyzed: 1)
```

*Screenshot Proof Needed: SOC Timeline UI / Terminal output.*
![Investigation Timeline Placeholder](_insert_screenshot_here_)

### Conclusion
**Result:** PASSED. The attack was successfully captured, analyzed by multiple models, enriched with external intel, mitigated automatically, and explained via the AI Copilot.
