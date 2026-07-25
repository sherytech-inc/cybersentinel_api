# CyberSentinel System Validation Checklist

**Purpose:** This document is the final quality assurance checklist before the viva defense. Every core feature must be manually validated by the author to ensure 100% confidence. Do not check off an item until you have personally seen it work end-to-end and collected a screenshot.

---

## 1. Core Engine & Backend

### ☑ Packet Capture
- **Test:** Run live capture against a known noisy interface (e.g., streaming video or `ping`).
- **Date Tested:** `[YYYY-MM-DD]`
- **Result:** `[PASS/FAIL/NOTES]`
- **Screenshot Ref:** `[]`

### ☑ Flow Creation
- **Test:** Ensure raw packets are being aggregated into bidirectional NetFlow-like records.
- **Date Tested:** `[YYYY-MM-DD]`
- **Result:** `[PASS/FAIL/NOTES]`
- **Screenshot Ref:** `[]`

### ☑ ML Classification
- **Test:** Ensure both Random Forest and Isolation Forest assign confidence/anomaly scores to flows.
- **Date Tested:** `[YYYY-MM-DD]`
- **Result:** `[PASS/FAIL/NOTES]`
- **Screenshot Ref:** `[]`

### ☑ Threat Intelligence
- **Test:** Inject a known malicious IP (e.g., simulated C2 server) and verify the external reputation score is pulled.
- **Date Tested:** `[YYYY-MM-DD]`
- **Result:** `[PASS/FAIL/NOTES]`
- **Screenshot Ref:** `[]`

### ☑ Decision Engine
- **Test:** Verify the final threat score matches the weighted mathematical combination of RF, IF, and Intel scores.
- **Date Tested:** `[YYYY-MM-DD]`
- **Result:** `[PASS/FAIL/NOTES]`
- **Screenshot Ref:** `[]`

---

## 2. Real-Time & Response Systems

### ☑ WebSockets (Dashboard)
- **Test:** Inject an attack and watch the UI update instantly without refreshing the browser.
- **Date Tested:** `[YYYY-MM-DD]`
- **Result:** `[PASS/FAIL/NOTES]`
- **Screenshot Ref:** `[]`

### ☑ Threat Response & Firewall Actions
- **Test:** Trigger a block on an IP and verify the backend correctly logs a firewall action.
- **Date Tested:** `[YYYY-MM-DD]`
- **Result:** `[PASS/FAIL/NOTES]`
- **Screenshot Ref:** `[]`

---

## 3. Investigation & Explainability

### ☑ AI Analyst - Context Awareness
- **Test:** Ask "Show active threats". Verify the output matches exactly what is in the database (IDs, IP addresses, scores).
- **Date Tested:** `[YYYY-MM-DD]`
- **Result:** `[PASS/FAIL/NOTES]`
- **Screenshot Ref:** `[]`

### ☑ AI Analyst - Explainability
- **Test:** Ask "Explain why alert X was flagged". Verify the exact mathematical breakdown of RF, IF, and Intel scores is provided.
- **Date Tested:** `[YYYY-MM-DD]`
- **Result:** `[PASS/FAIL/NOTES]`
- **Screenshot Ref:** `[]`

### ☑ Investigation Timeline
- **Test:** Open a specific alert and verify the chronological events (Created, RF/IF Detection, AI Explanation, Blocked).
- **Date Tested:** `[YYYY-MM-DD]`
- **Result:** `[PASS/FAIL/NOTES]`
- **Screenshot Ref:** `[]`

---

## 4. Operational & Demo Capabilities

### ☑ Demo Mode (Attack Injection)
- **Test:** Inject a Port Scan. Verify the mock packets, alerts, and firewall actions appear across the system.
- **Date Tested:** `[YYYY-MM-DD]`
- **Result:** `[PASS/FAIL/NOTES]`
- **Screenshot Ref:** `[]`

### ☑ Reports & Exports
- **Test:** Ensure PDF, CSV, and JSON exports generate correctly and contain valid alert data.
- **Date Tested:** `[YYYY-MM-DD]`
- **Result:** `[PASS/FAIL/NOTES]`
- **Screenshot Ref:** `[]`

---

## 5. UI Polish & Consistency Check

**Ensure the following UI details are perfectly consistent across the dashboard:**
- `[ ]` Loading indicators exist and function properly.
- `[ ]` Empty states are handled gracefully (e.g., "No active threats found").
- `[ ]` Error states (e.g., failed API call) show a toast/notification, not a blank screen.
- `[ ]` Buttons and spacing align perfectly on different screen sizes.
- `[ ]` Scroll behavior works smoothly on long lists (like the Timeline).
- `[ ]` Dark mode (if applicable) is universally applied.
- `[ ]` Severity colors are strictly enforced:
  - 🟢 Safe
  - 🟡 Medium
  - 🟠 High
  - 🔴 Critical
