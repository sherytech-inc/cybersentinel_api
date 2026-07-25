# CyberSentinel Viva Preparation Pack

This document contains anticipated questions and highly articulate, defensible answers for your Final Year Project (FYP) Viva/Defense.

## 1. System Architecture & Decisions

**Q: Why did you choose FastAPI instead of Django or Flask for the backend?**
**A:** "CyberSentinel is fundamentally a real-time system analyzing continuous packet streams. Flask and Django are traditionally synchronous (WSGI). FastAPI is built on ASGI and native Python `asyncio`. This allowed me to handle high-throughput packet ingestion, non-blocking external API calls (to VirusTotal/AbuseIPDB), and persistent WebSocket connections concurrently on a single server without thread starvation. It also drastically reduced boilerplate by auto-generating our OpenAPI specs."

**Q: Why Supabase and PostgreSQL over MongoDB?**
**A:** "A SOC platform requires structured data relationships (Alerts -> Packets -> Analyst Notes) and absolute transactional consistency (ACID), which relational databases handle better. I chose Supabase specifically because it wraps PostgreSQL with a real-time subscription engine. Instead of polling the database or building a complex Redis pub/sub layer, Supabase streams database changes directly to our Next.js frontend via WebSockets."

## 2. Machine Learning Pipeline

**Q: Why did you use a Hybrid Machine Learning approach instead of just one Deep Learning model?**
**A:** "Deep Learning (like LSTMs or CNNs) requires massive amounts of labeled data and significant computational overhead for inference, which introduces latency. By using a hybrid classical ML approach, I achieved real-time speeds:
1. **Random Forest (Supervised):** Rapidly identifies known signatures and attack patterns (e.g. port scans, DDoS) with high accuracy and explainability (feature importance).
2. **Isolation Forest (Unsupervised):** Acts as a fallback for zero-day threats. If an attacker uses a novel technique that evades Random Forest, Isolation Forest detects the statistical anomaly.
This combination provides defense-in-depth with sub-millisecond inference times."

**Q: How do you handle false positives?**
**A:** "False positives are mitigated by the **Decision Engine Fusion Layer**. An alert isn't triggered just because an ML model spiked. The Fusion Engine weights the Random Forest score (60%), the Isolation Forest score (10%), and the Threat Intelligence Reputation Score (30%). If an anomaly is detected, but AbuseIPDB and VirusTotal confirm the IP is a trusted Google DNS server, the overall Threat Score is reduced below the alerting threshold."

## 3. The AI Analyst Copilot

**Q: Is your AI Analyst just a wrapper around ChatGPT?**
**A:** "No. It uses an LLM (Groq API for ultra-fast Llama-3 inference), but the intelligence comes from **Retrieval-Augmented Generation (RAG)** and Intent Classification.
1. When a user queries the Copilot, a custom `QueryClassifier` determines the intent (e.g. 'EXPLAIN_ALERT' vs 'INVESTIGATE_IP').
2. The `ContextBuilder` dynamically queries the Supabase database for the specific alert details, the ML score breakdown, and recent firewall actions.
3. This factual context is injected into the prompt.
This ensures the LLM is deterministic and grounded in the actual network telemetry, preventing hallucinations and providing actionable, data-driven SOC advice."

## 4. Scalability & Real-world Application

**Q: Could this system be deployed in a real enterprise environment?**
**A:** "As a prototype, it successfully demonstrates the core mechanics of a modern SIEM/SOAR platform. For enterprise deployment, the architecture would need to scale horizontally:
1. The Scapy packet capture script would be replaced by a high-performance network tap like Zeek or Suricata.
2. The data ingestion layer would need a message broker like Apache Kafka to queue packets before ML inference.
However, the Decision Engine, the Threat Intel caching layer, and the real-time AI dashboard are fundamentally sound and mimic modern platforms like CrowdStrike or Splunk."

## 5. Security & Ethics

**Q: Does your system automate firewall blocking? Isn't that dangerous?**
**A:** "Yes, the Response Engine can execute firewall blocks via `iptables` for critical threats. However, I implemented safeguards:
- Blocks are only triggered if the Threat Score exceeds a strict threshold (e.g., > 90).
- The system includes an override mechanism in the Dashboard where analysts can manually revoke a block.
- For a production deployment, this would typically run in 'Monitor Only' mode until baseline traffic is fully understood."
