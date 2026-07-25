# CyberSentinel System Architecture

This document provides a high-level overview of the CyberSentinel architecture.

## System Architecture Diagram

```mermaid
graph TD
    %% Define Styles
    classDef client fill:#e3f2fd,stroke:#1e88e5,stroke-width:2px;
    classDef backend fill:#e8f5e9,stroke:#43a047,stroke-width:2px;
    classDef ml fill:#fff3e0,stroke:#fb8c00,stroke-width:2px;
    classDef intel fill:#f3e5f5,stroke:#8e24aa,stroke-width:2px;
    classDef db fill:#ffebee,stroke:#e53935,stroke-width:2px;

    %% Client Layer
    Dashboard["Next.js Real-time Dashboard"]:::client

    %% Backend API Layer (FastAPI)
    subgraph Backend [FastAPI Backend Engine]
        API["REST API (HTTP)"]:::backend
        WS["WebSocket Hub"]:::backend
        Cap["Packet Capture Service (Scapy)"]:::backend
        Flow["Flow Feature Extractor"]:::backend
        DecEngine["Fusion Decision Engine"]:::backend
        ResEngine["Threat Response Center (Firewall)"]:::backend
        Copilot["AI Analyst (RAG + Groq)"]:::backend
    end

    %% Machine Learning Layer
    subgraph ML_Models [Machine Learning Subsystem]
        RF["Random Forest (Supervised)"]:::ml
        IF["Isolation Forest (Unsupervised)"]:::ml
    end

    %% External Threat Intelligence
    subgraph External_Intel [Threat Intelligence APIs]
        AbuseIPDB["AbuseIPDB"]:::intel
        VirusTotal["VirusTotal"]:::intel
    end

    %% Database Layer (Supabase / Postgres)
    subgraph Database [Supabase PostgreSQL]
        DB_Packets[(Packets / Flows)]:::db
        DB_Alerts[(Threat Alerts)]:::db
        DB_Firewall[(Firewall Logs)]:::db
        DB_Chat[(Copilot History)]:::db
    end

    %% Flow of Data
    Dashboard <-->|REST & WebSockets| API
    Dashboard <-->|Real-time Events| WS
    
    Cap -->|Raw Packets| Flow
    Flow -->|Network Features| RF
    Flow -->|Network Features| IF
    
    RF -->|Score & Class| DecEngine
    IF -->|Anomaly Score| DecEngine
    
    DecEngine <-->|IP Lookup| External_Intel
    DecEngine -->|Final Threat Score| API
    DecEngine -->|Triggers| ResEngine
    
    ResEngine -->|iptables/UFW| OS_Firewall[OS Firewall]
    
    API -->|Read/Write| Database
    WS -.->|Streams| Database
    Copilot <-->|Context Queries| Database
    Copilot <-->|LLM Inference| Groq[Groq LLM API]
    
    API <--> Copilot
```

## Architecture Decisions (FYP Defense Justification)

**1. Why FastAPI?**
FastAPI natively supports Python `asyncio`, which is critical for handling thousands of packets per second without blocking the main thread. It also auto-generates OpenAPI documentation and provides built-in WebSocket support for the real-time dashboard.

**2. Why Supabase / PostgreSQL?**
Instead of setting up a complex local database and dealing with connection pooling overhead, Supabase provides a managed, serverless PostgreSQL database with real-time subscriptions, making it perfect for a SOC dashboard that needs to update instantly when new threats are detected.

**3. Why Hybrid Machine Learning (Random Forest + Isolation Forest)?**
- **Random Forest** is supervised and excellent at detecting known attack signatures (like Port Scans, Brute Force) with high accuracy.
- **Isolation Forest** is unsupervised and detects zero-day anomalies that don't match known signatures.
- Combining them minimizes false negatives (missing an attack) and false positives (blocking legitimate traffic).

**4. Why an AI Copilot?**
Traditional dashboards leave the analyst to decipher raw data (e.g. "Rule 341 triggered"). Integrating an LLM with RAG (Retrieval-Augmented Generation) translates raw telemetry and threat scores into human-readable investigations, drastically reducing Mean Time To Respond (MTTR).
