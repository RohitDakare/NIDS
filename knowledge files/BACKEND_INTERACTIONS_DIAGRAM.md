# ⚙️ NIDS Backend Interactions Diagram

## 🎯 NIDS Orchestrator: The Central Hub

This diagram details the interactions centered around the `NIDSOrchestrator` within the FastAPI backend, showcasing its role in managing detection, alerting, and prevention processes.

```mermaid
graph TD
    subgraph "NIDS Backend (FastAPI)"
        direction LR

        PS[Packet Sniffer]
        MLD[ML Detector]
        SD[Signature Detector]
        AM[Alert Manager]
        IPSM[IPS Manager]
        BCC[Blockchain Client]
        API[API Endpoints]
        MDB[MongoDB]

        subgraph "Core Orchestration"
            NIDS_ORCH["NIDS Orchestrator"]
        end

        API -- "Start/Stop Sniffer" --> NIDS_ORCH
        API -- "Get Alerts/Stats" --> NIDS_ORCH

        PS -- "Captured Packet" --> NIDS_ORCH
        NIDS_ORCH -- "Dispatch Packet" --> MLD
        NIDS_ORCH -- "Dispatch Packet" --> SD

        MLD -- "Anomaly Detected" --> NIDS_ORCH
        SD -- "Signature Match" --> NIDS_ORCH

        NIDS_ORCH -- "Generate Alert" --> AM
        AM -- "Save Alert" --> MDB
        AM -- "Record Alert Hash" --> BCC

        NIDS_ORCH -- "Trigger IPS" --> IPSM
        IPSM -- "Block IP Command" --> BCC
        IPSM -- "Interact with Network Device" --> J(Router/Firewall);

        BCC -- "Verify Integrity (Startup)" --> NIDS_ORCH
        NIDS_ORCH -- "Query Alerts" --> MDB

        style NIDS_ORCH fill:#e3f2fd,stroke:#2196f3,stroke-width:2px;
        style PS fill:#ffe0b2,stroke:#fb8c00,stroke-width:2px;
        style MLD fill:#e8f5e9,stroke:#4caf50,stroke-width:2px;
        style SD fill:#e8f5e9,stroke:#4caf50,stroke-width:2px;
        style AM fill:#fce4ec,stroke:#e91e63,stroke-width:2px;
        style IPSM fill:#f3e5f5,stroke:#9c27b0,stroke-width:2px;
        style BCC fill:#c8e6c9,stroke:#388e3c,stroke-width:2px;
        style API fill:#e0f2f7,stroke:#00acc1,stroke-width:2px;
        style MDB fill:#cfd8dc,stroke:#607d8b,stroke-width:2px;
        style J fill:#ef9a9a,stroke:#d32f2f,stroke-width:2px;
    end
```
