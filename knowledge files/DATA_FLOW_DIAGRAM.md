# 📊 NIDS Data Flow Diagram

## 🌊 Detailed Data Flow

This diagram illustrates the journey of network packets through the NIDS, from capture and analysis to alert generation, storage, blockchain logging, and user visualization.

```mermaid
graph TD
    A[Raw Network Traffic] --> B(Packet Sniffer);

    subgraph "NIDS Backend (FastAPI)"
        direction LR
        B --> C{Packet Parsing & Feature Extraction};

        C --> D1[ML Detector<br/>(Anomaly Detection)];
        C --> D2[Signature Detector<br/>(Rule-based Detection)];

        D1 -- "Anomaly Score" --> E{NIDS Orchestrator};
        D2 -- "Threat Match" --> E;

        E -- "Generate Alert" --> F[Alert Manager];
        E -- "Critical Threat" --> G[IPS Manager];

        F -- "Store Alert" --> H[MongoDB];
        F -- "Log Alert Hash" --> I[Blockchain Ledger];

        G -- "Initiate Block<br/>(IP Blacklist)" --> J(Router/Firewall);
        G -- "Log IPS Action Hash" --> I;
    end

    H -- "Alert Data" --> K[Backend API Endpoint];
    I -- "Blockchain Record" --> K;

    K -- "Fetch Alerts/Stats" --> L[Frontend (Next.js UI)];
    L --> M[User/Admin Display];

    style A fill:#e0f2f7,stroke:#00acc1,stroke-width:2px;
    style B fill:#ffe0b2,stroke:#fb8c00,stroke-width:2px;
    style C fill:#fff9c4,stroke:#fbc02d,stroke-width:2px;
    style D1 fill:#e8f5e9,stroke:#4caf50,stroke-width:2px;
    style D2 fill:#e8f5e9,stroke:#4caf50,stroke-width:2px;
    style E fill:#e3f2fd,stroke:#2196f3,stroke-width:2px;
    style F fill:#fce4ec,stroke:#e91e63,stroke-width:2px;
    style G fill:#f3e5f5,stroke:#9c27b0,stroke-width:2px;
    style H fill:#cfd8dc,stroke:#607d8b,stroke-width:2px;
    style I fill:#c8e6c9,stroke:#388e3c,stroke-width:2px;
    style J fill:#ef9a9a,stroke:#d32f2f,stroke-width:2px;
    style K fill:#e0f2f7,stroke:#00acc1,stroke-width:2px;
    style L fill:#e1bee7,stroke:#ab47bc,stroke-width:2px;
    style M fill:#bbdefb,stroke:#42a5f5,stroke-width:2px;
```
