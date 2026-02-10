# 🔒 NIDS Security Features Diagram

## 🛡️ Leveraging Blockchain for Enhanced Security

This diagram illustrates how the NIDS utilizes blockchain technology to ensure integrity, provide an immutable audit trail, and enhance the security posture of the system.

```mermaid
graph TD
    subgraph "NIDS Backend (FastAPI)"
        direction LR

        STARTUP[System Startup]
        ML_MODELS[ML Models]
        RULES[Detection Rules]
        ALERTS[Detected Alerts]
        IPS_ACTIONS[IPS Enforcement Actions]
        BC_CLIENT[Blockchain Client]
        INTEGRITY_MGR[Integrity Manager]

        STARTUP -- "Triggers Check" --> INTEGRITY_MGR
        INTEGRITY_MGR -- "Calculates Checksum" --> ML_MODELS
        INTEGRITY_MGR -- "Calculates Checksum" --> RULES

        ML_MODELS -- "Checksums" --> BC_CLIENT
        RULES -- "Checksums" --> BC_CLIENT
        BC_CLIENT -- "Verifies against<br/>Blockchain Record" --> INTEGRITY_MGR

        ALERTS -- "Hash of Alert" --> BC_CLIENT
        IPS_ACTIONS -- "Hash of Action" --> BC_CLIENT

        BC_CLIENT -- "Records Immutable Data" --> BLOCKCHAIN[(Blockchain Ledger)]
        BLOCKCHAIN -- "Provides Proof of<br/>Integrity & Audit Trail" --> SYSTEM_AUDIT[System Audit/Forensics]

        style STARTUP fill:#e3f2fd,stroke:#2196f3,stroke-width:2px;
        style ML_MODELS fill:#e8f5e9,stroke:#4caf50,stroke-width:2px;
        style RULES fill:#e8f5e9,stroke:#4caf50,stroke-width:2px;
        style ALERTS fill:#fce4ec,stroke:#e91e63,stroke-width:2px;
        style IPS_ACTIONS fill:#f3e5f5,stroke:#9c27b0,stroke-width:2px;
        style BC_CLIENT fill:#c8e6c9,stroke:#388e3c,stroke-width:2px;
        style INTEGRITY_MGR fill:#fff9c4,stroke:#fbc02d,stroke-width:2px;
        style BLOCKCHAIN fill:#bbdefb,stroke:#42a5f5,stroke-width:2px;
        style SYSTEM_AUDIT fill:#e0e0e0,stroke:#616161,stroke-width:2px;
    end
```
