graph TB
%% === STYLES ===
classDef core fill:#1E90FF,stroke:#000,color:#000,stroke-width:2px,rx:10px,ry:10px;
classDef db fill:#9ACD32,stroke:#000,color:#000,stroke-width:2px,rx:10px,ry:10px;
classDef blockchain fill:#FFD700,stroke:#000,color:#000,stroke-width:2px,rx:10px,ry:10px;
classDef frontend fill:#FF69B4,stroke:#000,color:#000,stroke-width:2px,rx:10px,ry:10px;
classDef backend fill:#00CED1,stroke:#000,color:#000,stroke-width:2px,rx:10px,ry:10px;
classDef detection fill:#FF8C00,stroke:#000,color:#000,stroke-width:2px,rx:10px,ry:10px;

%% === USERS ===
User(("User<br/>Web Interface"))

%% === FRONTEND ===
Frontend["Frontend<br/>React (Next.js)"]:::frontend
User -->|"interacts with"| Frontend

%% === BACKEND ===
Backend["Backend<br/>FastAPI Server"]:::backend
Frontend -->|"REST API calls"| Backend

%% === DETECTION MODULES ===
subgraph "Detection Modules"
  PacketSniffer["Packet Sniffer<br/>Captures Network Traffic"]:::detection
  MLDetector["ML Detector<br/>Anomaly Detection"]:::detection
  SignatureDetector["Signature Detector<br/>Pattern Matching"]:::detection
  AlertManager["Alert Manager<br/>Manages Alerts"]:::detection
end

Backend -->|"orchestrates"| PacketSniffer
Backend -->|"orchestrates"| MLDetector
Backend -->|"orchestrates"| SignatureDetector
Backend -->|"orchestrates"| AlertManager

%% === DATABASE ===
DB[("Database<br/>MongoDB")]:::db
AlertManager -->|"stores alerts"| DB
PacketSniffer -->|"stores packets"| DB

%% === BLOCKCHAIN ===
Blockchain["Blockchain<br/>Ethereum Client"]:::blockchain
AlertManager -->|"logs alerts"| Blockchain

%% === DATA FLOW ===
PacketSniffer -->|"captures packets"| MLDetector
PacketSniffer -->|"captures packets"| SignatureDetector
MLDetector -->|"detects anomalies"| AlertManager
SignatureDetector -->|"detects signatures"| AlertManager

%% === CONTROL FLOW ===
Backend -->|"API commands"| PacketSniffer
Backend -->|"API commands"| MLDetector
Backend -->|"API commands"| SignatureDetector
Backend -->|"API commands"| AlertManager

%% === SYSTEM MONITORING ===
User -->|"views metrics"| Frontend
Backend -->|"provides status"| User

%% === SECURITY ===
Backend -->|"validates API keys"| User
Backend -->|"applies rate limiting"| User

%% === LIFECYCLE ===
Backend -->|"initializes on startup"| PacketSniffer
Backend -->|"initializes on startup"| MLDetector
Backend -->|"initializes on startup"| SignatureDetector
Backend -->|"initializes on startup"| AlertManager
Backend -->|"gracefully stops on shutdown"| PacketSniffer
Backend -->|"gracefully stops on shutdown"| MLDetector
Backend -->|"gracefully stops on shutdown"| SignatureDetector
Backend -->|"gracefully stops on shutdown"| AlertManager