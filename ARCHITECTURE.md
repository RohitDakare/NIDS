# 🏗️ NIDS System Architecture

## Visual Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            USER INTERFACE LAYER                              │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                     Web Browser (User)                                │  │
│  │                                                                        │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐ │  │
│  │  │ Overview │  │  Alerts  │  │ Traffic  │  │Detection │  │Settings│ │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └────────┘ │  │
│  └────────────────────────────┬─────────────────────────────────────────┘  │
└───────────────────────────────┼────────────────────────────────────────────┘
                                │
                                │ HTTP/HTTPS
                                │
┌───────────────────────────────▼────────────────────────────────────────────┐
│                         FRONTEND LAYER (Port 3000)                          │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                    Next.js 15.2.4 Application                       │    │
│  │                                                                      │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │    │
│  │  │  Dashboard   │  │   Charts     │  │   Tables     │             │    │
│  │  │  Components  │  │  (Recharts)  │  │  (shadcn)    │             │    │
│  │  └──────────────┘  └──────────────┘  └──────────────┘             │    │
│  │                                                                      │    │
│  │  ┌──────────────────────────────────────────────────────────────┐  │    │
│  │  │              API Client (Fetch/Axios)                         │  │    │
│  │  └──────────────────────────────────────────────────────────────┘  │    │
│  └──────────────────────────────┬───────────────────────────────────────┘  │
└─────────────────────────────────┼──────────────────────────────────────────┘
                                  │
                                  │ REST API
                                  │
┌─────────────────────────────────▼──────────────────────────────────────────┐
│                         BACKEND LAYER (Port 8000)                           │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                    FastAPI Application                              │    │
│  │                                                                      │    │
│  │  ┌──────────────────────────────────────────────────────────────┐  │    │
│  │  │                    Security Middleware                        │  │    │
│  │  │  • Rate Limiting (slowapi)                                    │  │    │
│  │  │  • CORS Protection                                            │  │    │
│  │  │  • JWT Authentication                                         │  │    │
│  │  │  • Trusted Host Validation                                    │  │    │
│  │  └──────────────────────────────────────────────────────────────┘  │    │
│  │                                                                      │    │
│  │  ┌──────────────────────────────────────────────────────────────┐  │    │
│  │  │                    API Endpoints                              │  │    │
│  │  │                                                                │  │    │
│  │  │  /api/v1/start-sniffer    /api/v1/alerts                     │  │    │
│  │  │  /api/v1/stop-sniffer     /api/v1/packets                    │  │    │
│  │  │  /api/v1/status           /api/v1/stats                      │  │    │
│  │  │  /api/v1/health           /api/v1/correlation                │  │    │
│  │  │  /docs (Swagger UI)       /api/v1/signature-rules            │  │    │
│  │  └──────────────────────────────────────────────────────────────┘  │    │
│  └──────────────────────────────┬───────────────────────────────────────┘  │
└─────────────────────────────────┼──────────────────────────────────────────┘
                                  │
                                  │
┌─────────────────────────────────▼──────────────────────────────────────────┐
│                         NIDS CORE LAYER                                     │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                    NIDS Orchestrator                                │    │
│  │              (Central Coordination & Control)                       │    │
│  │                                                                      │    │
│  │  • Lifecycle Management                                             │    │
│  │  • Component Coordination                                           │    │
│  │  • Alert Callbacks                                                  │    │
│  │  • Configuration Management                                         │    │
│  └───┬────────────────────┬────────────────────┬──────────────────┬───┘    │
│      │                    │                    │                  │         │
│      ▼                    ▼                    ▼                  ▼         │
│  ┌─────────┐        ┌──────────┐        ┌──────────┐      ┌──────────┐    │
│  │ Packet  │        │    ML    │        │Signature │      │  Alert   │    │
│  │ Sniffer │───────▶│ Detector │        │ Detector │      │ Manager  │    │
│  └─────────┘        └──────────┘        └──────────┘      └──────────┘    │
│      │                    │                    │                  │         │
│      │              ┌─────┴────────────────────┘                  │         │
│      │              │                                             │         │
│      │              ▼                                             │         │
│      │         ┌─────────┐                                        │         │
│      │         │ Feature │                                        │         │
│      │         │Extract  │                                        │         │
│      │         └─────────┘                                        │         │
│      │                                                            │         │
│      │  Packet Flow:                                              │         │
│      │  1. Capture packets from network                           │         │
│      │  2. Extract features                                       │         │
│      │  3. Run through ML model                                   │         │
│      │  4. Check against signatures                               │         │
│      │  5. Generate alerts if threats detected                    │         │
│      │                                                            │         │
└──────┼────────────────────────────────────────────────────────────┼─────────┘
       │                                                            │
       │                                                            │
┌──────▼────────────────────────────────────────────────────────────▼─────────┐
│                         DATA STORAGE LAYER                                  │
│                                                                              │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐          │
│  │    MongoDB       │  │   ML Models      │  │   Log Files      │          │
│  │  (Port 27017)    │  │   Storage        │  │                  │          │
│  │                  │  │                  │  │                  │          │
│  │ • alerts         │  │ • nids_model     │  │ • nids.log       │          │
│  │ • packets        │  │   .joblib        │  │ • audit.log      │          │
│  │ • rules          │  │ • scaler.joblib  │  │ • error.log      │          │
│  │ • metrics        │  │ • metadata.json  │  │                  │          │
│  │ • audit_logs     │  │                  │  │                  │          │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘          │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────┐
│                         EXTERNAL INTERFACES                                  │
│                                                                              │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐          │
│  │   Network        │  │   Blockchain     │  │   Threat Intel   │          │
│  │   Interface      │  │   (Optional)     │  │   Feeds          │          │
│  │                  │  │                  │  │   (Future)       │          │
│  │ • Ethernet       │  │ • Web3.py        │  │                  │          │
│  │ • Wi-Fi          │  │ • Smart Contract │  │ • MISP           │          │
│  │ • Loopback       │  │ • Audit Trail    │  │ • AlienVault     │          │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘          │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. Packet Sniffer (10.7 KB)
**Technology:** Scapy + Npcap/libpcap  
**Functions:**
- Capture live network packets
- Filter by protocol, port, IP
- Extract packet metadata
- Thread-safe processing
- Configurable capture parameters

**Key Methods:**
```python
start_capture()      # Begin packet capture
stop_capture()       # Stop capture
process_packet()     # Process individual packet
extract_features()   # Extract packet features
```

### 2. ML Detector (40.9 KB)
**Technology:** scikit-learn, pandas, numpy  
**Supported Models:**
- Random Forest (Supervised)
- Gradient Boosting (Supervised)
- Isolation Forest (Unsupervised)
- One-Class SVM (Unsupervised)

**Detection Pipeline:**
```
Packet → Feature Extraction → Normalization → ML Model → Confidence Score → Alert
```

**Features Extracted:**
- Protocol type
- Packet size
- Source/destination IP
- Port numbers
- Payload characteristics
- Timing information
- Statistical features

### 3. Signature Detector (31.0 KB)
**Technology:** YAML rules + Pattern matching  
**Detection Types:**
- DDoS attacks
- Port scanning
- Brute force
- SYN flood
- ICMP flood
- Slowloris
- SQL injection
- XSS attacks

**Rule Structure:**
```yaml
id: rule_001
name: "Attack Name"
pattern: "regex_pattern"
severity: high|medium|low
action: alert|block|log
enabled: true
```

### 4. Alert Manager (21.6 KB)
**Functions:**
- Alert generation
- Severity classification
- Alert correlation
- Pattern detection
- MongoDB persistence
- Real-time callbacks

**Alert Lifecycle:**
```
Detection → Generation → Storage → Notification → Resolution
```

### 5. NIDS Orchestrator (18.8 KB)
**Role:** Central coordinator  
**Responsibilities:**
- Component initialization
- Lifecycle management
- Configuration distribution
- Alert routing
- Error handling
- System monitoring

## Data Flow

### Normal Traffic Flow
```
Network → Packet Sniffer → Feature Extraction → ML Detector → No Threat → Log
                                               → Signature Detector → No Match → Log
```

### Threat Detection Flow
```
Network → Packet Sniffer → Feature Extraction → ML Detector → Anomaly Detected
                                               → Signature Detector → Pattern Matched
                                                                    ↓
                                                              Alert Manager
                                                                    ↓
                                                    ┌───────────────┴───────────────┐
                                                    ↓                               ↓
                                              MongoDB Storage                  Frontend Dashboard
                                                    ↓                               ↓
                                              Audit Log                        User Notification
```

## Security Architecture

### Authentication Flow
```
User Request → API Gateway → JWT Validation → Rate Limit Check → Authorization
                                    ↓                                    ↓
                              Invalid Token                         Valid Token
                                    ↓                                    ↓
                              401 Unauthorized                    Process Request
```

### Rate Limiting
```
Request → slowapi Limiter → Check Rate → Within Limit → Process
                                ↓              ↓
                          Exceeded Limit    429 Error
```

## Deployment Architecture

### Development Environment
```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Developer     │────▶│   Local Host    │────▶│   MongoDB       │
│   Machine       │     │   Backend:8000  │     │   localhost     │
│                 │     │   Frontend:3000 │     │   :27017        │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

### Docker Deployment
```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Compose                            │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Backend    │  │   Frontend   │  │   MongoDB    │      │
│  │  Container   │  │  Container   │  │  Container   │      │
│  │              │  │              │  │              │      │
│  │  Port: 8000  │  │  Port: 3000  │  │  Port: 27017 │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Shared Network: nids-network             │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Production Architecture
```
                    ┌─────────────────┐
                    │   Load Balancer │
                    │   (Nginx/HAProxy)│
                    └────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
        ┌──────────┐   ┌──────────┐   ┌──────────┐
        │ Backend  │   │ Backend  │   │ Backend  │
        │Instance 1│   │Instance 2│   │Instance 3│
        └────┬─────┘   └────┬─────┘   └────┬─────┘
             │              │              │
             └──────────────┼──────────────┘
                            │
                    ┌───────▼────────┐
                    │  MongoDB       │
                    │  Replica Set   │
                    └────────────────┘
```

## Monitoring & Logging

### Logging Architecture
```
Application Logs → File Handler → logs/nids.log
                 → Console Handler → stdout
                 → MongoDB Handler → audit_logs collection
                 → Syslog Handler → System logs (optional)
```

### Metrics Collection
```
System Metrics → Prometheus Client → Metrics Endpoint (/metrics)
                                    → Grafana Dashboard
                                    → Alert Manager
```

## Technology Stack Summary

### Backend Stack
```
┌─────────────────────────────────────────┐
│ FastAPI 0.68.0+                         │
│   ├── Uvicorn (ASGI Server)             │
│   ├── Pydantic (Validation)             │
│   └── Starlette (Framework)             │
├─────────────────────────────────────────┤
│ Security                                │
│   ├── PyJWT (Authentication)            │
│   ├── slowapi (Rate Limiting)           │
│   ├── cryptography (Encryption)         │
│   └── python-jose (JWT)                 │
├─────────────────────────────────────────┤
│ Network & Detection                     │
│   ├── Scapy (Packet Capture)            │
│   ├── scikit-learn (ML)                 │
│   ├── pandas (Data Processing)          │
│   └── numpy (Numerical Computing)       │
├─────────────────────────────────────────┤
│ Database                                │
│   ├── pymongo (MongoDB Driver)          │
│   └── motor (Async MongoDB)             │
├─────────────────────────────────────────┤
│ Blockchain                              │
│   ├── web3.py (Ethereum)                │
│   └── eth-account (Accounts)            │
└─────────────────────────────────────────┘
```

### Frontend Stack
```
┌─────────────────────────────────────────┐
│ Next.js 15.2.4                          │
│   ├── React 18                          │
│   ├── TypeScript                        │
│   └── App Router                        │
├─────────────────────────────────────────┤
│ UI Components                           │
│   ├── shadcn/ui                         │
│   ├── Radix UI                          │
│   └── Tailwind CSS                      │
├─────────────────────────────────────────┤
│ Data Visualization                      │
│   ├── Recharts                          │
│   └── Lucide Icons                      │
├─────────────────────────────────────────┤
│ State Management                        │
│   ├── React Hooks                       │
│   └── Custom Hooks                      │
└─────────────────────────────────────────┘
```

## Performance Characteristics

### Throughput
```
Packet Processing: ~1000 packets/second
API Requests: 100 requests/minute (rate limited)
Alert Generation: Real-time (<1 second latency)
Database Writes: Async, non-blocking
```

### Resource Usage
```
CPU: 5-15% (idle to moderate load)
Memory: 128-512 MB (depending on buffer size)
Disk I/O: Minimal (log rotation enabled)
Network: Depends on traffic volume
```

### Scalability Limits
```
Single Instance:
  - Max Packets: ~10,000/second
  - Max Concurrent Users: ~100
  - Max Alerts/Day: ~1,000,000

Clustered:
  - Horizontal scaling supported
  - Load balancer required
  - Shared MongoDB backend
```

---

**Document Version:** 1.0  
**Last Updated:** December 26, 2025  
**Maintained By:** NIDS Development Team
