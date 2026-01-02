# Secure and Scalable Network Intrusion Detection: A Hybrid Approach using Machine Learning and Blockchain-Based Integrity Verification

**Abstract**  
In an era of increasingly sophisticated cyber threats, traditional Network Intrusion Detection Systems (NIDS) often struggle with a trade-off between the accuracy of signature-based detection and the adaptability of machine learning (ML) models. Furthermore, the integrity of detection logs and model artifacts remains a critical vulnerability, as sophisticated attackers may attempt to tamper with evidence. This paper presents a comprehensive, full-stack NIDS that integrates a dual-engine detection mechanism—combining rule-based pattern matching with anomaly detection using Random Forest and Isolation Forest algorithms. Additionally, we introduce a novel blockchain-based integrity layer that immutably records critical alerts and verifies the integrity of detection models, ensuring non-repudiation and system trustworthiness.

---

## 1. Introduction

Network security is a paramount concern for modern enterprises. As attack vectors evolve from simple port scans to complex, zero-day exploits, NIDS must evolve to detect both known and unknown threats.

Traditional systems rely heavily on **Signature-Based Detection**, which is highly accurate for known attacks but fails against new, unseen variants. Conversely, **Anomaly-Based Detection** using Machine Learning (ML) can identify deviations from normal traffic patterns but suffers from higher false-positive rates.

This project proposes a **Hybrid NIDS** that leverages the strengths of both approaches. Moreover, it addresses a specific gap in current NIDS architectures: **Log Integrity**. By integrating an Ethereum-based smart contract, the system ensures that critical alerts and core system files (such as the trained ML model) are cryptographically verified and immutable.

## 2. System Architecture

The proposed system follows a distributed, full-stack architecture designed for high performance and usability. It is divided into three primary layers: the **Core Detection Engine (Backend)**, the **Visualization Layer (Frontend)**, and the **Integrity Layer (Blockchain)**.

### 2.1 Backend (FastAPI & Python)
The backend acts as the central nervous system, built with **FastAPI** for asynchronous performance.
- **Packet Sniffer**: Utilizes `Scapy` to capture raw network traffic from the Network Interface Card (NIC) in continuous real-time analysis.
- **Orchestrator**: Manages multi-threaded execution, ensuring the sniffer, detectors, and alert managers run concurrently without race conditions.

### 2.2 Frontend (Next.js & React)
A modern, responsive dashboard built with **Next.js 15** provides security analysts with real-time visibility.
- **Live Traffic Monitoring**: Visualizes protocol distribution and traffic volume.
- **Alert Management**: Displays alerts with severity levels, allowing analysts to filter and resolve incidents.

### 2.3 Integrity Layer (Blockchain)
To ensure data tamper-proofing, the system integrates with an Ethereum-compatible blockchain using `Web3.py`.
- **Alert Hashing**: Critical alerts are hashed (SHA-256) and stored on-chain.
- **Model Verification**: The integrity of the ML model file (`nids_model.joblib`) is periodically verified against a stored hash on the smart contract to prevent model poisoning.

---

## 3. Methodology

### 3.1 Dual-Engine Detection Strategy

#### 3.1.1 Signature-Based Detection
This engine operates on a strictly defined set of rules and Regular Expressions (Regex). It is reliable for identifying:
- **Web Attacks**: SQL Injection (`' OR '1'='1`), XSS payloads (`<script>`).
- **Network Scans**: Rapid port scanning patterns or specific malicious flag combinations (e.g., Christmas Tree packets).
- **Known Malware Signatures**: Matching payload bytes against a database of known threats.

#### 3.1.2 Machine Learning Anomaly Detection
To detect zero-day attacks, the system employs unsupervised and supervised learning techniques.
- **Feature Extraction**: Incoming packets are parsed to extract features such as `packet_length`, `tcp_flags`, `window_size`, and port numbers.
- **Algorithms**:
  - **Random Forest**: Used for classification when labeled training data is available.
  - **Isolation Forest**: Used for unsupervised anomaly detection to identify outliers in traffic flow that deviate significantly from the baseline.

### 3.2 Alert Correlation & Hybrid Analysis
An **Alert Manager** component aggregates outputs from both matching engines.
- **De-duplication**: Prevents alert fatigue by grouping similar alerts within a short time window.
- **Hybrid Scoring**: A weighted scoring mechanism upgrades the severity of an alert if both engines trigger simultaneously on the same packet flow.

### 3.3 Blockchain Integrity Mechanism
The system employs a smart contract, `NIDSRecord.sol`, containing the following logic:
1.  **`recordAlert(alertId, alertHash, severity)`**: Stores the cryptographic hash of an alert's metadata. This ensures that logs in the database cannot be silently altered or deleted by an attacker who gains DB access.
2.  **`verifyIntegrity(fileName, fileHash)`**: Allows the NIDS to query the blockchain for the "official" hash of its configuration and model files. If the local file's hash differs, the system halts or alerts, indicating potential localized compromise.

---

## 4. Implementation Details

The implementation leverages a modern, open-source technology stack:

- **Packet Capture**: `Scapy` (Python)
- **ML Libraries**: `Scikit-learn`, `Pandas`
- **Backend API**: `FastAPI`, `Uvicorn`
- **Frontend**: `React`, `Next.js`, `Tailwind CSS`
- **Blockchain**: `Solidity` (Smart Contract), `Web3.py` (Client)
- **Database**: `MongoDB` (for persistent log storage)

**Key Logic Flow:**
1.  `PacketSniffer` captures IP packet.
2.  `SignatureDetector` scans payload for regex matches.
3.  `MLDetector` transforms packet features and predicts anomaly class.
4.  If threat found -> `AlertManager` creates `Alert` object.
5.  If severity is `CRITICAL` -> `BlockchainClient` sends transaction to Ethereum network.
6.  Frontend polls `/api/alerts` and renders notification to user.

---

## 5. Results and Evaluation

The system was validated using a custom `simulate_attacks.py` script capable of generating:
- **Concurrent Port Scans**: High-speed scanning (200+ threads) to test throughput.
- **SYN Floods**: Denial-of-Service simulation to test rate limiting and anomaly detection.
- **Malicious Payloads**: Injection strings to verify signature rules.

### Findings:
- **Accuracy**: The Signature engine demonstrated 100% detection for known web attack patterns. The ML engine successfully flagged anomalous high-volume traffic (DDoS simulation) that passed individual signature checks.
- **Latency**: The asynchronous backend architecture maintained low latency (<50ms processing time per batch) even under load.
- **Integrity**: Deletion of critical logs from the local database was successfully detected by comparing local records against the immutable blockchain ledger.

---

## 6. Conclusion and Future Work

This project demonstrates the viability of a **Hybrid NIDS** enhanced by blockchain technology. By combining the precision of signatures with the adaptability of ML, the system offers robust protection against a wide spectrum of threats. The integration of blockchain provides a layer of immutability rarely seen in standard setups, securing the system's own integrity against sophisticated "cover-your-tracks" attacks.

**Future Work** includes:
- **Deep Learning**: Replacing Random Forest with LSTM/CNNs for time-series analysis of traffic flows.
- **Decentralized Consensus**: utilizing a consortium blockchain for multi-node threat intelligence sharing.
- **Automated IPS**: Expanding from Detection (IDS) to Prevention (IPS) by automatically modifying firewall rules via the `triggerIncidentResponse` smart contract function.

---
