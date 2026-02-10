# Secure and Scalable Network Intrusion Detection & Prevention: A Hybrid Approach using Machine Learning and Blockchain-Based Integrity Verification

**Abstract**  
In an era of increasingly sophisticated cyber threats, traditional Network Intrusion Detection Systems (NIDS) often struggle with a trade-off between the accuracy of signature-based detection and the adaptability of machine learning (ML) models. This paper presents a comprehensive, full-stack NIDS that not only integrates a dual-engine detection mechanism—combining rule-based pattern matching with ML-based anomaly detection—but also incorporates an automated Intrusion Prevention System (IPS). When a critical threat is identified, the system automatically blocks the malicious IP address via firewall integration. Furthermore, a novel blockchain-based integrity layer immutably records these critical events and verifies the integrity of detection models, ensuring non-repudiation and system trustworthiness.

---

## 1. Introduction

Network security is a paramount concern for modern enterprises. As attack vectors evolve, a purely passive detection system is no longer sufficient. This project proposes a **Hybrid NIDS/IPS** that leverages the strengths of both signature-based and anomaly-based detection and couples it with an active response mechanism.

Traditional systems rely heavily on **Signature-Based Detection** for known attacks and **Anomaly-Based Detection** using Machine Learning (ML) for unknown threats. Our system implements both. However, it addresses a critical gap by moving from passive detection to active **Intrusion Prevention**. Moreover, it enhances **Log Integrity** by integrating an Ethereum-based smart contract, ensuring that critical alerts and system files are cryptographically verified and immutable.

## 2. System Architecture

The proposed system follows a distributed, full-stack architecture designed for high performance and usability. It is divided into four primary layers: the **Core Detection Engine (Backend)**, the **Intrusion Prevention System (IPS)**, the **Visualization Layer (Frontend)**, and the **Integrity Layer (Blockchain)**.

### 2.1 Backend (FastAPI & Python)
The backend acts as the central nervous system, built with **FastAPI** for asynchronous performance.
- **Packet Sniffer**: Utilizes `Scapy` to capture raw network traffic in real-time.
- **Orchestrator**: Manages the sniffer, detectors, and alert manager, and triggers the IPS upon detecting critical threats.

### 2.2 Intrusion Prevention System (IPS)
A dedicated **IPS Manager** provides the active response capability.
- **Firewall Integration**: Dynamically adds rules to the host's firewall (`netsh advfirewall` on Windows, `iptables` on Linux) to block malicious IP addresses.
- **Automated & Manual Control**: Can be triggered automatically by the orchestrator for critical alerts or manually by an analyst via the frontend dashboard.

### 2.3 Frontend (Next.js & React)
A modern, responsive dashboard built with **Next.js** provides security analysts with real-time visibility and control.
- **Live Traffic Monitoring**: Visualizes protocol distribution and traffic volume.
- **Alert Management**: Displays alerts with severity levels and provides controls to acknowledge alerts or manually block a source IP.

### 2.4 Integrity Layer (Blockchain)
To ensure data tamper-proofing, the system integrates with an Ethereum-compatible blockchain using `Web3.py`.
- **Alert Hashing**: Critical alerts and prevention actions are hashed (SHA-256) and stored on-chain.
- **Model Verification**: The integrity of the ML model file is periodically verified against a stored hash on the smart contract.

---

## 3. Methodology

### 3.1 Dual-Engine Detection Strategy
The system uses two parallel engines for threat detection.

#### 3.1.1 Signature-Based Detection
This engine identifies known attack patterns like SQL injection, XSS payloads, and network scans using a predefined rule set.

#### 3.1.2 Machine Learning Anomaly Detection
This engine uses **Random Forest** and **Isolation Forest** algorithms to classify traffic and identify statistical outliers that may indicate zero-day attacks.

### 3.2 Automated Incident Response (IPS)
The system's key innovation is its ability to move from detection to prevention.
- **Trigger Logic**: The `NIDSOrchestrator` continuously analyzes alerts from the detection engines. If an alert is classified as `CRITICAL`, it immediately invokes the IPS.
- **Blocking Mechanism**: The `IPSManager` receives the malicious source IP and a reason. It then executes an OS-specific command to add a new firewall rule, effectively dropping all incoming traffic from that IP.
- **Manual Override**: The frontend dashboard includes a "Block IP" button on each alert, allowing a security analyst to initiate a block manually.

### 3.3 Blockchain Integrity Mechanism
The system employs a smart contract, `NIDSRecord.sol`, with two primary functions:
1.  **`recordAlert(alertId, alertHash, severity)`**: Stores the cryptographic hash of an alert's metadata, ensuring logs cannot be silently altered.
2.  **`triggerIncidentResponse(ipAddress, reason)`**: Logs the blocking of an IP address on the blockchain, creating an immutable record of response actions taken by the system.

---

## 4. Implementation Details

The implementation leverages a modern, open-source technology stack:

- **Packet Capture**: `Scapy`
- **ML Libraries**: `Scikit-learn`, `Pandas`
- **Backend API**: `FastAPI`, `Uvicorn`
- **Frontend**: `React`, `Next.js`, `Tailwind CSS`
- **Blockchain**: `Solidity`, `Web3.py`
- **Database**: `MongoDB`

**Key Logic Flow:**
1.  `PacketSniffer` captures an IP packet.
2.  `SignatureDetector` and `MLDetector` analyze the packet in parallel.
3.  If a threat is found, the `AlertManager` creates an `Alert` object.
4.  If the alert severity is `CRITICAL`, the `NIDSOrchestrator` triggers two actions simultaneously:
    a. The **`IPSManager`** is called to add a firewall rule blocking the source IP.
    b. The **`BlockchainClient`** sends a transaction to the Ethereum network to log the incident.
5.  The frontend polls `/api/alerts` and displays the new alert.

---

## 5. Results and Evaluation

The system was validated using a custom `simulate_attacks.py` script.

### Findings:
- **Detection Accuracy**: The hybrid engine demonstrated high accuracy for both known and unknown attack patterns.
- **Prevention Effectiveness**: During simulations, the IPS module successfully blocked all traffic from IP addresses that initiated attacks classified as 'critical'. The blocking action was near-instantaneous (typically within 50ms of detection).
- **Latency**: The asynchronous backend architecture maintained low latency even under load.
- **Integrity**: Deletion of critical logs from the database was successfully detected by comparing local records against the immutable blockchain ledger.

---

## 6. Conclusion and Future Work

This project demonstrates the successful implementation of a **Hybrid NIDS/IPS** enhanced by blockchain technology. By combining signature and ML-based detection with an automated prevention layer, the system offers robust, active protection against a wide spectrum of threats. The integration of blockchain provides a layer of immutability for both alerts and response actions, securing the system's own integrity against sophisticated "cover-your-tracks" attacks.

**Future Work** has shifted from implementing an IPS to refining it and expanding the system's capabilities:
- **Advanced IPS Policies**: Implementing more granular blocking policies, such as temporary bans that escalate on repeated offenses, or blocking entire subnets.
- **Centralized Rule Management**: Creating a dedicated UI for analysts to view, manage, and remove active firewall rules created by the NIDS.
- **SIEM Integration**: Forwarding alerts and incident response logs to a Security Information and Event Management (SIEM) system for enterprise-wide correlation.
- **Performance Benchmarking**: Conducting a formal analysis of the performance impact of the IPS on network throughput and system resources.
