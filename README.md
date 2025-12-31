# 🛡️ AI-Based Network Intrusion Detection System (NIDS)

A comprehensive, full-stack Network Intrusion Detection System combining signature-based rules and machine learning anomaly detection, featuring a modern real-time dashboard.

## 📋 Table of Contents
- [Features](#-features)
- [Project Structure](#-project-structure)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Running the Application](#-running-the-application)
- [Testing & Validation](#-testing--validation)
- [API Documentation](#-api-documentation)

## 🎯 Features

- **Real-time Packet Sniffing**: Captures and analyzes live network traffic.
- **Dual Detection Engines**:
  - **Machine Learning**: Anomaly detection using Random Forest/Isolation Forest.
  - **Signature-Based**: Rule-based pattern matching for known threats (DDoS, SQLi, etc.).
- **Modern Dashboard**: Built with Next.js, featuring real-time charts and alert management.
- **RESTful API**: FastAPI backend for robust system control.
- **Security**: Authentication, Rate Limiting, and Secure Headers.

## 🏗️ Project Structure

The project is organized into two main dedicated directories:

```
NIDS/
├── backend/                  # FastAPI Application
│   ├── app/
│   │   ├── core/            # Detection logic (Sniffer, ML, Signatures)
│   │   ├── api/             # API Endpoints
│   │   └── models/          # Data Models
│   ├── main_working.py      # Entry Point
│   ├── requirements.txt     # Python Dependencies
│   └── venv_clean/          # Virtual Environment
│
├── frontend/                 # Next.js Application
│   ├── app/                 # App Router & Pages
│   ├── components/          # UI Components
│   └── package.json         # Node Dependencies
│
└── docs/                     # Documentation files
```

## 📋 Prerequisites

- **OS**: Windows (preferred for Npcap) or Linux.
- **Python**: 3.8+
- **Node.js**: 18+
- **Packet Capture Driver**:
  - Windows: **Npcap** (ensure "Install Npcap in WinPcap API-compatible Mode" is checked).
  - Linux: `libpcap`

## 🚀 Installation

### 1. Clone the Repository
```bash
git clone <repository-url>
cd NIDS
```

### 2. Backend Setup
```bash
cd backend
python -m venv venv_clean
# Activate:
# Windows: .\venv_clean\Scripts\activate
# Linux: source venv_clean/bin/activate

pip install -r requirements.txt
```

### 3. Frontend Setup
```bash
cd frontend
npm install
```

## 🏃 Running the Application

### 1. Start the Backend
**Note:** For real packet capture on Windows, run your terminal as **Administrator**.

```bash
cd backend
python main_working.py
```
*Server will start at `http://0.0.0.0:8000`*

### 2. Start the Frontend
Open a new terminal (normal privileges are fine).

```bash
cd frontend
npm run dev
```
*Dashboard will be available at `http://localhost:3000`*

## 🧪 Testing & Validation

To verify the system is working, you can generate simulated attack traffic.

1.  Ensure the Backend is running.
2.  Open a terminal in the `backend/` directory.
3.  Run the generator:
    ```bash
    python generate_attack_traffic.py
    ```
4.  Follow the prompts to simulate attacks (e.g., DDoS, Port Scan).
5.  Check the **Dashboard** for alerts.

## 📡 API Documentation

Access the interactive Swagger UI at:
**[http://localhost:8000/docs](http://localhost:8000/docs)**

### Key Endpoints
- **GET** `/api/v1/health`: Check system status.
- **POST** `/api/v1/start-sniffer`: Begin capturing packets.
- **GET** `/api/v1/alerts`: Retrieve generated alerts.

## 👥 Support

For issues, please check the logs in `backend/logs/nids.log` or refer to the `RUN_SUMMARY.md` for the latest status.
