# ⚔️ NIDS Attack Simulation Guide

This guide explains how to use the attack simulation tools to test the NIDS detection capabilities.

## 🚀 How to Run Simulations

### 1. Basic Simulation (Concurrent Port Scan + Floods)
The updated simulation script now supports **concurrent multi-threaded port scanning**, making it significantly faster and more aggressive (simulating a real "noisy" scanner).

```powershell
cd backend
python simulate_attacks.py
```

**Features:**
- ⚡ **Concurrent Scanning**: Uses 200 threads to scan ports 1-9000 simultaneously.
- 🌊 **SYN Flood**: Floods port 8000 with connection attempts.
- 🕵️ **Suspicious Payloads**: Sends SQLi, XSS, and other malicious signatures.

### 2. Advanced Usage
You can modify `backend/simulate_attacks.py` to customize the attack:

- **Target IP**: Change `target = "127.0.0.1"` to a different IP if testing across network.
- **Port Range**: Adjust `args=(target, 1, 9000, 200)` in the `main` block.
- **Thread Count**: Increase `max_threads` (default 200) for even faster scanning.

---

## 🛡️ Detection in NIDS

When you run `simulate_attacks.py`, the NIDS should generate alerts if configured correctly.

### Port Scan Detection
- **Rule ID**: `SIG-002` (Signature Detector)
- **Logic**: Detects when a single source IP touches >50 unique ports in a short window.
- **Expected Alert**: "Port Scan Detected from 127.0.0.1"

### DDoS / Flood Detection
- **Rule ID**: `SIG-003` (and Rate Limiter)
- **Logic**: Detects high packet rate or SYN flood (>20 SYN/sec).
- **Expected Alert**: "DDoS Attack Detected" or "Rate Limit Exceeded"

### Web Attack Detection
- **Rule IDs**: `SIG-004` (SQLi), `SIG-005` (XSS)
- **Logic**: Matches regex patterns in packet payloads.
- **Expected Alerts**: "SQL Injection Attempt", "XSS Attack Detected"

---

## ⚠️ Troubleshooting Detection

If you don't see alerts on the dashboard:

1. **Check Interface**: Ensure NIDS contains the `Loopback` interface if testing on localhost (`127.0.0.1`).
   - Windows Npcap: Install with "Loopback Adapter Support".
   - NIDS Config: Set `INTERFACE=Loopback Pseudo-Interface 1` (or similar) in `.env`.
   
2. **Test Across Network**: 
   - Run NIDS on Machine A.
   - Run `simulate_attacks.py` on Machine B (targeting Machine A's IP).
   - This keeps traffic on the "Ethernet" interface, which is easier to capture.

3. **Check Logs**:
   - Look at `backend/logs/nids.log` for "Packet captured" messages.

---

## ⚡ Performance Note
The new concurrent scanner is very aggressive.
- **Old Speed**: ~10 ports/second
- **New Speed**: ~500+ ports/second

Use responsibly!
