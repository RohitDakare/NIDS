# 🚀 NIDS Quick Start Guide

## ⚡ Instant Start (Current Session)

Since your services are **already running**, simply open your browser:

### 👉 [http://localhost:3000](http://localhost:3000)

---

## 🔧 Manual Startup Guide

If you need to restart the services, follow these standard steps.

### 1. Start Backend
The backend handles packet sniffing and detection logic.

```powershell
# Open Terminal 1
cd "d:\Rohit imp file\Project\NIDS\backend"

# Activate Virtual Environment (if not active)
.\venv_clean\Scripts\activate

# Run the Server
python main_working.py
```
*Wait until you see:* `Application startup complete.`

### 2. Start Frontend
The frontend provides the visual dashboard.

```powershell
# Open Terminal 2
cd "d:\Rohit imp file\Project\NIDS\frontend"

# Run Development Server
npm run dev
```
*Wait until you see:* `Ready in ...s`

---

## 🧪 Testing the System

### Generate Simulated Attacks
To verify that the NIDS is detecting threats, generation of simulated traffic is recommended.

1.  Ensure the **Backend** is running.
2.  Open a **new terminal**.
3.  Run the attack generator:

```powershell
cd "d:\Rohit imp file\Project\NIDS\backend"
.\venv_clean\Scripts\activate
python simulate_attacks.py
```

4.  Select an attack type (e.g., `1` for DDoS).
5.  Check the **Dashboard** ([localhost:3000](http://localhost:3000)) for new alerts.

---

## 🆘 Common Troubleshooting

| Issue | Solution |
|-------|----------|
| **Backend fails to start** | Ensure you are in `backend/` and `venv_clean` is activated. Run `pip install -r requirements.txt` if needed. |
| **Frontend fails to start** | Ensure you are in `frontend/`. Run `npm install` to update dependencies. |
| **No Alerts appearing** | Make sure you clicked **"Start Monitoring"** in the Detection tab. |
| **Permission Denied** | Packet sniffing often requires Admin privileges. Run the backend terminal as **Administrator**. |

---

### 📚 Key File Locations
- **Backend Entry**: `backend/main_working.py`
- **Frontend Entry**: `frontend/app/page.tsx`
- **Logs**: `backend/logs/nids.log`
