# 🛡️ AI-Based Network Intrusion Detection System (NIDS)

A comprehensive full-stack Network Intrusion Detection System that combines signature-based detection and machine learning-based anomaly detection with a modern web dashboard.

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Running the Application](#-running-the-application)
- [Testing with Data Packets](#-testing-with-data-packets)
- [API Documentation](#-api-documentation)
- [Machine Learning Training](#-machine-learning-training)
- [Security Setup](#-security-setup)
- [Frontend Dashboard](#-frontend-dashboard)
- [Testing](#-testing)
- [Development](#-development)
- [Deployment](#-deployment)
- [Troubleshooting](#-troubleshooting)
- [Support](#-support)

## 🎯 Features

- **Real-time Packet Sniffing**: Capture and analyze live network traffic
- **Dual Detection Engines**:
  - ML-Based Anomaly Detection using pre-trained models
  - Signature-Based Detection with rule-based pattern matching
- **Modern Web Dashboard**: Real-time monitoring and visualization
- **RESTful API**: FastAPI-based backend for system control
- **Alert Management**: Comprehensive alert generation and tracking
- **Database Storage**: MongoDB for alerts, packets, and system data
- **Performance Monitoring**: System health and metrics tracking
- **Responsive UI**: Mobile-friendly dashboard with dark/light themes
- **Security Features**: API authentication, rate limiting, input validation, SSL/TLS support

## 🏗️ Architecture

```
NIDS/
├── app/                      # FastAPI backend application
│   ├── api/                  # API routes
│   ├── core/                 # Core NIDS functionality
│   │   ├── packet_sniffer.py      # Network capture
│   │   ├── ml_detector.py          # ML anomaly detection
│   │   ├── signature_detector.py   # Signature matching
│   │   ├── alert_manager.py        # Alert handling
│   │   └── nids_orchestrator.py    # Main orchestrator
│   ├── db/                   # Database operations
│   ├── models/               # Pydantic models
│   ├── utils/                # Utility functions
│   ├── ml_models/            # Trained ML models
│   └── main.py               # FastAPI entry point
│
├── nids-dashboard/           # Next.js frontend application
│   ├── app/                  # Next.js app router
│   ├── components/           # React components
│   ├── hooks/                # Custom React hooks
│   └── lib/                  # Utilities and API client
│
├── scripts/                  # Utility scripts
│   ├── setup_and_test.py     # Automated setup
│   ├── secure_deploy.py      # Security hardening
│   ├── train_models.py       # ML model training
│   ├── init_mongodb.py       # Database initialization
│   └── security_test.py      # Security testing
│
├── tests/                    # Test suites
│   ├── unit/                 # Unit tests
│   ├── integration/          # Integration tests
│   └── e2e/                  # End-to-end tests
│
├── data/                     # Training data and datasets
├── logs/                     # Application logs
└── config/                   # Configuration files
```

## 📋 Prerequisites

### Backend Requirements
- **Python 3.8+**
- **MongoDB** (local installation or cloud instance)
- **Npcap** (Windows) or **libpcap** (Linux/Mac) for packet capture

### Frontend Requirements
- **Node.js 18+**
- **npm** or **yarn**

### System Requirements
- **Administrative privileges** for packet capture
- **Network interface** with packet capture capabilities
- **4GB RAM** minimum (8GB recommended)
- **2GB free disk space**

## 🚀 Installation

### Quick Setup (Recommended)

For a streamlined setup experience, use the automated setup script:

```bash
# Clone the repository
git clone <repository-url>
cd NIDS

# Run automated setup and testing
python scripts/setup_and_test.py
```

This script will:
- ✅ Check Python version compatibility
- ✅ Install all dependencies
- ✅ Create necessary directories
- ✅ Set up environment configuration
- ✅ Train an initial ML model
- ✅ Test core module imports
- ✅ Validate database connection

### Manual Setup

#### 1. Clone the Repository

```bash
git clone <repository-url>
cd NIDS
```

#### 2. Backend Setup

##### Create Virtual Environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python -m venv venv
source venv/bin/activate
```

##### Install Python Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt

# For Windows with scikit-learn issues
pip install -r config/requirements-windows.txt
```

##### Setup MongoDB
1. **Install MongoDB**:
   - Download from [mongodb.com](https://www.mongodb.com/try/download/community)
   - Start MongoDB service

2. **Initialize Database**:
   ```bash
   python scripts/init_mongodb.py
   ```

#### 3. Frontend Setup

```bash
cd nids-dashboard
npm install
cd ..
```

## ⚙️ Configuration

### Environment Variables

Copy the example configuration file:

```bash
cp config/env.example .env
```

Edit `.env` with your settings:

```env
# Network Configuration
INTERFACE=eth0  # Your network interface (use 'ipconfig' on Windows or 'ifconfig' on Linux to find)
PACKET_COUNT=1000
TIMEOUT=30

# ML Model Settings
MODEL_PATH=app/ml_models/nids_model.joblib
CONFIDENCE_THRESHOLD=0.8

# Database Configuration
MONGODB_URL=mongodb://localhost:27017
MONGODB_DB_NAME=nids

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000

# Security Configuration (for production)
API_KEY=<your-api-key>
JWT_SECRET=<your-jwt-secret>
ENABLE_RATE_LIMITING=true
ENABLE_API_AUTH=true
ENABLE_HTTPS=false

# CORS Configuration
CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000

# Logging
LOG_LEVEL=INFO
```

### Network Interface Configuration

**Windows:**
- Install Npcap from [npcap.com](https://npcap.com/)
- Use `configure_interface.py` to list available interfaces:
  ```bash
  python configure_interface.py
  ```
- Common interfaces: `Ethernet`, `Wi-Fi`, `Local Area Connection`

**Linux/Mac:**
- Install libpcap: `sudo apt install libpcap-dev` (Ubuntu/Debian)
- Use `ifconfig` or `ip addr` to find interface names
- Common interfaces: `eth0`, `wlan0`, `lo`

## 🏃 Running the Application

### Development Mode

#### Start Backend (Terminal 1)
```bash
# Activate virtual environment
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# Start FastAPI server
python -m app.main

# Or using uvicorn directly
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

#### Start Frontend (Terminal 2)
```bash
cd nids-dashboard
npm run dev
```

### Production Mode

#### Backend
```bash
# Using the startup script
./start_nids.sh  # Linux/Mac
# or
start_nids.bat   # Windows

# Or directly
python -m app.main
```

#### Frontend
```bash
cd nids-dashboard
npm run build
npm start
```

### Docker Deployment

```bash
# Build and run backend + frontend + MongoDB
docker compose up -d --build

# View logs
docker compose logs -f

# Stop services
docker compose down
```

### Access Points

- **Frontend Dashboard**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **System Info**: http://localhost:8000/info
- **Health Check**: http://localhost:8000/api/v1/health

## 🧪 Testing with Data Packets

The NIDS system can be tested with various attack patterns and data packets. Here are the commands to test the system:

### Prerequisites for Packet Testing

1. **Start the NIDS System**:
   ```bash
   python -m app.main
   ```

2. **Start the Sniffer** (via API or dashboard):
   ```bash
   # Using curl
   curl -X POST http://localhost:8000/api/v1/start-sniffer \
        -H "Content-Type: application/json" \
        -d '{"interface": "Wi-Fi"}'
   ```

### Method 1: Simulated Attack Testing (Safe - Recommended)

These scripts generate attack patterns without sending real network traffic:

```bash
# Generate simulated attack traffic
python generate_attack_traffic.py

# Create predefined attack patterns
python create_test_attacks.py

# Run comprehensive test suite
python test_nids_with_attacks.py

# Quick attack test
python quick_attack_test.py
```

### Method 2: Real Network Attack Testing (Use with Caution)

⚠️ **WARNING**: These scripts generate real network traffic. Only use on networks you own or have permission to test.

```bash
# Generate real attack packets using Scapy
python real_attack_generator.py

# Run automated attack tests
python run_attack_tests.py
```

### Method 3: Anomaly Testing

```bash
# Test ML anomaly detection
python anomaly_test.py

# Direct testing
python test_direct.py
```

### Method 4: API-Based Testing

```bash
# Test API endpoints with sample data
python test_api.py

# Simple API test
python test_simple.py

# Test packet sniffer functionality
python test_sniffer.py
```

### Attack Types Supported

1. **DDoS (Distributed Denial of Service)**
   - High-frequency requests from multiple source IPs
   - Test: `python generate_attack_traffic.py` → Select "ddos"

2. **Port Scanning**
   - Systematic scanning of multiple ports
   - Test: `python generate_attack_traffic.py` → Select "port_scan"

3. **Brute Force Attacks**
   - Multiple login attempts with common passwords
   - Test: `python generate_attack_traffic.py` → Select "brute_force"

4. **SYN Flood**
   - High volume of SYN packets without completing handshake
   - Test: `python generate_attack_traffic.py` → Select "syn_flood"

5. **ICMP Flood**
   - High volume of ICMP packets (ping flood)
   - Test: `python generate_attack_traffic.py` → Select "icmp_flood"

6. **Slowloris Attack**
   - Slow HTTP requests to exhaust server connections
   - Test: `python generate_attack_traffic.py` → Select "slowloris"

7. **Anomalous Traffic**
   - Various unusual traffic patterns
   - Test: `python anomaly_test.py`

### Testing Workflow

1. **Start NIDS System**:
   ```bash
   python -m app.main
   ```

2. **Start Packet Capture** (in another terminal):
   ```bash
   curl -X POST http://localhost:8000/api/v1/start-sniffer \
        -H "Content-Type: application/json" \
        -d '{"interface": "Wi-Fi"}'
   ```

3. **Run Attack Generator** (in another terminal):
   ```bash
   python generate_attack_traffic.py
   # Select attack type when prompted
   ```

4. **Monitor Alerts**:
   ```bash
   # View alerts via API
   curl http://localhost:8000/api/v1/alerts
   
   # Or check the dashboard at http://localhost:3000
   ```

5. **Check Detection Statistics**:
   ```bash
   curl http://localhost:8000/api/v1/stats
   ```

### Expected Results

After running attack tests, you should see:
- ✅ Alerts generated for each attack type
- ✅ Detection rate > 80% for known attack patterns
- ✅ Alerts include: attack type, source IP, severity, timestamp
- ✅ Packet capture rate > 90% of attack packets
- ✅ Alert generation within 1-2 seconds of attack start

### Demo Mode

For a quick demonstration without setting up attacks:

```bash
# Run the demo script
python demo.py
```

This will simulate packet capture and detection without requiring actual network traffic.

## 📡 API Documentation

### Core Operations

- `POST /api/v1/start-sniffer` - Start packet monitoring
- `POST /api/v1/stop-sniffer` - Stop monitoring
- `GET /api/v1/status` - System health and status

### Data Retrieval

- `GET /api/v1/alerts` - Recent security alerts
- `GET /api/v1/packets` - Recent captured packets
- `GET /api/v1/stats` - Detection statistics
- `GET /api/v1/health` - Health check

### Management

- `POST /api/v1/alerts/{id}/resolve` - Resolve alerts
- `DELETE /api/v1/alerts/{id}` - Delete alerts
- `GET /api/v1/export/alerts` - Export alerts

### API Examples

```bash
# Start sniffer
curl -X POST http://localhost:8000/api/v1/start-sniffer \
     -H "Content-Type: application/json" \
     -d '{"interface": "Wi-Fi"}'

# Check status
curl http://localhost:8000/api/v1/status

# Get recent alerts
curl http://localhost:8000/api/v1/alerts

# Stop sniffer
curl -X POST http://localhost:8000/api/v1/stop-sniffer
```

**Note**: In production with authentication enabled, add header:
```bash
-H "Authorization: Bearer YOUR_API_KEY"
```

Full API documentation available at: http://localhost:8000/docs

## 🤖 Machine Learning Training

The NIDS system uses machine learning models for anomaly detection. Here's how to train and manage models:

### Quick Training (Recommended for beginners)

```bash
# Quick training with default settings
python scripts/train_models.py --quick

# Train specific models
python scripts/train_models.py --models random_forest isolation_forest

# Use synthetic data (if no real dataset available)
python scripts/train_models.py --synthetic --quick
```

### Web Dashboard Training

```bash
# Launch the training dashboard
python scripts/train_models.py --dashboard

# Then open: http://localhost:8001
```

### Advanced Training Pipeline

```bash
# Full pipeline with custom configuration
python scripts/ml_training_pipeline.py --data-path data/cic-ids2017 --models random_forest gradient_boosting
```

### Supported Models

1. **Random Forest** (Supervised) - Best for balanced datasets
2. **Gradient Boosting** (Supervised) - Highest accuracy
3. **Isolation Forest** (Unsupervised) - Best for unknown attacks
4. **One-Class SVM** (Unsupervised) - Strict anomaly detection

### Data Requirements

- **CIC-IDS2017 Dataset**: Download from https://www.unb.ca/cic/datasets/ids-2017.html
- Extract CSV files to `data/cic-ids2017/`
- Or use synthetic data: `python scripts/train_models.py --synthetic`

### Model Deployment

After training, models are automatically saved to `app/ml_models/`. The NIDS system will load the default model (`nids_model.joblib`) on startup.

## 🔒 Security Setup

### Quick Security Setup (5 Minutes)

```bash
# Run security hardening
python scripts/secure_deploy.py

# Setup MongoDB authentication
mongo < scripts/setup_mongodb.js

# Generate SSL certificates (Windows)
scripts\setup_ssl.bat

# Or on Linux/Mac
./scripts/setup_ssl.sh

# Install security dependencies
pip install -r requirements-security.txt

# Test security measures
python scripts/security_test.py
```

### Security Features

- ✅ API Authentication & Authorization
- ✅ Rate Limiting & DDoS Protection
- ✅ Input Validation & Sanitization
- ✅ Secure Database Configuration
- ✅ ML Model Integrity Verification
- ✅ Comprehensive Audit Logging
- ✅ HTTPS/TLS Encryption
- ✅ Security Headers & CORS

### Security Credentials

After running `secure_deploy.py`, check `scripts/SECURITY_CREDENTIALS.txt` for generated API keys and passwords.

⚠️ **IMPORTANT**: Delete this file after copying credentials to secure storage!

### Security Testing

```bash
# Run comprehensive security tests
python scripts/security_test.py

# Expected output: All tests should pass (9/9)
```

### Production Security Checklist

- [ ] Ran `secure_deploy.py`
- [ ] MongoDB authentication configured
- [ ] SSL certificates generated
- [ ] Security tests pass (100%)
- [ ] API authentication working
- [ ] Rate limiting active
- [ ] Input validation enabled
- [ ] Audit logging configured
- [ ] `.env` file secured

## 🎨 Frontend Dashboard

The NIDS dashboard provides real-time monitoring and visualization.

### Development

```bash
cd nids-dashboard
npm run dev
```

Access at: http://localhost:3000

### Production Build

```bash
cd nids-dashboard
npm run build
npm start
```

### Features

- Real-time alerts feed
- Traffic visualization (charts and graphs)
- Packet explorer with search and filters
- System health monitoring
- Alert management (acknowledge, resolve, delete)
- Configuration management
- Export functionality

## 🧪 Testing

### Backend Tests

```bash
# Run all tests
python tests/run_tests.py all

# Run specific test types
python tests/run_tests.py unit
python tests/run_tests.py integration
python tests/run_tests.py e2e

# Run with coverage
python tests/run_tests.py coverage

# Using pytest directly
pytest tests/
pytest tests/ --cov=app --cov-report=html
```

### Frontend Tests

```bash
cd nids-dashboard
npm test
```

### Test Categories

- **Unit Tests**: Individual component tests
- **Integration Tests**: Component interaction tests
- **End-to-End Tests**: Complete workflow tests
- **Performance Tests**: Slow-running tests

### Test Runner Options

```bash
# Run specific test file
python tests/run_tests.py specific --test-path tests/unit/test_ml_detector.py

# Run with verbose output
python tests/run_tests.py unit --verbose

# Code quality checks
python tests/run_tests.py lint
python tests/run_tests.py format
python tests/run_tests.py imports
```

## 🔧 Development

### Project Structure

- `app/` - FastAPI backend application
- `nids-dashboard/` - Next.js frontend application
- `scripts/` - Utility and setup scripts
- `tests/` - Test suites
- `data/` - Training data and datasets

### Adding New Features

1. **Backend**: Add routes in `app/api/routes.py`, implement logic in `app/core/`
2. **Frontend**: Add components in `nids-dashboard/components/`, pages in `nids-dashboard/app/`
3. **Database**: Update MongoDB schemas in `scripts/init_mongodb.py`

### Code Quality

```bash
# Backend linting
black app/
isort app/
flake8 app/

# Frontend linting
cd nids-dashboard
npm run lint
```

## 🚀 Deployment

### Docker Deployment (Recommended)

```bash
# Build and run all services
docker compose up -d --build

# Set environment variables in .env file:
# MONGODB_USERNAME=nids_user
# MONGODB_PASSWORD=strong-password
# API_KEY=prod-api-key
# CORS_ORIGINS=https://your-frontend-domain
# TRUSTED_HOSTS=your-backend-domain

# Access services
# API: http://localhost:8000
# Frontend: http://localhost:3000
```

### Manual Deployment

1. **Configure production environment**
2. **Set up reverse proxy** (nginx/apache)
3. **Enable SSL/TLS**
4. **Configure firewall rules**
5. **Set up monitoring and logging**

### Cloud Deployment

The application can be deployed to:
- **Vercel/Netlify** (Frontend)
- **Heroku/Railway** (Backend)
- **AWS/GCP/Azure** (Full stack)

## 🐛 Troubleshooting

### Common Issues

#### 1. "Permission Denied" for Packet Capture

**Windows:**
- Run as Administrator
- Install Npcap: https://npcap.com/

**Linux/Mac:**
- Run with sudo: `sudo python -m app.main`
- Or add user to appropriate groups

#### 2. "Network Interface Not Found"

```bash
# Windows: List interfaces
python configure_interface.py
# or
ipconfig

# Linux/Mac: List interfaces
ifconfig
# or
ip addr

# Update .env file with correct interface name
```

#### 3. "MongoDB Connection Failed"

```bash
# Check MongoDB is running
# Windows
net start MongoDB

# Linux
sudo systemctl start mongod

# Mac
brew services start mongodb-community

# Test connection
python scripts/init_mongodb.py
```

#### 4. "ML Model Not Found"

```bash
# Train initial model
python scripts/train_models.py --quick

# Or create dummy model
python create_dummy_model.py
```

#### 5. "Scikit-learn Installation Issues (Windows)"

See the Windows Installation section above, or:

```bash
# Use pre-compiled wheels
pip install --only-binary=all scikit-learn numpy pandas scipy

# Or install Visual C++ Build Tools
# Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/
```

#### 6. "Port Already in Use"

```bash
# Change port in .env file
API_PORT=8001

# Or find and kill process using port 8000
# Windows
netstat -ano | findstr :8000
taskkill /PID <PID> /F

# Linux/Mac
lsof -ti:8000 | xargs kill
```

#### 7. "API Authentication Failing"

```bash
# Check API key is set in .env
echo $API_KEY  # Linux/Mac
echo %API_KEY% # Windows

# Regenerate API key
python scripts/secure_deploy.py

# Restart server
python -m app.main
```

#### 8. "No Alerts Generated During Testing"

```bash
# Check ML model is loaded
curl http://localhost:8000/api/v1/status

# Verify sniffer is running
curl http://localhost:8000/api/v1/status | grep is_running

# Check detection thresholds
# Lower CONFIDENCE_THRESHOLD in .env if needed
```

### Debug Mode

```bash
# Enable debug logging
export LOG_LEVEL=DEBUG  # Linux/Mac
set LOG_LEVEL=DEBUG     # Windows

# Run with verbose output
python -m app.main --log-level debug
```

### Log Files

- Application logs: `logs/nids.log`
- Security logs: `logs/nids.log` (filter for "security")
- Training logs: `logs/ml_training_*.log`

## 📞 Support

### Resources

- **API Documentation**: http://localhost:8000/docs (when running)
- **Issue Tracker**: [GitHub Issues](https://github.com/your-repo/issues)
- **Logs**: Check `logs/nids.log` for errors

### Getting Help

1. Check the troubleshooting section above
2. Review log files in `logs/` directory
3. Run diagnostic scripts:
   ```bash
   python scripts/setup_and_test.py
   python scripts/security_test.py
   ```
4. Check system status:
   ```bash
   curl http://localhost:8000/api/v1/health
   ```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

### Development Guidelines

- Follow PEP 8 for Python code
- Use TypeScript for frontend components
- Write tests for new features
- Update documentation
- Ensure cross-platform compatibility

## 📚 Quick Command Reference

### Setup
```bash
python scripts/setup_and_test.py        # Automated setup
python scripts/init_mongodb.py          # Initialize database
python scripts/secure_deploy.py          # Security setup
```

### Running
```bash
python -m app.main                       # Start backend
cd nids-dashboard && npm run dev         # Start frontend
docker compose up -d                     # Docker deployment
```

### Testing
```bash
python tests/run_tests.py all           # Run all tests
python generate_attack_traffic.py       # Test with attacks
python demo.py                          # Demo mode
python scripts/security_test.py         # Security tests
```

### ML Training
```bash
python scripts/train_models.py --quick   # Quick training
python scripts/train_models.py --dashboard  # Web dashboard
python scripts/ml_training_pipeline.py   # Advanced training
```

### Configuration
```bash
python configure_interface.py            # List network interfaces
python detect_interfaces.py              # Auto-detect interfaces
```

---

**Built with ❤️ for network security professionals**

For detailed information about any specific aspect, check the inline code comments and API documentation at http://localhost:8000/docs when the server is running.
