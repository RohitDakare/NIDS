# 🛡️ AI-Based Network Intrusion Detection System (NIDS)

A comprehensive full-stack Network Intrusion Detection System that combines signature-based detection and machine learning-based anomaly detection with a modern web dashboard.

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Running the Application](#-running-the-application)
- [API Documentation](#-api-documentation)
- [Development](#-development)
- [Testing](#-testing)
- [Deployment](#-deployment)
- [Contributing](#-contributing)
- [License](#-license)

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

## 🏗️ Architecture

```
NIDS/
├── backend/ (Python FastAPI)
│   ├── app/
│   │   ├── api/          # API routes
│   │   ├── core/         # Core NIDS functionality
│   │   │   ├── packet_sniffer.py     # Network capture
│   │   │   ├── ml_detector.py        # ML anomaly detection
│   │   │   ├── signature_detector.py # Signature matching
│   │   │   └── alert_manager.py      # Alert handling
│   │   ├── db/           # Database operations
│   │   └── models/       # Pydantic models
│   ├── scripts/          # Utility scripts
│   └── requirements.txt  # Python dependencies
│
├── frontend/ (Next.js)
│   ├── nids-dashboard/
│   │   ├── app/          # Next.js app router
│   │   ├── components/   # React components
│   │   ├── hooks/        # Custom React hooks
│   │   ├── lib/          # Utilities and API client
│   │   └── package.json  # Node dependencies
│
└── docs/                 # Documentation
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

For a streamlined setup experience, use our automated setup script:

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

### 1. Clone the Repository

```bash
git clone <repository-url>
cd NIDS
```

### 2. Backend Setup

#### Create Virtual Environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python -m venv venv
source venv/bin/activate
```

#### Install Python Dependencies
```bash
pip install -r requirements.txt
```

#### Setup MongoDB
1. **Install MongoDB**:
   - Download from [mongodb.com](https://www.mongodb.com/try/download/community)
   - Start MongoDB service

2. **Initialize Database**:
   ```bash
   python scripts/init_mongodb.py
   ```

### 3. Frontend Setup

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

# Logging
LOG_LEVEL=INFO
```

### Network Interface Configuration

**Windows:**
- Install Npcap from [npcap.com](https://npcap.com/)
- Use `configure_interface.py` to list available interfaces

**Linux/Mac:**
- Install libpcap: `sudo apt install libpcap-dev` (Ubuntu/Debian)
- Use `ifconfig` or `ip addr` to find interface names

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
# or
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
```

#### Frontend
```bash
cd nids-dashboard
npm run build
npm start
```

### Access Points

- **Frontend Dashboard**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **System Info**: http://localhost:8000/info

## 📡 API Endpoints

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

## 🧪 Testing

### Backend Tests
```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=app --cov-report=html
```

### Frontend Tests
```bash
cd nids-dashboard
npm test
```

### Demo Mode
```bash
# Run the demo script
python demo.py
```

## 🔧 Development

### Project Structure
- `app/` - FastAPI backend application
- `nids-dashboard/` - Next.js frontend application
- `scripts/` - Utility and setup scripts
- `tests/` - Test suites
- `docs/` - Documentation

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
# Build and run backend + frontend + MongoDB
docker compose up -d --build

# Set environment (production example)
# Create a .env file with:
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

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/your-repo/issues)
- **Documentation**: See `docs/` directory
- **API Docs**: Available at `/docs` when running

## 🔒 Security Considerations

- Run with appropriate network permissions
- Use HTTPS in production
- Regularly update dependencies
- Monitor system performance
- Implement rate limiting
- Secure API endpoints

---

**Built with ❤️ for network security professionals**
