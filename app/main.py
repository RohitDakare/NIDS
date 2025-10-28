import os
import logging
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import uvicorn
import logging
import os
from contextlib import asynccontextmanager
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.api.routes import router
from app.core.nids_orchestrator import NIDSOrchestrator
from app.utils.config import settings
from app.utils.security import SecurityMiddleware, security_manager
from app.models.schemas import SnifferConfig, MLModelConfig
from app.core.nids_orchestrator import NIDSOrchestrator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/nids.log'),
        logging.StreamHandler()
    ]
)

# Load environment variables from .env file
load_dotenv()

logger = logging.getLogger(__name__)

# Create necessary directories
os.makedirs('app/ml_models', exist_ok=True)
os.makedirs('data', exist_ok=True)
os.makedirs('logs', exist_ok=True)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    logger.info("Starting NIDS application...")
    
    try:
        # Initialize NIDS orchestrator
        # Default to Wi-Fi interface on Windows, loopback on Linux
        default_interface = "Wi-Fi" if os.name == 'nt' else "lo"
        sniffer_config = SnifferConfig(
            interface=os.getenv("INTERFACE", default_interface),
            packet_count=int(os.getenv("PACKET_COUNT", "1000")),
            timeout=int(os.getenv("TIMEOUT", "30"))
        )
        
        ml_config = MLModelConfig(
            model_path=os.getenv("MODEL_PATH", "app/ml_models/nids_model.joblib"),
            confidence_threshold=float(os.getenv("CONFIDENCE_THRESHOLD", "0.8"))
        )
        
        # Create NIDS orchestrator
        global nids_orchestrator
        nids_orchestrator = NIDSOrchestrator(
            sniffer_config=sniffer_config,
            ml_config=ml_config,
            alert_callback=lambda alert: logger.info(f"Alert generated: {alert.description}")
        )
        # Import routes module to set the orchestrator
        from app.api import routes
        routes.nids_orchestrator = nids_orchestrator
        
        logger.info("NIDS system initialized successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize NIDS system: {e}")
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down NIDS application...")
    
    try:
        if nids_orchestrator:
            nids_orchestrator.stop()
            logger.info("NIDS system stopped successfully")
    except Exception as e:
        logger.error(f"Error during shutdown: {e}")

# Create FastAPI application
app = FastAPI(
    title="AI-Based Network Intrusion Detection System (NIDS)",
    description="""
    A comprehensive Python-based backend for a hybrid Network Intrusion Detection System 
    that integrates signature-based detection and machine learning-based anomaly detection.
    
    ## Features
    
    - **Real-time Packet Sniffing**: Capture and analyze live network traffic
    - **ML-Based Anomaly Detection**: Pre-trained machine learning models for threat detection
    - **Signature-Based Detection**: Rule-based pattern matching for known attacks
    - **Alerting & Logging**: Comprehensive logging and alert generation
    - **RESTful API**: FastAPI-based interface for system control and monitoring
    
    ## Quick Start
    
    1. Start the system: `POST /start-sniffer`
    2. Monitor status: `GET /status`
    3. View alerts: `GET /alerts`
    4. Stop the system: `POST /stop-sniffer`
    """,
    version="1.0.0",
    contact={
        "name": "NIDS Development Team",
        "email": "nids@example.com",
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT",
    },
    lifespan=lifespan
)

# Add security middleware
app.add_middleware(SecurityMiddleware)

def _split_env_list(value: str, default: list[str]) -> list[str]:
    if not value:
        return default
    return [item.strip() for item in value.split(',') if item.strip()]

# Trusted hosts from env (CSV). Default to localhost only in production-safe way
trusted_hosts_env = os.getenv("TRUSTED_HOSTS", "localhost,127.0.0.1")
trusted_hosts = _split_env_list(trusted_hosts_env, ["localhost", "127.0.0.1"])
app.add_middleware(TrustedHostMiddleware, allowed_hosts=trusted_hosts)

# CORS allowed origins from env (CSV). Defaults include local dev hosts
cors_origins_env = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000")
cors_origins = _split_env_list(cors_origins_env, ["http://localhost:3000", "http://127.0.0.1:3000"])

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Include API routes
app.include_router(router, prefix="/api/v1", tags=["NIDS API"])

@app.get("/", tags=["Root"])
async def root():
    """Root endpoint with system information"""
    return {
        "message": "AI-Based Network Intrusion Detection System (NIDS)",
        "version": "1.0.0",
        "status": "running",
        "documentation": "/docs",
        "api_base": "/api/v1"
    }

@app.get("/info", tags=["System Info"])
async def system_info():
    """Get system information"""
    return {
        "system": "AI-Based NIDS",
        "version": "1.0.0",
        "description": "Network Intrusion Detection System with ML and Signature-based detection",
        "features": [
            "Real-time packet sniffing",
            "ML-based anomaly detection",
            "Signature-based detection",
            "Alert management",
            "RESTful API"
        ],
        "endpoints": {
            "start_sniffer": "POST /api/v1/start-sniffer",
            "stop_sniffer": "POST /api/v1/stop-sniffer",
            "status": "GET /api/v1/status",
            "alerts": "GET /api/v1/alerts",
            "packets": "GET /api/v1/packets",
            "stats": "GET /api/v1/stats",
            "health": "GET /api/v1/health"
        }
    }

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler"""
    logger.error(f"Unhandled exception: {exc}")
    return {
        "error": "Internal server error",
        "message": str(exc),
        "status_code": 500
    }

if __name__ == "__main__":
    # Run the application
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    ) 