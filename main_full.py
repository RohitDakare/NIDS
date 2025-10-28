import os
import logging
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import uvicorn
from contextlib import asynccontextmanager
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.api.routes import router
from app.utils.config import settings
from app.utils.security import SecurityMiddleware, security_manager

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/nids.log'),
        logging.StreamHandler()
    ]
)

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
        # Basic initialization without complex components for now
        logger.info("NIDS system initialized successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize NIDS system: {e}")
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down NIDS application...")

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

# Add trusted host middleware
allowed_hosts = os.getenv("CORS_ORIGINS", "localhost,127.0.0.1").split(",")
app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

# Add secure CORS middleware
cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:3000,https://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
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

# API endpoints are now provided by the router

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
    logger.info("Starting NIDS backend server...")
    uvicorn.run(
        "main_full:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
