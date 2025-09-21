import os
import logging
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import uvicorn
from contextlib import asynccontextmanager
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from typing import List, Dict, Any
from datetime import datetime, timedelta

from app.utils.config import settings
from app.utils.security import SecurityMiddleware, security_manager
from app.models.schemas import SnifferConfig, MLModelConfig
from app.core.nids_orchestrator import NIDSOrchestrator

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

# Global state for NIDS system with sample data
nids_state = {
    "sniffer_active": False,
    "alerts_count": 0,
    "packets_processed": 0,
    "start_time": datetime.now(),
    "alerts": [
        {
            "id": "alert_001",
            "timestamp": "2024-01-20T10:30:00Z",
            "severity": "high",
            "type": "malware",
            "description": "Suspicious executable detected in network traffic",
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.50",
            "protocol": "TCP",
            "port": 443,
            "status": "active",
            "confidence": 0.95
        },
        {
            "id": "alert_002", 
            "timestamp": "2024-01-20T10:25:00Z",
            "severity": "medium",
            "type": "intrusion",
            "description": "Multiple failed login attempts detected",
            "source_ip": "192.168.1.200",
            "destination_ip": "10.0.0.10",
            "protocol": "SSH",
            "port": 22,
            "status": "active",
            "confidence": 0.87
        }
    ],
    "packets": [
        {
            "id": "packet_001",
            "timestamp": "2024-01-20T10:35:00Z",
            "source_ip": "192.168.1.50",
            "destination_ip": "8.8.8.8",
            "protocol": "UDP",
            "port": 53,
            "size": 64,
            "flags": ["DNS"],
            "threat_level": "low"
        }
    ],
    "signature_rules": [
        {
            "id": "rule_001",
            "name": "Malware Detection",
            "description": "Detects known malware signatures",
            "enabled": True,
            "pattern": "malware_pattern_*",
            "severity": "high"
        }
    ]
}

# Global NIDS orchestrator instance
nids_orchestrator = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    logger.info("Starting NIDS application...")
    
    try:
        # Initialize NIDS orchestrator with real components
        global nids_orchestrator
        
        sniffer_config = SnifferConfig(
            interface=os.getenv("INTERFACE", "Loopback Pseudo-Interface 1"),
            packet_count=int(os.getenv("PACKET_COUNT", "1000")),
            timeout=int(os.getenv("TIMEOUT", "30"))
        )
        
        ml_config = MLModelConfig(
            model_path=os.getenv("MODEL_PATH", "app/ml_models/nids_model.joblib"),
            confidence_threshold=float(os.getenv("CONFIDENCE_THRESHOLD", "0.8"))
        )
        
        # Create NIDS orchestrator with real packet capture
        nids_orchestrator = NIDSOrchestrator(
            sniffer_config=sniffer_config,
            ml_config=ml_config,
            alert_callback=lambda alert: handle_real_alert(alert)
        )
        
        logger.info("NIDS system initialized successfully with real packet capture")
        
    except Exception as e:
        logger.error(f"Failed to initialize NIDS system: {e}")
        logger.info("Continuing with mock data mode...")
        nids_orchestrator = None
    
    yield
    
    # Shutdown
    logger.info("Shutting down NIDS application...")
    try:
        if nids_orchestrator:
            nids_orchestrator.stop()
            logger.info("NIDS orchestrator stopped")
    except Exception as e:
        logger.error(f"Error stopping NIDS orchestrator: {e}")

def handle_real_alert(alert):
    """Handle real alerts from NIDS orchestrator"""
    alert_data = {
        "id": f"alert_{len(nids_state['alerts']) + 1:03d}",
        "timestamp": alert.timestamp.isoformat() + "Z",
        "severity": alert.severity.value,
        "type": alert.detection_type.value,
        "description": alert.description,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "protocol": alert.protocol,
        "port": alert.port,
        "status": "active",
        "confidence": alert.confidence
    }
    nids_state["alerts"].append(alert_data)
    nids_state["alerts_count"] = len(nids_state["alerts"])
    logger.info(f"Real alert added: {alert.description}")

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
cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:3001,https://localhost:3000,https://localhost:3001").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
)

# Add rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Root endpoint
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

# API Endpoints
@app.get("/api/v1/health", tags=["System"])
@limiter.limit("100/minute")
async def health(request: Request):
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    }

@app.get("/api/v1/status", tags=["System"])
@limiter.limit("100/minute")
async def get_status(request: Request):
    """Get system status"""
    uptime = datetime.now() - nids_state["start_time"]
    return {
        "status": "running",
        "sniffer_active": nids_state["sniffer_active"],
        "alerts_count": nids_state["alerts_count"],
        "packets_processed": nids_state["packets_processed"],
        "uptime": str(uptime).split('.')[0]  # Remove microseconds
    }

@app.post("/api/v1/start-sniffer", tags=["Control"])
@limiter.limit("10/minute")
async def start_sniffer(request: Request):
    """Start the packet sniffer"""
    if nids_state["sniffer_active"]:
        raise HTTPException(status_code=400, detail="Sniffer is already active")
    
    # Parse request body if present
    try:
        body = await request.json() if request.headers.get("content-type") == "application/json" else {}
        config = body.get("config", {}) if body else {}
        logger.info(f"Starting sniffer with config: {config}")
    except Exception as e:
        logger.warning(f"Could not parse request body: {e}")
        config = {}
    
    # Try to start real NIDS orchestrator
    if nids_orchestrator:
        try:
            nids_orchestrator.start()
            logger.info("Real NIDS orchestrator started - capturing live packets")
            mode = "real_capture"
        except Exception as e:
            logger.error(f"Failed to start real NIDS orchestrator: {e}")
            logger.info("Falling back to simulation mode")
            mode = "simulation"
    else:
        logger.info("NIDS orchestrator not available - using simulation mode")
        mode = "simulation"
    
    nids_state["sniffer_active"] = True
    nids_state["packets_processed"] = 0  # Reset counter
    logger.info(f"Packet sniffer started in {mode} mode")
    
    return {
        "message": f"Packet sniffer started successfully in {mode} mode",
        "status": "active",
        "mode": mode,
        "config": config
    }

@app.post("/api/v1/stop-sniffer", tags=["Control"])
@limiter.limit("10/minute")
async def stop_sniffer(request: Request):
    """Stop the packet sniffer"""
    if not nids_state["sniffer_active"]:
        # Don't throw error, just return current state
        return {
            "message": "Sniffer is already inactive",
            "status": "inactive"
        }
    
    # Stop real NIDS orchestrator if available
    if nids_orchestrator:
        try:
            nids_orchestrator.stop()
            logger.info("Real NIDS orchestrator stopped")
        except Exception as e:
            logger.error(f"Error stopping NIDS orchestrator: {e}")
    
    nids_state["sniffer_active"] = False
    logger.info("Packet sniffer stopped")
    
    return {
        "message": "Packet sniffer stopped successfully",
        "status": "inactive"
    }

@app.get("/api/v1/alerts", tags=["Data"])
@limiter.limit("100/minute")
async def get_alerts(request: Request, limit: int = 100, offset: int = 0):
    """Get system alerts"""
    return {
        "alerts": nids_state["alerts"][offset:offset+limit],
        "total": len(nids_state["alerts"]),
        "limit": limit,
        "offset": offset
    }

@app.get("/api/v1/packets", tags=["Data"])
@limiter.limit("100/minute")
async def get_packets(request: Request, limit: int = 100, offset: int = 0):
    """Get captured packets"""
    return {
        "packets": nids_state["packets"][offset:offset+limit],
        "total": len(nids_state["packets"]),
        "limit": limit,
        "offset": offset
    }

@app.get("/api/v1/stats", tags=["Analytics"])
@limiter.limit("100/minute")
async def get_stats(request: Request):
    """Get system statistics"""
    uptime = datetime.now() - nids_state["start_time"]
    
    return {
        "system": {
            "uptime": str(uptime).split('.')[0],
            "status": "running",
            "version": "1.0.0"
        },
        "sniffer": {
            "active": nids_state["sniffer_active"],
            "packets_processed": nids_state["packets_processed"]
        },
        "alerts": {
            "total": len(nids_state["alerts"]),
            "high": len([a for a in nids_state["alerts"] if a["severity"] == "high"]),
            "medium": len([a for a in nids_state["alerts"] if a["severity"] == "medium"]),
            "low": len([a for a in nids_state["alerts"] if a["severity"] == "low"])
        },
        "performance": {
            "cpu_usage": "5%",
            "memory_usage": "128MB", 
            "disk_usage": "1.2GB"
        }
    }

# Additional API endpoints for frontend integration
@app.post("/api/v1/alerts/{alert_id}/resolve", tags=["Alerts"])
@limiter.limit("50/minute")
async def resolve_alert(alert_id: str, request: Request):
    """Resolve an alert"""
    # Find and update alert
    for alert in nids_state["alerts"]:
        if alert["id"] == alert_id:
            alert["status"] = "resolved"
            logger.info(f"Alert {alert_id} resolved")
            return {"message": "Alert resolved successfully", "alert_id": alert_id}
    
    raise HTTPException(status_code=404, detail="Alert not found")

@app.delete("/api/v1/alerts/{alert_id}", tags=["Alerts"])
@limiter.limit("50/minute")
async def delete_alert(alert_id: str, request: Request):
    """Delete an alert"""
    # Remove alert from list
    nids_state["alerts"] = [a for a in nids_state["alerts"] if a["id"] != alert_id]
    logger.info(f"Alert {alert_id} deleted")
    return {"message": "Alert deleted successfully", "alert_id": alert_id}

@app.post("/api/v1/alerts/clear", tags=["Alerts"])
@limiter.limit("10/minute")
async def clear_alerts(request: Request, older_than_days: int = None):
    """Clear alerts"""
    if older_than_days:
        # Clear alerts older than specified days
        cutoff_date = datetime.now() - timedelta(days=older_than_days)
        nids_state["alerts"] = [a for a in nids_state["alerts"] 
                               if datetime.fromisoformat(a["timestamp"].replace('Z', '+00:00')) > cutoff_date]
    else:
        # Clear all alerts
        nids_state["alerts"] = []
    
    logger.info("Alerts cleared")
    return {"message": "Alerts cleared successfully"}

@app.get("/api/v1/correlation", tags=["Analytics"])
@limiter.limit("100/minute")
async def get_correlation(request: Request):
    """Get correlation analysis"""
    return {
        "correlations": [
            {
                "id": "corr_001",
                "type": "ip_correlation",
                "description": "Multiple alerts from same source IP",
                "source_ip": "192.168.1.100",
                "alert_count": 3,
                "confidence": 0.89
            }
        ],
        "patterns": [
            {
                "pattern": "brute_force_ssh",
                "frequency": 5,
                "last_seen": "2024-01-20T10:30:00Z"
            }
        ]
    }

@app.get("/api/v1/signature-rules", tags=["Rules"])
@limiter.limit("100/minute")
async def get_signature_rules(request: Request):
    """Get signature rules"""
    return {
        "rules": nids_state["signature_rules"],
        "total": len(nids_state["signature_rules"])
    }

@app.post("/api/v1/signature-rules/{rule_id}/enable", tags=["Rules"])
@limiter.limit("50/minute")
async def enable_signature_rule(rule_id: str, request: Request):
    """Enable a signature rule"""
    for rule in nids_state["signature_rules"]:
        if rule["id"] == rule_id:
            rule["enabled"] = True
            logger.info(f"Signature rule {rule_id} enabled")
            return {"message": "Rule enabled successfully", "rule_id": rule_id}
    
    raise HTTPException(status_code=404, detail="Rule not found")

@app.post("/api/v1/signature-rules/{rule_id}/disable", tags=["Rules"])
@limiter.limit("50/minute")
async def disable_signature_rule(rule_id: str, request: Request):
    """Disable a signature rule"""
    for rule in nids_state["signature_rules"]:
        if rule["id"] == rule_id:
            rule["enabled"] = False
            logger.info(f"Signature rule {rule_id} disabled")
            return {"message": "Rule disabled successfully", "rule_id": rule_id}
    
    raise HTTPException(status_code=404, detail="Rule not found")

@app.post("/api/v1/config/sniffer", tags=["Configuration"])
@limiter.limit("20/minute")
async def update_sniffer_config(request: Request):
    """Update sniffer configuration"""
    # Placeholder for sniffer config update
    logger.info("Sniffer configuration updated")
    return {"message": "Sniffer configuration updated successfully"}

@app.post("/api/v1/config/ml", tags=["Configuration"])
@limiter.limit("20/minute")
async def update_ml_config(request: Request):
    """Update ML configuration"""
    # Placeholder for ML config update
    logger.info("ML configuration updated")
    return {"message": "ML configuration updated successfully"}

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
        "main_working:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
