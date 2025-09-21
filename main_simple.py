import os
import logging
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# Create directories
os.makedirs('logs', exist_ok=True)
os.makedirs('app/ml_models', exist_ok=True)
os.makedirs('data', exist_ok=True)

# Create FastAPI app
app = FastAPI(
    title="NIDS Backend",
    description="Network Intrusion Detection System",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://localhost:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {
        "message": "NIDS Backend",
        "version": "1.0.0",
        "status": "running"
    }

@app.get("/api/v1/health")
async def health():
    return {"status": "healthy", "timestamp": "2024-01-01T00:00:00Z"}

@app.get("/api/v1/status")
async def get_status():
    return {
        "status": "running",
        "sniffer_active": False,
        "alerts_count": 0,
        "packets_processed": 0
    }

if __name__ == "__main__":
    logger.info("Starting NIDS backend...")
    uvicorn.run(
        "main_simple:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
