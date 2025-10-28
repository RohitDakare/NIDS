import os
import logging
from dotenv import load_dotenv
from fastapi import FastAPI
import uvicorn

# Load environment variables
load_dotenv()

# Configure basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create directories
os.makedirs('logs', exist_ok=True)

# Create simple FastAPI app
app = FastAPI(
    title="NIDS Test",
    description="Simple test version of NIDS backend",
    version="1.0.0"
)

@app.get("/")
async def root():
    return {
        "message": "NIDS Backend Test",
        "status": "running"
    }

@app.get("/health")
async def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    logger.info("Starting NIDS test backend...")
    uvicorn.run(
        "test_main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
