import os
from typing import Optional
from pydantic import BaseSettings, Field


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
    # Network Configuration
    INTERFACE: str = Field(default="eth0", description="Network interface to monitor")
    PACKET_COUNT: int = Field(default=1000, description="Number of packets to capture")
    TIMEOUT: int = Field(default=30, description="Capture timeout in seconds")
    
    # ML Model Settings
    MODEL_PATH: str = Field(default="app/ml_models/nids_model.joblib", description="Path to ML model")
    CONFIDENCE_THRESHOLD: float = Field(default=0.8, description="ML confidence threshold")
    
    # MongoDB Database Configuration
    MONGODB_URL: str = Field(default="mongodb://localhost:27017", description="MongoDB connection URL")
    MONGODB_DB_NAME: str = Field(default="nids", description="MongoDB database name")
    
    # API Configuration
    API_HOST: str = Field(default="0.0.0.0", description="API host")
    API_PORT: int = Field(default=8000, description="API port")
    API_RELOAD: bool = Field(default=True, description="Enable API auto-reload")
    
    # Security Configuration
    CORS_ORIGINS: str = Field(default="*", description="CORS allowed origins")
    API_KEY: Optional[str] = Field(default=None, description="API key for authentication")
    
    # Logging Configuration
    LOG_LEVEL: str = Field(default="INFO", description="Logging level")
    LOG_FILE: str = Field(default="logs/nids.log", description="Log file path")
    
    # Performance Configuration
    MAX_ALERTS: int = Field(default=10000, description="Maximum alerts to store")
    MAX_PACKETS_BUFFER: int = Field(default=10000, description="Maximum packets in buffer")
    MAX_CONNECTIONS: int = Field(default=10000, description="Maximum database connections")
    
    # Detection Configuration
    RATE_LIMIT_PACKETS_PER_SECOND: int = Field(default=100, description="Packet rate limit")
    RATE_LIMIT_BYTES_PER_SECOND: int = Field(default=1000000, description="Byte rate limit")
    CORRELATION_WINDOW_MINUTES: int = Field(default=5, description="Alert correlation window")
    
    class Config:
        env_file = ".env"
        case_sensitive = True


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get application settings"""
    return settings


def validate_settings() -> bool:
    """Validate critical settings"""
    try:
        # Check if required directories exist
        os.makedirs(os.path.dirname(settings.LOG_FILE), exist_ok=True)
        os.makedirs(os.path.dirname(settings.MODEL_PATH), exist_ok=True)
        
        # Validate ML model path
        if not os.path.exists(settings.MODEL_PATH):
            print(f"Warning: ML model not found at {settings.MODEL_PATH}")
            return False
            
        # Validate confidence threshold
        if not 0.0 <= settings.CONFIDENCE_THRESHOLD <= 1.0:
            print(f"Error: Confidence threshold must be between 0.0 and 1.0, got {settings.CONFIDENCE_THRESHOLD}")
            return False
            
        return True
        
    except Exception as e:
        print(f"Error validating settings: {e}")
        return False


if __name__ == "__main__":
    # Test settings loading
    print("NIDS Configuration:")
    print(f"Interface: {settings.INTERFACE}")
    print(f"MongoDB URL: {settings.MONGODB_URL}")
    print(f"Model Path: {settings.MODEL_PATH}")
    print(f"API Port: {settings.API_PORT}")
    
    if validate_settings():
        print("✅ Configuration is valid")
    else:
        print("❌ Configuration has issues")