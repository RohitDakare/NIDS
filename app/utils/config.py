import os
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict
from pydantic_settings import BaseSettings


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
    
    # Advanced Security Settings
    JWT_SECRET: Optional[str] = Field(default=None, description="JWT secret key")
    ENCRYPTION_KEY: Optional[str] = Field(default=None, description="Data encryption key")
    ENABLE_AUDIT_LOG: bool = Field(default=False, description="Enable audit logging")
    ENABLE_RATE_LIMITING: bool = Field(default=False, description="Enable rate limiting")
    ENABLE_API_AUTH: bool = Field(default=False, description="Enable API authentication")
    ENABLE_HTTPS: bool = Field(default=False, description="Enable HTTPS")
    SSL_CERT_PATH: Optional[str] = Field(default=None, description="SSL certificate path")
    SSL_KEY_PATH: Optional[str] = Field(default=None, description="SSL key path")
    
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
        case_sensitive = True
        extra = "allow"  # Allow extra environment variables


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
        
        # Get the absolute path to the model file
        model_path = os.path.join(os.path.dirname(__file__), "..", settings.MODEL_PATH)
        model_path = os.path.abspath(model_path)
        
        # Validate ML model path
        if not os.path.exists(model_path):
            print(f"Warning: ML model not found at {model_path}")
            print(f"Expected path: {settings.MODEL_PATH}")
            print(f"Absolute path: {model_path}")
            print("Available models in ml_models directory:")
            ml_dir = os.path.join(os.path.dirname(__file__), "..", "ml_models")
            if os.path.exists(ml_dir):
                models = os.listdir(ml_dir)
                for model in models:
                    print(f"  - {model}")
            return False
            
        # Validate confidence threshold
        if not 0.0 <= settings.CONFIDENCE_THRESHOLD <= 1.0:
            print(f"Error: Confidence threshold must be between 0.0 and 1.0, got {settings.CONFIDENCE_THRESHOLD}")
            return False
            
        return True
        
    except Exception as e:
        print(f"Error validating settings: {e}")
        return False


# Legacy Config class for backward compatibility
class Config:
    """Legacy Config class for backward compatibility with run.py"""
    
    # Class attributes that map to settings
    LOG_LEVEL = settings.LOG_LEVEL
    LOG_FILE = settings.LOG_FILE
    API_HOST = settings.API_HOST
    API_PORT = settings.API_PORT
    API_RELOAD = settings.API_RELOAD
    INTERFACE = settings.INTERFACE
    
    @classmethod
    def validate_config(cls):
        """Validate configuration"""
        return validate_settings()
    
    @classmethod
    def create_directories(cls):
        """Create necessary directories"""
        try:
            os.makedirs(os.path.dirname(cls.LOG_FILE), exist_ok=True)
            os.makedirs("data", exist_ok=True)
            os.makedirs("models", exist_ok=True)
            return True
        except Exception as e:
            print(f"Error creating directories: {e}")
            return False
    
    @classmethod
    def is_valid_interface(cls, interface):
        """Check if network interface is valid"""
        try:
            import netifaces
            interfaces = netifaces.interfaces()
            return interface in interfaces
        except:
            # If netifaces not available, assume valid
            return True
    
    @classmethod
    def get_network_interfaces(cls):
        """Get available network interfaces"""
        try:
            import netifaces
            return netifaces.interfaces()
        except:
            return ["eth0", "wlan0", "lo"]
    
    @classmethod
    def get_all_config(cls):
        """Get all configuration as dict"""
        return {
            "network": {
                "interface": cls.INTERFACE,
            },
            "api": {
                "host": cls.API_HOST,
                "port": cls.API_PORT,
            },
            "ml_model": {
                "model_path": settings.MODEL_PATH,
                "confidence_threshold": settings.CONFIDENCE_THRESHOLD,
            }
        }


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