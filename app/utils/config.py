import os
from typing import Dict, Any, Optional
from dotenv import load_dotenv
import logging

logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

class Config:
    """Configuration management for NIDS system"""
    
    # Network Configuration
    INTERFACE = os.getenv("INTERFACE", "Loopback Pseudo-Interface 1")  # Default to loopback for testing
    PACKET_COUNT = int(os.getenv("PACKET_COUNT", "1000"))
    TIMEOUT = int(os.getenv("TIMEOUT", "30"))
    
    # ML Model Configuration
    MODEL_PATH = os.getenv("MODEL_PATH", "models/nids_model.joblib")
    CONFIDENCE_THRESHOLD = float(os.getenv("CONFIDENCE_THRESHOLD", "0.8"))
    
    # Database Configuration
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/nids.db")
    
    # Logging Configuration
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE = os.getenv("LOG_FILE", "logs/nids.log")
    
    # API Configuration
    API_HOST = os.getenv("API_HOST", "0.0.0.0")
    API_PORT = int(os.getenv("API_PORT", "8000"))
    API_RELOAD = os.getenv("API_RELOAD", "true").lower() == "true"
    
    # Security Configuration
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")
    API_KEY = os.getenv("API_KEY", None)
    
    # Performance Configuration
    MAX_ALERTS = int(os.getenv("MAX_ALERTS", "10000"))
    MAX_PACKETS_BUFFER = int(os.getenv("MAX_PACKETS_BUFFER", "10000"))
    MAX_CONNECTIONS = int(os.getenv("MAX_CONNECTIONS", "10000"))
    
    # Detection Configuration
    RATE_LIMIT_PACKETS_PER_SECOND = int(os.getenv("RATE_LIMIT_PACKETS_PER_SECOND", "100"))
    RATE_LIMIT_BYTES_PER_SECOND = int(os.getenv("RATE_LIMIT_BYTES_PER_SECOND", "1000000"))
    CORRELATION_WINDOW_MINUTES = int(os.getenv("CORRELATION_WINDOW_MINUTES", "5"))
    
    @classmethod
    def get_all_config(cls) -> Dict[str, Any]:
        """Get all configuration as dictionary"""
        return {
            "network": {
                "interface": cls.INTERFACE,
                "packet_count": cls.PACKET_COUNT,
                "timeout": cls.TIMEOUT
            },
            "ml_model": {
                "model_path": cls.MODEL_PATH,
                "confidence_threshold": cls.CONFIDENCE_THRESHOLD
            },
            "database": {
                "database_url": cls.DATABASE_URL
            },
            "logging": {
                "log_level": cls.LOG_LEVEL,
                "log_file": cls.LOG_FILE
            },
            "api": {
                "host": cls.API_HOST,
                "port": cls.API_PORT,
                "reload": cls.API_RELOAD
            },
            "security": {
                "cors_origins": cls.CORS_ORIGINS,
                "api_key_configured": cls.API_KEY is not None
            },
            "performance": {
                "max_alerts": cls.MAX_ALERTS,
                "max_packets_buffer": cls.MAX_PACKETS_BUFFER,
                "max_connections": cls.MAX_CONNECTIONS
            },
            "detection": {
                "rate_limit_packets_per_second": cls.RATE_LIMIT_PACKETS_PER_SECOND,
                "rate_limit_bytes_per_second": cls.RATE_LIMIT_BYTES_PER_SECOND,
                "correlation_window_minutes": cls.CORRELATION_WINDOW_MINUTES
            }
        }
    
    @classmethod
    def validate_config(cls) -> bool:
        """Validate configuration settings"""
        try:
            # Validate network interface
            if not cls.INTERFACE:
                logger.error("INTERFACE configuration is required")
                return False
            
            # Validate packet count
            if cls.PACKET_COUNT <= 0:
                logger.error("PACKET_COUNT must be greater than 0")
                return False
            
            # Validate timeout
            if cls.TIMEOUT <= 0:
                logger.error("TIMEOUT must be greater than 0")
                return False
            
            # Validate confidence threshold
            if not 0.0 <= cls.CONFIDENCE_THRESHOLD <= 1.0:
                logger.error("CONFIDENCE_THRESHOLD must be between 0.0 and 1.0")
                return False
            
            # Validate API port
            if not 1 <= cls.API_PORT <= 65535:
                logger.error("API_PORT must be between 1 and 65535")
                return False
            
            # Validate performance settings
            if cls.MAX_ALERTS <= 0:
                logger.error("MAX_ALERTS must be greater than 0")
                return False
            
            if cls.MAX_PACKETS_BUFFER <= 0:
                logger.error("MAX_PACKETS_BUFFER must be greater than 0")
                return False
            
            logger.info("Configuration validation passed")
            return True
            
        except Exception as e:
            logger.error(f"Configuration validation failed: {e}")
            return False
    
    @classmethod
    def create_directories(cls):
        """Create necessary directories"""
        directories = [
            "models",
            "data", 
            "logs",
            os.path.dirname(cls.LOG_FILE)
        ]
        
        for directory in directories:
            if directory:
                os.makedirs(directory, exist_ok=True)
                logger.debug(f"Created directory: {directory}")
    
    @classmethod
    def get_network_interfaces(cls) -> list:
        """Get available network interfaces"""
        try:
            import psutil
            interfaces = []
            for interface, addresses in psutil.net_if_addrs().items():
                if addresses:  # Only include interfaces with addresses
                    interfaces.append(interface)
            return interfaces
        except ImportError:
            logger.warning("psutil not available, cannot get network interfaces")
            return ["eth0", "lo"]  # Default fallback
    
    @classmethod
    def is_valid_interface(cls, interface: str) -> bool:
        """Check if network interface is valid"""
        available_interfaces = cls.get_network_interfaces()
        return interface in available_interfaces 