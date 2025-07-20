#!/usr/bin/env python3
"""
NIDS Application Runner

This script starts the AI-based Network Intrusion Detection System.
"""

import os
import sys
import logging
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from app.utils.config import Config
from app.main import app
import uvicorn

def setup_logging():
    """Setup logging configuration"""
    logging.basicConfig(
        level=getattr(logging, Config.LOG_LEVEL),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(Config.LOG_FILE),
            logging.StreamHandler()
        ]
    )

def validate_environment():
    """Validate environment and configuration"""
    logger = logging.getLogger(__name__)
    
    # Validate configuration
    if not Config.validate_config():
        logger.error("Configuration validation failed")
        return False
    
    # Create necessary directories
    Config.create_directories()
    
    # Check network interface
    if not Config.is_valid_interface(Config.INTERFACE):
        logger.warning(f"Network interface '{Config.INTERFACE}' may not be available")
        logger.info(f"Available interfaces: {Config.get_network_interfaces()}")
    
    logger.info("Environment validation completed")
    return True

def main():
    """Main application entry point"""
    print("🛡️  AI-Based Network Intrusion Detection System (NIDS)")
    print("=" * 60)
    
    # Setup logging
    setup_logging()
    logger = logging.getLogger(__name__)
    
    # Validate environment
    if not validate_environment():
        logger.error("Environment validation failed. Exiting.")
        sys.exit(1)
    
    # Display configuration
    config = Config.get_all_config()
    logger.info("Starting NIDS with configuration:")
    logger.info(f"  Network Interface: {config['network']['interface']}")
    logger.info(f"  API Host: {config['api']['host']}")
    logger.info(f"  API Port: {config['api']['port']}")
    logger.info(f"  ML Model: {config['ml_model']['model_path']}")
    logger.info(f"  Confidence Threshold: {config['ml_model']['confidence_threshold']}")
    
    try:
        # Start the application
        logger.info("Starting NIDS application...")
        uvicorn.run(
            "app.main:app",
            host=Config.API_HOST,
            port=Config.API_PORT,
            reload=Config.API_RELOAD,
            log_level=Config.LOG_LEVEL.lower()
        )
    except KeyboardInterrupt:
        logger.info("Application stopped by user")
    except Exception as e:
        logger.error(f"Application failed to start: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 