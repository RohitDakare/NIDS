#!/usr/bin/env python3
"""
Setup and Test Script for NIDS

This script helps set up the NIDS environment and run basic tests
to ensure everything is working correctly.
"""

import os
import sys
import subprocess
import logging
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Change to project root directory
os.chdir(project_root)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def check_python_version():
    """Check if Python version is compatible"""
    logger.info("Checking Python version...")
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        logger.error("Python 3.8+ is required")
        return False
    logger.info(f"✅ Python {version.major}.{version.minor}.{version.micro} is compatible")
    return True


def install_dependencies():
    """Install required dependencies"""
    logger.info("Installing dependencies...")
    try:
        # Use current Python executable to ensure we're using the right environment
        result = subprocess.run([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt", "--upgrade"
        ], check=True, capture_output=True, text=True, cwd=project_root)
        logger.info("✅ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"❌ Failed to install dependencies: {e}")
        if e.stderr:
            logger.error(f"Error output: {e.stderr}")
        return False
    except Exception as e:
        logger.error(f"❌ Unexpected error installing dependencies: {e}")
        return False


def create_directories():
    """Create necessary directories"""
    logger.info("Creating directories...")
    directories = [
        "logs",
        "data",
        "app/ml_models",
        "data/cic-ids2017"
    ]
    
    for directory in directories:
        dir_path = project_root / directory
        dir_path.mkdir(parents=True, exist_ok=True)
        logger.info(f"✅ Created directory: {directory}")
    
    return True


def setup_environment():
    """Set up environment configuration"""
    logger.info("Setting up environment...")
    
    env_file = project_root / ".env"
    env_example = project_root / "config" / "env.example"
    
    if not env_file.exists() and env_example.exists():
        # Copy example to .env
        with open(env_example, 'r') as src, open(env_file, 'w') as dst:
            dst.write(src.read())
        logger.info("✅ Created .env file from example")
    elif env_file.exists():
        logger.info("✅ .env file already exists")
    else:
        logger.warning("⚠️ No environment configuration found")
    
    return True


def train_initial_model():
    """Train an initial ML model"""
    logger.info("Training initial ML model...")
    try:
        # Import and run model training
        from scripts.train_ml_model import main as train_main
        success = train_main()
        if success:
            logger.info("✅ ML model trained successfully")
        else:
            logger.warning("⚠️ ML model training had issues")
        return success
    except ImportError as e:
        logger.error(f"❌ Failed to import training module: {e}")
        return False
    except Exception as e:
        logger.error(f"❌ Failed to train ML model: {e}")
        return False


def test_api_import():
    """Test if core modules can be imported"""
    logger.info("Testing core module imports...")
    try:
        # Test basic imports first
        import pandas as pd
        import numpy as np
        import sklearn
        logger.info("✅ Basic ML libraries imported successfully")
        
        # Test NIDS modules
        from app.models.schemas import PacketInfo, Alert
        logger.info("✅ NIDS schemas imported successfully")
        
        from app.utils.config import settings
        logger.info("✅ Configuration imported successfully")
        
        # Test if we can create basic objects
        from datetime import datetime
        packet = PacketInfo(
            timestamp=datetime.now(),
            source_ip="192.168.1.1",
            dest_ip="192.168.1.2",
            protocol="TCP",
            packet_length=64
        )
        logger.info("✅ Can create PacketInfo objects")
        
        logger.info("✅ All core modules imported successfully")
        return True
    except ImportError as e:
        logger.error(f"❌ Failed to import modules: {e}")
        return False
    except Exception as e:
        logger.error(f"❌ Error testing imports: {e}")
        return False


def test_database_connection():
    """Test MongoDB connection"""
    logger.info("Testing database connection...")
    try:
        from app.db.mongodb import mongodb
        # Try to get database instance
        db = mongodb.db
        logger.info("✅ Database connection successful")
        return True
    except Exception as e:
        logger.warning(f"⚠️ Database connection failed: {e}")
        logger.info("This is normal if MongoDB is not running")
        return False


def run_basic_tests():
    """Run basic functionality tests"""
    logger.info("Running basic tests...")
    try:
        # Check if pytest is available
        result = subprocess.run([
            sys.executable, "-m", "pytest", "--version"
        ], capture_output=True, text=True, cwd=project_root)
        
        if result.returncode != 0:
            logger.warning("⚠️ pytest not available, skipping tests")
            return False
        
        # Run pytest on unit tests if they exist
        test_dir = project_root / "tests" / "unit"
        if test_dir.exists():
            result = subprocess.run([
                sys.executable, "-m", "pytest", str(test_dir), "-v", "--tb=short"
            ], capture_output=True, text=True, cwd=project_root)
            
            if result.returncode == 0:
                logger.info("✅ Basic tests passed")
                return True
            else:
                logger.warning("⚠️ Some tests failed")
                logger.info(f"Test output:\n{result.stdout}")
                return False
        else:
            logger.info("✅ No unit tests found, skipping")
            return True
    except Exception as e:
        logger.error(f"❌ Failed to run tests: {e}")
        return False


def main():
    """Main setup and test function"""
    logger.info("🚀 Starting NIDS setup and testing...")
    logger.info(f"Working directory: {os.getcwd()}")
    logger.info(f"Python executable: {sys.executable}")
    
    success_count = 0
    total_checks = 7
    
    # Run all checks
    checks = [
        ("Python Version", check_python_version),
        ("Dependencies", install_dependencies),
        ("Directories", create_directories),
        ("Environment", setup_environment),
        ("Module Imports", test_api_import),
        ("ML Model", train_initial_model),
        ("Database", test_database_connection),
    ]
    
    for name, check_func in checks:
        logger.info(f"\n--- {name} Check ---")
        try:
            if check_func():
                success_count += 1
        except Exception as e:
            logger.error(f"❌ {name} check failed with error: {e}")
    
    # Summary
    logger.info(f"\n{'='*50}")
    logger.info(f"SETUP SUMMARY: {success_count}/{total_checks} checks passed")
    
    if success_count >= 5:  # Allow some checks to fail
        logger.info("🎉 NIDS setup completed successfully!")
        logger.info("\nNext steps:")
        logger.info("1. Start MongoDB service (if not running)")
        logger.info("2. Run: python -m app.main")
        logger.info("3. Open frontend: cd nids-dashboard && npm run dev")
        logger.info("4. Access dashboard at http://localhost:3000")
        return True
    else:
        logger.error("❌ Setup incomplete. Please fix the issues above.")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
