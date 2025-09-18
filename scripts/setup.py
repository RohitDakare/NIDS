#!/usr/bin/env python3
"""
NIDS Setup Script

This script helps set up the AI-based Network Intrusion Detection System.
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def print_header(title):
    """Print a formatted header"""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

def print_section(title):
    """Print a formatted section"""
    print(f"\n{'-'*40}")
    print(f"  {title}")
    print(f"{'-'*40}")

def run_command(command, description):
    """Run a command and handle errors"""
    print(f"🔄 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed: {e}")
        print(f"Error output: {e.stderr}")
        return False

def check_python_version():
    """Check if Python version is compatible"""
    print_section("Checking Python Version")
    
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print(f"❌ Python {version.major}.{version.minor} is not supported")
        print("Please use Python 3.8 or higher")
        return False
    
    print(f"✅ Python {version.major}.{version.minor}.{version.micro} is compatible")
    return True

def create_virtual_environment():
    """Create a virtual environment"""
    print_section("Creating Virtual Environment")
    
    venv_path = Path("venv")
    if venv_path.exists():
        print("✅ Virtual environment already exists")
        return True
    
    if not run_command("python -m venv venv", "Creating virtual environment"):
        return False
    
    return True

def install_dependencies():
    """Install required dependencies"""
    print_section("Installing Dependencies")
    
    # Determine the pip command based on OS
    if os.name == 'nt':  # Windows
        pip_cmd = "venv\\Scripts\\pip"
        requirements_file = "requirements-windows.txt"
    else:  # Unix/Linux/Mac
        pip_cmd = "venv/bin/pip"
        requirements_file = "requirements.txt"
    
    # Upgrade pip first
    if os.name == 'nt':  # Windows
        python_cmd = "venv\\Scripts\\python"
    else:  # Unix/Linux/Mac
        python_cmd = "venv/bin/python"
    
    if not run_command(f"{python_cmd} -m pip install --upgrade pip", "Upgrading pip"):
        return False
    
    # Install numpy and scipy first (required for scikit-learn)
    print("🔄 Installing core scientific libraries...")
    if os.name == 'nt':  # Windows
        # Use pre-compiled wheels for Windows
        if not run_command(f"{pip_cmd} install numpy pandas scipy", "Installing core scientific libraries"):
            print("⚠️  Trying alternative installation method...")
            if not run_command(f"{pip_cmd} install --only-binary=all numpy pandas scipy", "Installing core libraries (binary only)"):
                return False
    else:
        if not run_command(f"{pip_cmd} install numpy pandas scipy", "Installing core scientific libraries"):
            return False
    
    # Install scikit-learn
    print("🔄 Installing scikit-learn...")
    if os.name == 'nt':  # Windows
        if not run_command(f"{pip_cmd} install scikit-learn", "Installing scikit-learn"):
            print("⚠️  Trying alternative scikit-learn installation...")
            if not run_command(f"{pip_cmd} install --only-binary=all scikit-learn", "Installing scikit-learn (binary only)"):
                print("❌ Failed to install scikit-learn. Please install Microsoft Visual C++ Build Tools")
                print("   Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/")
                return False
    else:
        if not run_command(f"{pip_cmd} install scikit-learn", "Installing scikit-learn"):
            return False
    
    # Install remaining requirements
    if not run_command(f"{pip_cmd} install -r {requirements_file}", "Installing remaining requirements"):
        return False
    
    return True

def create_directories():
    """Create necessary directories"""
    print_section("Creating Directories")
    
    directories = [
        "app/ml_models",
        "data",
        "logs",
        "tests"
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"✅ Created directory: {directory}")

def create_config_file():
    """Create configuration file"""
    print_section("Creating Configuration File")
    
    config_content = """# Network Interface Configuration
INTERFACE=eth0
PACKET_COUNT=1000
TIMEOUT=30

# ML Model Settings
MODEL_PATH=app/ml_models/nids_model.joblib
CONFIDENCE_THRESHOLD=0.8

# Database Configuration
DATABASE_URL=sqlite:///./data/nids.db

# Logging Configuration
LOG_LEVEL=INFO
LOG_FILE=logs/nids.log

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_RELOAD=true

# Security Configuration
CORS_ORIGINS=*
API_KEY=your_api_key_here

# Performance Configuration
MAX_ALERTS=10000
MAX_PACKETS_BUFFER=10000
MAX_CONNECTIONS=10000

# Detection Configuration
RATE_LIMIT_PACKETS_PER_SECOND=100
RATE_LIMIT_BYTES_PER_SECOND=1000000
CORRELATION_WINDOW_MINUTES=5
"""
    
    config_file = Path(".env")
    if config_file.exists():
        print("✅ Configuration file already exists")
    else:
        with open(config_file, 'w') as f:
            f.write(config_content)
        print("✅ Created configuration file: .env")

def check_network_interfaces():
    """Check available network interfaces"""
    print_section("Checking Network Interfaces")
    
    try:
        import psutil
        interfaces = []
        for interface, addresses in psutil.net_if_addrs().items():
            if addresses:
                interfaces.append(interface)
        
        print(f"✅ Available network interfaces: {', '.join(interfaces)}")
        
        # Check if default interface exists
        default_interface = "Ethernet"  # Default for Windows
        if default_interface in interfaces:
            print(f"✅ Default interface '{default_interface}' is available")
        else:
            print(f"⚠️  Default interface '{default_interface}' not found")
            print(f"   Please update the INTERFACE setting in .env file")
            print(f"   Available interfaces: {', '.join(interfaces)}")
        
        return True
    except ImportError:
        print("⚠️  psutil not available, cannot check network interfaces")
        return True

def run_tests():
    """Run basic tests"""
    print_section("Running Tests")
    
    # Determine the python command based on OS
    if os.name == 'nt':  # Windows
        python_cmd = "venv\\Scripts\\python"
    else:  # Unix/Linux/Mac
        python_cmd = "venv/bin/python"
    
    if not run_command(f"{python_cmd} -m pytest tests/ -v", "Running tests"):
        print("⚠️  Tests failed, but setup can continue")
        return False
    
    return True

def create_startup_scripts():
    """Create startup scripts"""
    print_section("Creating Startup Scripts")
    
    # Create Windows batch file
    if os.name == 'nt':
        batch_content = """@echo off
echo Starting NIDS Application...
call venv\\Scripts\\activate
python run.py
pause
"""
        with open("start_nids.bat", 'w') as f:
            f.write(batch_content)
        print("✅ Created Windows startup script: start_nids.bat")
    
    # Create Unix shell script
    shell_content = """#!/bin/bash
echo "Starting NIDS Application..."
source venv/bin/activate
python run.py
"""
    with open("start_nids.sh", 'w') as f:
        f.write(shell_content)
    
    # Make shell script executable
    if os.name != 'nt':
        os.chmod("start_nids.sh", 0o755)
    
    print("✅ Created Unix startup script: start_nids.sh")

def print_next_steps():
    """Print next steps for the user"""
    print_header("SETUP COMPLETED")
    print("✅ NIDS system has been set up successfully!")
    
    print("\n📋 Next Steps:")
    print("1. Activate the virtual environment:")
    if os.name == 'nt':  # Windows
        print("   venv\\Scripts\\activate")
    else:  # Unix/Linux/Mac
        print("   source venv/bin/activate")
    
    print("\n2. Start the NIDS application:")
    print("   python run.py")
    print("   or")
    if os.name == 'nt':
        print("   start_nids.bat")
    else:
        print("   ./start_nids.sh")
    
    print("\n3. Access the API documentation:")
    print("   http://localhost:8000/docs")
    
    print("\n4. Run the demo:")
    print("   python demo.py")
    
    print("\n5. Configure the system:")
    print("   - Edit .env file for configuration")
    print("   - Add your own ML models to app/ml_models/ directory")
    print("   - Customize signature rules")
    
    print("\n🔧 Configuration Options:")
    print("   - Network interface: INTERFACE in .env")
    print("   - ML model path: MODEL_PATH in .env")
    print("   - API port: API_PORT in .env")
    print("   - Log level: LOG_LEVEL in .env")

def main():
    """Main setup function"""
    print_header("NIDS Setup - AI-Based Network Intrusion Detection System")
    print("This script will set up the NIDS system on your machine")
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Create virtual environment
    if not create_virtual_environment():
        print("❌ Failed to create virtual environment")
        sys.exit(1)
    
    # Install dependencies
    if not install_dependencies():
        print("❌ Failed to install dependencies")
        sys.exit(1)
    
    # Create directories
    create_directories()
    
    # Create configuration file
    create_config_file()
    
    # Check network interfaces
    check_network_interfaces()
    
    # Run tests (optional)
    run_tests()
    
    # Create startup scripts
    create_startup_scripts()
    
    # Print next steps
    print_next_steps()

if __name__ == "__main__":
    main() 