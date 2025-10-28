#!/usr/bin/env python3
"""
Secure Deployment Script for NIDS

This script implements security best practices for production deployment.
"""

import os
import sys
import secrets
import subprocess
from pathlib import Path
from datetime import datetime
import hashlib

def generate_secure_config():
    """Generate secure configuration values"""
    config = {
        'API_KEY': secrets.token_urlsafe(32),
        'JWT_SECRET': secrets.token_urlsafe(32),
        'ENCRYPTION_KEY': secrets.token_urlsafe(32),
        'MONGODB_PASSWORD': secrets.token_urlsafe(16),
    }
    
    print("🔐 Generated secure configuration values")
    return config

def create_secure_env_file(config):
    """Create secure .env file"""
    env_content = f"""# NIDS Secure Configuration
# Generated on: {datetime.now().isoformat()}

# Security Settings
API_KEY={config['API_KEY']}
JWT_SECRET={config['JWT_SECRET']}
ENCRYPTION_KEY={config['ENCRYPTION_KEY']}

# Database Configuration (with authentication)
MONGODB_URL=mongodb://nids_user:{config['MONGODB_PASSWORD']}@localhost:27017/nids?authSource=admin
MONGODB_DB_NAME=nids

# Network Interface Configuration
INTERFACE=Ethernet
PACKET_COUNT=1000
TIMEOUT=30

# API Configuration (secure)
API_HOST=127.0.0.1
API_PORT=8000
CORS_ORIGINS=https://localhost:3000

# Logging Configuration
LOG_LEVEL=INFO
LOG_FILE=logs/nids.log
ENABLE_AUDIT_LOG=true

# Security Features
ENABLE_RATE_LIMITING=true
ENABLE_API_AUTH=true
ENABLE_HTTPS=true
SSL_CERT_PATH=certs/nids.crt
SSL_KEY_PATH=certs/nids.key

# Performance & Security
MAX_ALERTS=10000
MAX_PACKETS_BUFFER=10000
RATE_LIMIT_PACKETS_PER_SECOND=1000
"""
    
    with open('.env', 'w') as f:
        f.write(env_content)
    
    # Set secure permissions (Windows compatible)
    try:
        os.chmod('.env', 0o600)
    except:
        print("⚠️  Note: Set .env file permissions manually on Windows")
    
    print("✅ Created secure .env file")

def setup_mongodb_security(mongodb_password):
    """Setup MongoDB with authentication"""
    mongo_setup = f"""
use admin
db.createUser({{
  user: "nids_user",
  pwd: "{mongodb_password}",
  roles: [
    {{ role: "readWrite", db: "nids" }},
    {{ role: "dbAdmin", db: "nids" }}
  ]
}})

use nids
db.createCollection("alerts")
db.createCollection("packets")
db.createCollection("signature_rules")
db.createCollection("system_status")

# Create indexes for performance and security
db.alerts.createIndex({{ "timestamp": -1 }})
db.alerts.createIndex({{ "severity": 1 }})
db.alerts.createIndex({{ "source_ip": 1 }})
db.packets.createIndex({{ "timestamp": -1 }})
db.system_status.createIndex({{ "component": 1 }})
"""
    
    with open('setup_mongodb.js', 'w') as f:
        f.write(mongo_setup)
    
    print("✅ Created MongoDB security setup script")

def create_ssl_certificates():
    """Generate self-signed SSL certificates"""
    
    # Create certs directory
    certs_dir = Path("certs")
    certs_dir.mkdir(exist_ok=True)
    
    ssl_script_content = f"""
# Generate SSL certificates for NIDS
openssl genrsa -out certs/nids.key 2048
openssl req -new -key certs/nids.key -out certs/nids.csr -subj "/C=US/ST=State/L=City/O=NIDS/CN=localhost"
openssl x509 -req -days 365 -in certs/nids.csr -signkey certs/nids.key -out certs/nids.crt
"""
    
    if os.name == 'nt':  # Windows
        with open('setup_ssl.bat', 'w') as f:
            f.write(ssl_script_content.replace('\n', '\r\n'))
        print("✅ Created SSL certificate setup script (setup_ssl.bat)")
    else:  # Unix/Linux
        with open('setup_ssl.sh', 'w') as f:
            f.write('#!/bin/bash\n' + ssl_script_content)
        os.chmod('setup_ssl.sh', 0o755)
        print("✅ Created SSL certificate setup script (setup_ssl.sh)")

def create_security_config():
    """Create security configuration file"""
    security_config = {
        "rate_limiting": {
            "enabled": True,
            "requests_per_minute": 100,
            "burst_limit": 200
        },
        "authentication": {
            "enabled": True,
            "token_expiry_hours": 24,
            "require_https": True
        },
        "logging": {
            "audit_enabled": True,
            "log_sensitive_data": False,
            "max_log_size_mb": 100
        },
        "validation": {
            "strict_input_validation": True,
            "sanitize_logs": True,
            "max_request_size_mb": 10
        }
    }
    
    import json
    with open('config/security.json', 'w') as f:
        json.dump(security_config, f, indent=2)
    
    print("✅ Created security configuration file")

def main():
    """Main secure deployment function"""
    print("🛡️  NIDS Security Hardening")
    print("=" * 50)
    
    # Create directories
    for directory in ['logs', 'certs', 'config']:
        Path(directory).mkdir(exist_ok=True)
    
    # Generate secure configuration
    config = generate_secure_config()
    
    # Create secure environment file
    create_secure_env_file(config)
    
    # Setup MongoDB security
    setup_mongodb_security(config['MONGODB_PASSWORD'])
    
    # Create SSL certificates
    create_ssl_certificates()
    
    # Create security config
    create_security_config()
    
    print("\n🎯 Security Hardening Complete!")
    print("\n📋 Next Steps:")
    print("1. Setup MongoDB: mongo < setup_mongodb.js")
    if os.name == 'nt':
        print("2. Generate SSL certs: setup_ssl.bat")
    else:
        print("2. Generate SSL certs: ./setup_ssl.sh")
    print("3. Install security dependencies: pip install -r requirements-security.txt")
    print("4. Restart NIDS with new configuration")
    
    print("\n⚠️  Security Notes:")
    print("- API_KEY and JWT_SECRET are auto-generated")
    print("- MongoDB requires authentication now")
    print("- HTTPS is enabled by default")
    print("- Rate limiting is active")
    print("- Audit logging is enabled")
    
    # Save credentials for reference
    with open('SECURITY_CREDENTIALS.txt', 'w') as f:
        f.write("NIDS Security Credentials\n")
        f.write("=" * 30 + "\n")
        f.write(f"API Key: {config['API_KEY']}\n")
        f.write(f"MongoDB Password: {config['MONGODB_PASSWORD']}\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n")
        f.write("\nIMPORTANT: Keep this file secure and delete after setup!\n")
    
    print(f"\n🔑 Credentials saved to: SECURITY_CREDENTIALS.txt")

if __name__ == "__main__":
    main()
