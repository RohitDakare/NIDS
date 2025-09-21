"""
Security utilities for NIDS application
"""

import os
import jwt
import hashlib
import secrets
import ipaddress
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from passlib.context import CryptContext
from fastapi import HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import logging
import re

# Configure password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Configure JWT
JWT_SECRET = os.getenv("JWT_SECRET", "fallback-secret-key")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# Security logger
security_logger = logging.getLogger("nids.security")

class SecurityManager:
    """Centralized security management"""
    
    def __init__(self):
        self.api_key = os.getenv("API_KEY")
        self.jwt_secret = os.getenv("JWT_SECRET", JWT_SECRET)
        self.failed_attempts = {}  # IP -> count
        self.blocked_ips = set()
        
    def verify_api_key(self, provided_key: str) -> bool:
        """Verify API key"""
        if not self.api_key:
            security_logger.warning("No API key configured")
            return False
        
        # Use constant-time comparison to prevent timing attacks
        return secrets.compare_digest(self.api_key, provided_key)
    
    def create_access_token(self, data: Dict[str, Any]) -> str:
        """Create JWT access token"""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
        to_encode.update({"exp": expire})
        
        return jwt.encode(to_encode, self.jwt_secret, algorithm=JWT_ALGORITHM)
    
    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[JWT_ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )
        except jwt.JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
    
    def log_security_event(self, event_type: str, details: Dict[str, Any], 
                          client_ip: str = None):
        """Log security events for audit"""
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "client_ip": client_ip,
            "details": self.sanitize_log_data(details)
        }
        
        security_logger.info(f"Security Event: {event_type}", extra=log_data)
    
    def sanitize_log_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive information from log data"""
        sensitive_keys = ['password', 'api_key', 'token', 'secret', 'key']
        sanitized = {}
        
        for key, value in data.items():
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                sanitized[key] = "***REDACTED***"
            elif isinstance(value, str) and len(value) > 100:
                sanitized[key] = value[:50] + "...TRUNCATED"
            else:
                sanitized[key] = value
        
        return sanitized
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is blocked due to failed attempts"""
        return ip in self.blocked_ips
    
    def record_failed_attempt(self, ip: str):
        """Record failed authentication attempt"""
        self.failed_attempts[ip] = self.failed_attempts.get(ip, 0) + 1
        
        if self.failed_attempts[ip] >= 5:  # Block after 5 failed attempts
            self.blocked_ips.add(ip)
            security_logger.warning(f"IP {ip} blocked due to repeated failures")
    
    def reset_failed_attempts(self, ip: str):
        """Reset failed attempts for successful auth"""
        if ip in self.failed_attempts:
            del self.failed_attempts[ip]

class InputValidator:
    """Input validation and sanitization"""
    
    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_interface_name(interface: str) -> bool:
        """Validate network interface name"""
        # Allow alphanumeric, hyphens, spaces, underscores
        pattern = r'^[a-zA-Z0-9\s\-_\.]+$'
        return bool(re.match(pattern, interface)) and len(interface) <= 50
    
    @staticmethod
    def sanitize_string(input_str: str, max_length: int = 255) -> str:
        """Sanitize string input"""
        if not isinstance(input_str, str):
            raise ValueError("Input must be a string")
        
        # Remove null bytes and control characters
        sanitized = ''.join(char for char in input_str if ord(char) >= 32 or char in '\t\n\r')
        
        # Truncate to max length
        return sanitized[:max_length]
    
    @staticmethod
    def validate_port(port: int) -> bool:
        """Validate port number"""
        return isinstance(port, int) and 1 <= port <= 65535
    
    @staticmethod
    def validate_severity(severity: str) -> bool:
        """Validate alert severity"""
        valid_severities = ['low', 'medium', 'high', 'critical']
        return severity.lower() in valid_severities

class ModelSecurityManager:
    """Security for ML models"""
    
    def __init__(self):
        self.model_checksums = {}
        self.load_model_checksums()
    
    def load_model_checksums(self):
        """Load known good model checksums"""
        checksum_file = "config/model_checksums.json"
        if os.path.exists(checksum_file):
            import json
            with open(checksum_file, 'r') as f:
                self.model_checksums = json.load(f)
    
    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def verify_model_integrity(self, model_path: str) -> bool:
        """Verify model file hasn't been tampered with"""
        if not os.path.exists(model_path):
            return False
        
        file_hash = self.calculate_file_hash(model_path)
        model_name = os.path.basename(model_path)
        
        expected_hash = self.model_checksums.get(model_name)
        if not expected_hash:
            security_logger.warning(f"No checksum found for model: {model_name}")
            return False
        
        is_valid = file_hash == expected_hash
        if not is_valid:
            security_logger.error(f"Model integrity check failed: {model_name}")
        
        return is_valid
    
    def register_model(self, model_path: str):
        """Register a new model with its checksum"""
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found: {model_path}")
        
        file_hash = self.calculate_file_hash(model_path)
        model_name = os.path.basename(model_path)
        
        self.model_checksums[model_name] = file_hash
        
        # Save updated checksums
        checksum_file = "config/model_checksums.json"
        os.makedirs(os.path.dirname(checksum_file), exist_ok=True)
        
        import json
        with open(checksum_file, 'w') as f:
            json.dump(self.model_checksums, f, indent=2)
        
        security_logger.info(f"Registered model: {model_name}")

# Global security manager instance
security_manager = SecurityManager()
input_validator = InputValidator()
model_security = ModelSecurityManager()

# Security decorators and dependencies
security = HTTPBearer()

async def verify_api_key(credentials: HTTPAuthorizationCredentials = None):
    """FastAPI dependency for API key verification"""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials"
        )
    
    if not security_manager.verify_api_key(credentials.credentials):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    
    return credentials.credentials

def get_client_ip(request) -> str:
    """Extract client IP from request"""
    # Check for forwarded headers first
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    return request.client.host if request.client else "unknown"

class SecurityMiddleware:
    """Security middleware for additional protection"""
    
    def __init__(self, app):
        self.app = app
    
    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            # Add security headers
            async def send_wrapper(message):
                if message["type"] == "http.response.start":
                    headers = dict(message.get("headers", []))
                    
                    # Add security headers
                    security_headers = {
                        b"X-Content-Type-Options": b"nosniff",
                        b"X-Frame-Options": b"DENY",
                        b"X-XSS-Protection": b"1; mode=block",
                        b"Strict-Transport-Security": b"max-age=31536000; includeSubDomains",
                        b"Content-Security-Policy": b"default-src 'self'",
                    }
                    
                    for header, value in security_headers.items():
                        headers[header] = value
                    
                    message["headers"] = list(headers.items())
                
                await send(message)
            
            await self.app(scope, receive, send_wrapper)
        else:
            await self.app(scope, receive, send)
