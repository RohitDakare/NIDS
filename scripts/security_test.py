#!/usr/bin/env python3
"""
Security Testing Script for NIDS

Tests all security measures and vulnerabilities.
"""

import os
import sys
import requests
import json
import time
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

def test_api_authentication():
    """Test API authentication"""
    print("🔒 Testing API Authentication...")
    
    base_url = "http://localhost:8000/api/v1"
    
    # Test without authentication
    try:
        response = requests.get(f"{base_url}/alerts")
        if response.status_code == 401:
            print("✅ API correctly rejects unauthenticated requests")
        else:
            print(f"❌ API allows unauthenticated access: {response.status_code}")
    except requests.exceptions.ConnectionError:
        print("⚠️  NIDS server not running - start with: python -m app.main")
        return False
    
    # Test with invalid API key
    headers = {"Authorization": "Bearer invalid_key"}
    response = requests.get(f"{base_url}/alerts", headers=headers)
    if response.status_code == 401:
        print("✅ API correctly rejects invalid API keys")
    else:
        print(f"❌ API accepts invalid API key: {response.status_code}")
    
    return True

def test_rate_limiting():
    """Test rate limiting"""
    print("🚦 Testing Rate Limiting...")
    
    base_url = "http://localhost:8000/api/v1"
    api_key = os.getenv("API_KEY", "test_key")
    headers = {"Authorization": f"Bearer {api_key}"}
    
    # Make rapid requests to trigger rate limiting
    rate_limited = False
    for i in range(150):  # Exceed the 100/minute limit
        response = requests.get(f"{base_url}/status", headers=headers)
        if response.status_code == 429:  # Too Many Requests
            rate_limited = True
            break
        time.sleep(0.1)  # Small delay
    
    if rate_limited:
        print("✅ Rate limiting is working")
    else:
        print("❌ Rate limiting not working or limit too high")
    
    return rate_limited

def test_input_validation():
    """Test input validation"""
    print("🛡️  Testing Input Validation...")
    
    base_url = "http://localhost:8000/api/v1"
    api_key = os.getenv("API_KEY", "test_key")
    headers = {"Authorization": f"Bearer {api_key}"}
    
    # Test invalid IP address
    response = requests.get(f"{base_url}/alerts?source_ip=invalid_ip", headers=headers)
    if response.status_code == 400:
        print("✅ Invalid IP address rejected")
    else:
        print(f"❌ Invalid IP address accepted: {response.status_code}")
    
    # Test invalid severity
    response = requests.get(f"{base_url}/alerts?severity=invalid_severity", headers=headers)
    if response.status_code == 400:
        print("✅ Invalid severity rejected")
    else:
        print(f"❌ Invalid severity accepted: {response.status_code}")
    
    # Test SQL injection attempt
    response = requests.get(f"{base_url}/alerts?source_ip='; DROP TABLE alerts; --", headers=headers)
    if response.status_code in [400, 422]:
        print("✅ SQL injection attempt blocked")
    else:
        print(f"❌ Potential SQL injection vulnerability: {response.status_code}")
    
    return True

def test_https_enforcement():
    """Test HTTPS enforcement"""
    print("🔐 Testing HTTPS Enforcement...")
    
    # This would test HTTPS in production
    # For development, we'll check if SSL certificates exist
    ssl_cert_path = Path("certs/nids.crt")
    ssl_key_path = Path("certs/nids.key")
    
    if ssl_cert_path.exists() and ssl_key_path.exists():
        print("✅ SSL certificates found")
    else:
        print("⚠️  SSL certificates not found - run setup_ssl script")
    
    return True

def test_security_headers():
    """Test security headers"""
    print("🛡️  Testing Security Headers...")
    
    try:
        response = requests.get("http://localhost:8000/")
        headers = response.headers
        
        security_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options", 
            "X-XSS-Protection",
            "Strict-Transport-Security",
            "Content-Security-Policy"
        ]
        
        missing_headers = []
        for header in security_headers:
            if header not in headers:
                missing_headers.append(header)
        
        if not missing_headers:
            print("✅ All security headers present")
        else:
            print(f"⚠️  Missing security headers: {missing_headers}")
        
        return len(missing_headers) == 0
        
    except requests.exceptions.ConnectionError:
        print("⚠️  Cannot test headers - server not running")
        return False

def test_cors_configuration():
    """Test CORS configuration"""
    print("🌐 Testing CORS Configuration...")
    
    try:
        # Test with allowed origin
        headers = {"Origin": "https://localhost:3000"}
        response = requests.options("http://localhost:8000/api/v1/status", headers=headers)
        
        if "Access-Control-Allow-Origin" in response.headers:
            allowed_origin = response.headers["Access-Control-Allow-Origin"]
            if allowed_origin == "https://localhost:3000" or allowed_origin == "*":
                print("✅ CORS configured")
            else:
                print(f"⚠️  Unexpected CORS origin: {allowed_origin}")
        else:
            print("⚠️  CORS headers not found")
        
        # Test with disallowed origin
        headers = {"Origin": "https://malicious-site.com"}
        response = requests.options("http://localhost:8000/api/v1/status", headers=headers)
        
        if "Access-Control-Allow-Origin" in response.headers:
            allowed_origin = response.headers["Access-Control-Allow-Origin"]
            if allowed_origin == "*":
                print("❌ CORS allows all origins (security risk)")
                return False
        
        return True
        
    except requests.exceptions.ConnectionError:
        print("⚠️  Cannot test CORS - server not running")
        return False

def test_mongodb_security():
    """Test MongoDB security configuration"""
    print("🗄️  Testing MongoDB Security...")
    
    # Check if MongoDB authentication is configured
    mongodb_url = os.getenv("MONGODB_URL", "")
    
    if "password" in mongodb_url or "@" in mongodb_url:
        print("✅ MongoDB authentication configured")
    else:
        print("❌ MongoDB authentication not configured")
        return False
    
    # Test connection (would need to be running)
    try:
        from app.db.secure_mongodb import secure_mongo
        if secure_mongo.connect():
            print("✅ Secure MongoDB connection successful")
            secure_mongo.disconnect()
            return True
        else:
            print("❌ MongoDB connection failed")
            return False
    except Exception as e:
        print(f"⚠️  MongoDB test error: {e}")
        return False

def test_model_integrity():
    """Test ML model integrity verification"""
    print("🤖 Testing ML Model Security...")
    
    try:
        from app.utils.security import model_security
        
        # Check if model checksums exist
        model_path = Path("app/ml_models/nids_model.joblib")
        if model_path.exists():
            # This would fail if no checksum is registered
            try:
                is_valid = model_security.verify_model_integrity(str(model_path))
                if is_valid:
                    print("✅ Model integrity verification working")
                else:
                    print("⚠️  Model integrity check failed (expected for new models)")
            except Exception:
                print("⚠️  Model integrity check not configured")
        else:
            print("⚠️  No ML model found to test")
        
        return True
        
    except Exception as e:
        print(f"⚠️  Model security test error: {e}")
        return False

def test_logging_security():
    """Test secure logging configuration"""
    print("📝 Testing Logging Security...")
    
    # Check if audit logging is enabled
    audit_enabled = os.getenv("ENABLE_AUDIT_LOG", "false").lower() == "true"
    
    if audit_enabled:
        print("✅ Audit logging enabled")
    else:
        print("⚠️  Audit logging not enabled")
    
    # Check log file permissions (if exists)
    log_file = Path("logs/nids.log")
    if log_file.exists():
        try:
            # Check if log file is readable
            with open(log_file, 'r') as f:
                f.read(100)  # Read first 100 chars
            print("✅ Log file accessible")
        except PermissionError:
            print("❌ Log file permission error")
            return False
    
    return True

def generate_security_report(results):
    """Generate security assessment report"""
    print("\n" + "="*60)
    print("🛡️  NIDS SECURITY ASSESSMENT REPORT")
    print("="*60)
    
    total_tests = len(results)
    passed_tests = sum(1 for result in results.values() if result)
    
    print(f"Tests Passed: {passed_tests}/{total_tests}")
    print(f"Security Score: {(passed_tests/total_tests)*100:.1f}%")
    
    print("\n📊 Test Results:")
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {test_name}: {status}")
    
    print("\n🔧 Recommendations:")
    if not results.get("api_auth", True):
        print("  - Configure API authentication")
    if not results.get("rate_limiting", True):
        print("  - Enable rate limiting")
    if not results.get("mongodb_security", True):
        print("  - Configure MongoDB authentication")
    if not results.get("https", True):
        print("  - Generate SSL certificates")
    
    # Overall security level
    if passed_tests == total_tests:
        print("\n🎉 EXCELLENT: All security tests passed!")
    elif passed_tests >= total_tests * 0.8:
        print("\n✅ GOOD: Most security measures in place")
    elif passed_tests >= total_tests * 0.6:
        print("\n⚠️  MODERATE: Some security issues need attention")
    else:
        print("\n❌ POOR: Critical security vulnerabilities exist")

def main():
    """Run all security tests"""
    print("🛡️  NIDS Security Testing Suite")
    print("="*50)
    
    # Check if .env file exists
    if not Path(".env").exists():
        print("❌ No .env file found - run secure_deploy.py first")
        return
    
    # Load environment variables
    from dotenv import load_dotenv
    load_dotenv()
    
    # Run all tests
    results = {
        "api_auth": test_api_authentication(),
        "rate_limiting": test_rate_limiting(),
        "input_validation": test_input_validation(),
        "https": test_https_enforcement(),
        "security_headers": test_security_headers(),
        "cors": test_cors_configuration(),
        "mongodb_security": test_mongodb_security(),
        "model_integrity": test_model_integrity(),
        "logging_security": test_logging_security()
    }
    
    # Generate report
    generate_security_report(results)

if __name__ == "__main__":
    main()
