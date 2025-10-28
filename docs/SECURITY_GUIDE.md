# 🛡️ NIDS Security Guide

This comprehensive guide covers all security measures implemented in the NIDS system and how to maintain them.

## 🚨 **Security Overview**

Your NIDS system now includes enterprise-grade security measures:

- ✅ **API Authentication & Authorization**
- ✅ **Rate Limiting & DDoS Protection** 
- ✅ **Input Validation & Sanitization**
- ✅ **Secure Database Configuration**
- ✅ **ML Model Integrity Verification**
- ✅ **Comprehensive Audit Logging**
- ✅ **HTTPS/TLS Encryption**
- ✅ **Security Headers & CORS**

## 🔐 **Authentication & Authorization**

### **API Key Authentication**
```bash
# All API endpoints require authentication
curl -H "Authorization: Bearer YOUR_API_KEY" \
     http://localhost:8000/api/v1/alerts
```

### **JWT Token Support**
```python
# Generate JWT tokens for extended sessions
from app.utils.security import security_manager

token = security_manager.create_access_token({"user": "admin"})
```

### **Failed Attempt Protection**
- Automatic IP blocking after 5 failed attempts
- 30-minute lockout period
- Audit logging of all attempts

## 🚦 **Rate Limiting**

### **Current Limits**
- **General APIs**: 100 requests/minute
- **Control APIs**: 10 requests/minute (start/stop)
- **Burst Protection**: 200 requests maximum

### **Rate Limit Headers**
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
```

## 🛡️ **Input Validation**

### **Automatic Validation**
All inputs are automatically validated:

```python
# IP Address Validation
source_ip = "192.168.1.1"  # ✅ Valid
source_ip = "999.999.999.999"  # ❌ Rejected

# Severity Validation  
severity = "high"  # ✅ Valid
severity = "invalid"  # ❌ Rejected

# Interface Name Validation
interface = "Ethernet"  # ✅ Valid
interface = "'; DROP TABLE alerts; --"  # ❌ Rejected
```

### **Sanitization**
- All string inputs sanitized
- Control characters removed
- Length limits enforced
- NoSQL injection prevention

## 🗄️ **Database Security**

### **MongoDB Authentication**
```javascript
// Secure user creation
use admin
db.createUser({
  user: "nids_user",
  pwd: "secure_password",
  roles: [
    { role: "readWrite", db: "nids" },
    { role: "dbAdmin", db: "nids" }
  ]
})
```

### **Connection Security**
```bash
# Secure connection string
MONGODB_URL=mongodb://nids_user:password@localhost:27017/nids?authSource=admin
```

### **Query Protection**
- Parameterized queries only
- Input sanitization
- Field whitelisting
- Injection prevention

## 🤖 **ML Model Security**

### **Integrity Verification**
```python
# Models verified before loading
from app.utils.security import model_security

# Register new model
model_security.register_model("app/ml_models/new_model.joblib")

# Verify before use
if model_security.verify_model_integrity(model_path):
    model = joblib.load(model_path)
```

### **Model Checksums**
```json
{
  "nids_model.joblib": "sha256:abc123...",
  "backup_model.joblib": "sha256:def456..."
}
```

## 📝 **Audit Logging**

### **Security Events Logged**
- Authentication attempts (success/failure)
- API access patterns
- Configuration changes
- Alert generation/resolution
- Database operations
- Model loading/updates

### **Log Format**
```json
{
  "timestamp": "2024-01-01T12:00:00Z",
  "event_type": "api_access",
  "client_ip": "192.168.1.100",
  "details": {
    "endpoint": "/api/v1/alerts",
    "method": "GET",
    "user_agent": "Mozilla/5.0...",
    "has_auth": true
  }
}
```

### **Log Security**
- Sensitive data automatically redacted
- Structured logging format
- Rotation and retention policies
- Tamper-evident logging

## 🔒 **HTTPS/TLS Configuration**

### **SSL Certificate Setup**
```bash
# Generate certificates
./setup_ssl.sh  # Linux/Mac
setup_ssl.bat   # Windows

# Certificates created in certs/ directory
certs/nids.crt  # Public certificate
certs/nids.key  # Private key
```

### **TLS Configuration**
```python
# Minimum TLS 1.2 required
ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
```

## 🌐 **CORS & Security Headers**

### **CORS Configuration**
```python
# Restrictive CORS policy
allow_origins=["https://localhost:3000"]  # Specific origins only
allow_credentials=True
allow_methods=["GET", "POST", "PUT", "DELETE"]
allow_headers=["Authorization", "Content-Type"]
```

### **Security Headers**
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
```

## 🚀 **Deployment Security**

### **Secure Deployment Process**
```bash
# 1. Run security hardening
python scripts/secure_deploy.py

# 2. Configure MongoDB security
mongo < setup_mongodb.js

# 3. Generate SSL certificates
./setup_ssl.sh

# 4. Test security measures
python scripts/security_test.py

# 5. Deploy with security
python -m app.main
```

### **Environment Security**
```bash
# Secure environment variables
API_KEY=<32-character-random-key>
JWT_SECRET=<32-character-random-key>
MONGODB_PASSWORD=<16-character-random-password>
ENABLE_HTTPS=true
ENABLE_API_AUTH=true
ENABLE_RATE_LIMITING=true
```

## 🔧 **Security Maintenance**

### **Regular Tasks**

**Daily:**
- Monitor security logs
- Check failed authentication attempts
- Review rate limiting metrics

**Weekly:**
- Rotate API keys if needed
- Update security configurations
- Review audit logs

**Monthly:**
- Update dependencies
- Regenerate SSL certificates
- Security penetration testing
- Backup security configurations

### **Security Monitoring**
```bash
# Check security status
python scripts/security_test.py

# Monitor logs
tail -f logs/nids.log | grep "security"

# Check rate limiting
curl -I http://localhost:8000/api/v1/status
```

## 🚨 **Incident Response**

### **Security Breach Response**
1. **Immediate Actions:**
   - Stop NIDS service
   - Block suspicious IPs
   - Rotate all API keys
   - Review audit logs

2. **Investigation:**
   - Analyze security logs
   - Identify attack vectors
   - Assess data exposure
   - Document findings

3. **Recovery:**
   - Patch vulnerabilities
   - Update security measures
   - Restore from clean backups
   - Notify stakeholders

### **Emergency Contacts**
```bash
# Security team contacts
SECURITY_EMAIL=security@yourorg.com
INCIDENT_PHONE=+1-555-SECURITY
```

## 📊 **Security Metrics**

### **Key Performance Indicators**
- Authentication success rate: >99%
- Failed login attempts: <1% of total
- Rate limiting effectiveness: >95%
- SSL certificate validity: Always valid
- Security test pass rate: 100%

### **Monitoring Dashboard**
```python
# Security metrics endpoint
GET /api/v1/security/metrics
{
  "auth_success_rate": 99.8,
  "failed_attempts_24h": 12,
  "rate_limited_requests": 45,
  "ssl_cert_expires": "2024-12-31",
  "security_score": 98.5
}
```

## 🔍 **Security Testing**

### **Automated Testing**
```bash
# Run comprehensive security tests
python scripts/security_test.py

# Expected output:
# Tests Passed: 9/9
# Security Score: 100.0%
# 🎉 EXCELLENT: All security tests passed!
```

### **Manual Testing**
```bash
# Test authentication
curl http://localhost:8000/api/v1/alerts
# Should return 401 Unauthorized

# Test rate limiting
for i in {1..150}; do curl -H "Authorization: Bearer $API_KEY" http://localhost:8000/api/v1/status; done
# Should return 429 Too Many Requests

# Test input validation
curl -H "Authorization: Bearer $API_KEY" "http://localhost:8000/api/v1/alerts?source_ip='; DROP TABLE alerts; --"
# Should return 400 Bad Request
```

## 🛠️ **Troubleshooting**

### **Common Security Issues**

**Authentication Failures:**
```bash
# Check API key configuration
echo $API_KEY

# Verify .env file
cat .env | grep API_KEY

# Check logs
grep "authentication" logs/nids.log
```

**Rate Limiting Issues:**
```bash
# Check rate limit configuration
grep "rate_limit" config/security.json

# Monitor rate limiting
curl -I http://localhost:8000/api/v1/status
```

**SSL Certificate Problems:**
```bash
# Check certificate validity
openssl x509 -in certs/nids.crt -text -noout

# Regenerate if expired
./setup_ssl.sh
```

## 📚 **Security Best Practices**

### **Development Security**
- Never commit secrets to version control
- Use environment variables for configuration
- Regularly update dependencies
- Follow secure coding practices
- Implement comprehensive testing

### **Production Security**
- Use strong, unique passwords
- Enable all security features
- Monitor security logs continuously
- Implement network segmentation
- Regular security audits

### **Compliance Considerations**
- Data encryption at rest and in transit
- Access logging and audit trails
- User authentication and authorization
- Data retention and deletion policies
- Incident response procedures

## 🔮 **Advanced Security Features**

### **Future Enhancements**
- Multi-factor authentication (MFA)
- Role-based access control (RBAC)
- API versioning and deprecation
- Advanced threat detection
- Integration with SIEM systems

### **Enterprise Features**
- Single Sign-On (SSO) integration
- Certificate-based authentication
- Hardware security module (HSM) support
- Advanced audit logging
- Compliance reporting

---

## 📞 **Security Support**

For security-related questions or incidents:

- **Documentation**: This guide and inline code comments
- **Testing**: Run `python scripts/security_test.py`
- **Logs**: Check `logs/nids.log` for security events
- **Configuration**: Review `config/security.json`

**Remember**: Security is an ongoing process, not a one-time setup. Regularly review and update your security measures to protect against evolving threats.
