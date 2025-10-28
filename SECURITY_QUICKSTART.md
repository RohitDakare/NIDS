# 🚀 NIDS Security Quick Start

## ⚡ **Immediate Security Setup (5 Minutes)**

### **Step 1: Run Security Hardening**
```bash
# Navigate to NIDS directory
cd d:\NIDS

# Activate virtual environment
venv_new\Scripts\activate

# Run security deployment script
python scripts\secure_deploy.py
```

### **Step 2: Setup MongoDB Security**
```bash
# Start MongoDB with authentication
mongo < setup_mongodb.js
```

### **Step 3: Generate SSL Certificates**
```bash
# Windows
setup_ssl.bat

# The script creates:
# - certs\nids.crt (certificate)
# - certs\nids.key (private key)
```

### **Step 4: Install Security Dependencies**
```bash
pip install -r requirements-security.txt
```

### **Step 5: Test Security**
```bash
# Run security tests
python scripts\security_test.py

# Expected: All tests should pass
```

## 🔑 **Your Security Credentials**

After running `secure_deploy.py`, check `SECURITY_CREDENTIALS.txt`:

```
API Key: [32-character random key]
MongoDB Password: [16-character random password]
```

**⚠️ IMPORTANT: Delete this file after copying credentials to secure storage!**

## 🚦 **Quick Security Verification**

### **Test 1: API Authentication**
```bash
# This should FAIL (401 Unauthorized)
curl http://localhost:8000/api/v1/alerts

# This should SUCCEED (with your API key)
curl -H "Authorization: Bearer YOUR_API_KEY" http://localhost:8000/api/v1/status
```

### **Test 2: Rate Limiting**
```bash
# Make 150+ rapid requests - should get rate limited
for /L %i in (1,1,150) do curl -H "Authorization: Bearer YOUR_API_KEY" http://localhost:8000/api/v1/status
```

### **Test 3: Input Validation**
```bash
# This should FAIL (400 Bad Request)
curl -H "Authorization: Bearer YOUR_API_KEY" "http://localhost:8000/api/v1/alerts?source_ip=invalid_ip"
```

## 🛡️ **Security Status Check**

Run this anytime to check security:
```bash
python scripts\security_test.py
```

**Expected Output:**
```
🛡️ NIDS Security Testing Suite
==================================================
🔒 Testing API Authentication...
✅ API correctly rejects unauthenticated requests
✅ API correctly rejects invalid API keys

🚦 Testing Rate Limiting...
✅ Rate limiting is working

🛡️ Testing Input Validation...
✅ Invalid IP address rejected
✅ Invalid severity rejected
✅ SQL injection attempt blocked

Tests Passed: 9/9
Security Score: 100.0%
🎉 EXCELLENT: All security tests passed!
```

## 🚨 **If Security Tests Fail**

### **Common Issues & Fixes:**

**❌ "NIDS server not running"**
```bash
# Start the NIDS server
python -m app.main
```

**❌ "API allows unauthenticated access"**
```bash
# Check .env file has API_KEY
echo %API_KEY%

# Restart server with new config
python -m app.main
```

**❌ "MongoDB authentication failed"**
```bash
# Check MongoDB is running with auth
# Verify MONGODB_URL in .env file
```

**❌ "SSL certificates not found"**
```bash
# Generate certificates
setup_ssl.bat
```

## 🔧 **Production Deployment**

### **Environment Variables**
Your `.env` file should contain:
```env
# Security (Generated automatically)
API_KEY=<32-char-key>
JWT_SECRET=<32-char-secret>
ENCRYPTION_KEY=<32-char-key>

# Database (Secure)
MONGODB_URL=mongodb://nids_user:<password>@localhost:27017/nids?authSource=admin

# Security Features (Enabled)
ENABLE_RATE_LIMITING=true
ENABLE_API_AUTH=true
ENABLE_HTTPS=true
ENABLE_AUDIT_LOG=true

# Network (Restricted)
API_HOST=127.0.0.1
CORS_ORIGINS=https://localhost:3000
```

### **File Permissions**
```bash
# Secure .env file (Windows)
icacls .env /grant:r "%USERNAME%:F" /inheritance:r

# Secure certificate files
icacls certs\nids.key /grant:r "%USERNAME%:F" /inheritance:r
```

## 📊 **Security Monitoring**

### **Daily Checks**
```bash
# Check security logs
type logs\nids.log | findstr "security"

# Monitor failed attempts
type logs\nids.log | findstr "failed"

# Check rate limiting
type logs\nids.log | findstr "rate_limit"
```

### **Weekly Tasks**
- Run security test suite
- Review audit logs
- Update API keys if needed
- Check SSL certificate expiry

## 🆘 **Emergency Security Response**

### **If Compromised:**
1. **Immediate:**
   ```bash
   # Stop NIDS service
   taskkill /f /im python.exe
   
   # Block suspicious IPs in firewall
   # Change all passwords immediately
   ```

2. **Investigation:**
   ```bash
   # Check security logs
   type logs\nids.log | findstr "security"
   
   # Review recent API access
   type logs\nids.log | findstr "api_access"
   ```

3. **Recovery:**
   ```bash
   # Generate new credentials
   python scripts\secure_deploy.py
   
   # Restart with new security config
   python -m app.main
   ```

## ✅ **Security Checklist**

Before going to production:

- [ ] ✅ Ran `secure_deploy.py`
- [ ] ✅ MongoDB authentication configured
- [ ] ✅ SSL certificates generated
- [ ] ✅ Security tests pass (100%)
- [ ] ✅ API authentication working
- [ ] ✅ Rate limiting active
- [ ] ✅ Input validation enabled
- [ ] ✅ Audit logging configured
- [ ] ✅ Firewall rules configured
- [ ] ✅ Strong passwords used
- [ ] ✅ `.env` file secured
- [ ] ✅ Security documentation reviewed

## 🎯 **Security Score Target**

**Minimum for Production: 90%**
**Recommended: 100%**

Your NIDS system should achieve 100% security score with all measures implemented.

---

## 📞 **Need Help?**

1. **Run diagnostics:** `python scripts\security_test.py`
2. **Check logs:** `type logs\nids.log`
3. **Review config:** `type .env`
4. **Read full guide:** `docs\SECURITY_GUIDE.md`

**🛡️ Your NIDS is now enterprise-grade secure!**
