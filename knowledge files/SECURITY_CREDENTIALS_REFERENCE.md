# 🔐 Security Credentials Backup Note

**Date:** December 26, 2025, 5:10 PM IST

## ⚠️ Important Security Notice

The file `SECURITY_CREDENTIALS.txt` has been **DELETED** for security reasons.

All credentials are now stored in the proper location: `backend/.env`

---

## 📋 Credentials Reference

All credentials are stored in: **`backend/.env`**

### API Authentication
```env
API_KEY=6KzqUy9WWj4jFlQ-j7L8Sw8pYoL4URHRgvajEVFGk1c
JWT_SECRET=Y2dSIoDoJ4fP_0nyLo5WiCuMiCk3SGYPA0afCXlM_AQ
ENCRYPTION_KEY=zwFwpSYd_ANox-oj-Z93eGDNPp-KrcY6pcz0EJWDPP8
```

### MongoDB Authentication
```env
MONGODB_USERNAME=nids_user
MONGODB_PASSWORD=19fGlFYnLIcp-KEDy3CMQw
MONGODB_URL=mongodb://nids_user:19fGlFYnLIcp-KEDy3CMQw@localhost:27017/nids?authSource=admin
```

---

## 🔒 Security Best Practices

### For Development
- ✅ Credentials are in `.env` file
- ✅ `.env` is in `.gitignore`
- ✅ Plaintext credentials file deleted

### For Production
1. **Use Environment-Specific Secrets**
   - Don't commit `.env` to version control
   - Use different credentials for each environment

2. **Secret Management**
   - Consider using: Azure Key Vault, AWS Secrets Manager, HashiCorp Vault
   - Or environment variables set at system level

3. **Rotate Credentials Regularly**
   - Change API keys every 90 days
   - Update MongoDB passwords periodically

4. **Access Control**
   - Limit who can access `.env` file
   - Use file permissions (chmod 600 on Linux)
   - Encrypt sensitive files at rest

---

## 🔄 How to Regenerate Credentials

If you need to regenerate credentials:

### API Keys
```bash
cd backend
python scripts/secure_deploy.py
```

### MongoDB Password
```bash
# Generate new password
python -c "import secrets; print(secrets.token_urlsafe(32))"

# Update in .env file
# Update in MongoDB: mongo < scripts/setup_mongodb.js
```

---

## 📝 Where Credentials Are Used

### API_KEY
- Used in: API authentication headers
- Format: `Authorization: Bearer YOUR_API_KEY`
- Endpoints: All protected API endpoints

### JWT_SECRET
- Used in: JWT token signing
- Purpose: User session management
- Security: Keep this secret!

### ENCRYPTION_KEY
- Used in: Data encryption
- Purpose: Encrypt sensitive data
- Security: Never expose this

### MongoDB Credentials
- Used in: Database connections
- Purpose: Authenticate to MongoDB
- Security: Restrict network access

---

## 🚨 If Credentials Are Compromised

1. **Immediately Regenerate All Credentials**
   ```bash
   python scripts/secure_deploy.py
   ```

2. **Update `.env` File**
   - Replace all compromised credentials
   - Restart all services

3. **Revoke Old Credentials**
   - Update MongoDB users
   - Invalidate old API keys
   - Clear JWT tokens

4. **Audit Access Logs**
   - Check `logs/nids.log`
   - Review MongoDB audit logs
   - Look for suspicious activity

5. **Notify Stakeholders**
   - Inform team members
   - Document the incident
   - Update security procedures

---

## 📍 File Locations

### Current Credentials
- **Location:** `backend/.env`
- **Backup:** None (for security)
- **Version Control:** Excluded (in .gitignore)

### Example Configuration
- **Location:** `backend/config/env.example`
- **Purpose:** Template for new environments
- **Contains:** Placeholder values only

---

## ✅ Security Checklist

- [x] Credentials moved to `.env`
- [x] Plaintext credentials file deleted
- [x] `.env` in `.gitignore`
- [x] MongoDB authentication configured
- [x] API key authentication enabled
- [ ] SSL/TLS certificates generated (optional)
- [ ] Production credentials different from dev
- [ ] Regular credential rotation scheduled
- [ ] Access logs monitored
- [ ] Backup strategy implemented

---

## 💡 Additional Security Measures

### 1. Enable HTTPS
```env
ENABLE_HTTPS=true
SSL_CERT_PATH=certs/nids.crt
SSL_KEY_PATH=certs/nids.key
```

### 2. Restrict CORS
```env
CORS_ORIGINS=https://yourdomain.com
```

### 3. Enable Rate Limiting
```env
ENABLE_RATE_LIMITING=true
```

### 4. Enable API Authentication
```env
ENABLE_API_AUTH=true
```

### 5. Enable Audit Logging
```env
ENABLE_AUDIT_LOG=true
```

---

**Note:** This file serves as a reference only. The actual credentials are in `backend/.env`.

**Last Updated:** December 26, 2025, 5:10 PM IST
