# 🔒 Security Guide - Mobile AI Agent

> **Production security hardening for your bug bounty automation**

---

## 🎯 Security Overview

This guide covers:
- ✅ API key protection
- ✅ Rate limiting & cost controls
- ✅ Webhook security
- ✅ Access control
- ✅ Secure deployment practices

---

## 🔐 Level 1: API Key Protection

### Use Environment Variables (Recommended)

**Why**: Keeps secrets out of git, easy to rotate, platform-independent

**Setup**:

```bash
# 1. Copy template
cp .env.example .env

# 2. Edit with your keys
nano .env
```

```bash
# .env file
MISTRAL_API_KEY=dvNJMLdOwr5FuO0jqV41eYEwWblzoCGS
TELEGRAM_BOT_TOKEN=1234567890:ABCdefGHIjklMNOpqrsTUVwxyz
```

**Usage**:

```python
from security.security_utils import SecureConfig

# Automatically loads from env vars or config.json
config = SecureConfig.load_config()
```

**Priority**: Env vars > config.json

### PythonAnywhere Setup

```bash
# Web tab → Environment variables
MISTRAL_API_KEY = your_key_here
TELEGRAM_BOT_TOKEN = your_token_here
```

### Local Development

```bash
# Install python-dotenv (optional)
pip install python-dotenv

# Load .env automatically
python3 scripts/ai_recon_agent.py
```

---

## ⏱️ Level 2: Rate Limiting

### Prevent API Overspending

**Why**: Avoid surprise bills from runaway scripts or bugs

**Setup**:

```python
from security.security_utils import RateLimiter

# Initialize with limits
limiter = RateLimiter(
    max_calls_per_hour=100,   # Max 100 API calls/hour
    max_cost_per_day=5.0      # Max $5/day
)

# Before each AI call
if limiter.check_limit(estimated_cost=0.01):
    # Make API call
    result = ai_agent.generate(prompt)
else:
    # Rate limit hit!
    logging.warning("Rate limit reached!")
    stats = limiter.get_stats()
    logging.info(f"Current usage: {stats}")
```

**Configuration**:

```bash
# .env
MAX_API_CALLS_PER_HOUR=100
MAX_COST_PER_DAY=5.0
```

**Dashboard Integration**:

```python
# View current usage
GET /api/rate-limit/stats

Response:
{
  "calls_last_hour": 23,
  "max_calls_per_hour": 100,
  "daily_cost": 0.54,
  "max_cost_per_day": 5.0,
  "time_until_reset": 73421
}
```

---

## 🔒 Level 3: Webhook Security

### HMAC Signature Verification

**Why**: Prevent unauthorized access to your webhooks

**Setup**:

```python
from security.security_utils import WebhookSecurity

# Initialize with secret
webhook_security = WebhookSecurity(
    secret_key="your_webhook_secret"
)

# Sign outgoing webhooks
payload = json.dumps({"scan_complete": True})
signature = webhook_security.sign_payload(payload)

# Include in request
headers = {"X-Signature": signature}
requests.post(url, data=payload, headers=headers)
```

**Verify Incoming Webhooks**:

```python
from flask import Flask, request
app = Flask(__name__)

@app.route('/webhook', methods=['POST'])
@webhook_security.require_signature
def webhook():
    # Only executes if signature is valid
    data = request.json
    return {"status": "ok"}
```

**Environment Variable**:

```bash
# .env
WEBHOOK_SECRET=your_secret_key_here
```

**Generate Secret**:

```python
import secrets
print(secrets.token_urlsafe(32))
# Use this as WEBHOOK_SECRET
```

---

## 🚫 Level 4: IP Whitelisting

### Restrict API Access

**Why**: Only allow access from trusted IPs

**Setup**:

```python
from security.security_utils import IPWhitelist

# Allow specific IPs
ip_whitelist = IPWhitelist(allowed_ips=[
    "127.0.0.1",              # Localhost
    "::1",                    # IPv6 localhost
    "203.0.113.42",           # Your office IP
    "198.51.100.0/24"         # Your network (CIDR)
])

# Protect Flask routes
@app.route('/admin')
@ip_whitelist.require_whitelist
def admin():
    return "Admin panel"
```

**Configuration**:

```bash
# .env
ALLOWED_IPS=127.0.0.1,::1,203.0.113.42
```

**Dynamic Updates**:

```python
# Add IP at runtime
ip_whitelist.allowed_ips.append("198.51.100.50")

# Remove IP
ip_whitelist.allowed_ips.remove("203.0.113.42")
```

---

## 🔍 Level 5: Audit Logging

### Track All Security Events

**Setup**:

```python
import logging

# Configure security logger
security_logger = logging.getLogger('security')
security_logger.setLevel(logging.INFO)

handler = logging.FileHandler('logs/security.log')
handler.setFormatter(logging.Formatter(
    '[%(asctime)s] %(levelname)s - %(message)s'
))
security_logger.addHandler(handler)

# Log security events
security_logger.info(f"API key accessed from IP {request.remote_addr}")
security_logger.warning(f"Rate limit exceeded for user {user_id}")
security_logger.error(f"Invalid signature from IP {ip}")
```

**What to Log**:

- ✅ API key access
- ✅ Rate limit hits
- ✅ Failed authentication
- ✅ Webhook signature failures
- ✅ IP whitelist violations
- ✅ Configuration changes

**Log Analysis**:

```bash
# Find suspicious activity
grep "FAILED\|ERROR" logs/security.log

# Count rate limit hits
grep "Rate limit" logs/security.log | wc -l

# Find failed authentications
grep "Invalid signature" logs/security.log
```

---

## 📦 Complete Secure Setup

### Production Checklist

**1. Environment Variables** ✅

```bash
# Never commit these!
cp .env.example .env
nano .env  # Add all secrets
```

**2. .gitignore** ✅

```
.env
.env.*
config/config.json
logs/
results/
```

**3. Rate Limiting** ✅

```python
# In your agent
limiter = RateLimiter(max_cost_per_day=5.0)
```

**4. Webhook Security** ✅

```python
# In web interface
webhook_security = WebhookSecurity()
@app.route('/webhook')
@webhook_security.require_signature
def webhook():
    pass
```

**5. IP Whitelisting** ✅

```python
# Restrict admin access
ip_whitelist = IPWhitelist()
@app.route('/admin')
@ip_whitelist.require_whitelist
def admin():
    pass
```

**6. Audit Logging** ✅

```python
# Log all security events
security_logger.info(f"Event: {event}")
```

---

## 🚀 Deployment Security

### PythonAnywhere

**Recommended settings**:

```bash
# Environment variables (Web tab)
MISTRAL_API_KEY = ***
WEBHOOK_SECRET = ***
MAX_COST_PER_DAY = 2.0
ALLOWED_IPS = your.ip.address

# Force HTTPS
# In Web tab → Force HTTPS: ON
```

**Web app security**:

```python
# In web-interface/app.py
from flask import Flask
from flask_talisman import Talisman

app = Flask(__name__)
Talisman(app, force_https=True)  # Enforce HTTPS
```

### Local / VPS

**Firewall**:

```bash
# Allow only necessary ports
sudo ufw allow 22    # SSH
sudo ufw allow 443   # HTTPS
sudo ufw deny 5000   # Don't expose Flask directly
sudo ufw enable

# Use nginx/apache as reverse proxy
```

**SSL Certificate**:

```bash
# Get free cert from Let's Encrypt
sudo apt install certbot
sudo certbot --nginx -d yourdomain.com
```

---

## 🔐 Secret Rotation

### Rotate API Keys Regularly

**Mistral API**:

1. Generate new key: https://console.mistral.ai
2. Update `.env` or env var
3. Test with new key
4. Delete old key

**Telegram Bot**:

1. Message @BotFather
2. `/revoke` then `/newbot`
3. Update config
4. Test bot

**Webhook Secret**:

```python
# Generate new secret
import secrets
new_secret = secrets.token_urlsafe(32)

# Update everywhere using the webhook
# Then update WEBHOOK_SECRET env var
```

**Schedule**: Rotate every 90 days

---

## 🚨 Incident Response

### If API Key is Compromised

**1. Immediate Actions**:

```bash
# Revoke key immediately
# Mistral: https://console.mistral.ai → Delete key
# Telegram: @BotFather → /revoke

# Check usage for suspicious activity
# Mistral: Check billing for unusual costs
```

**2. Assess Damage**:

```bash
# Check logs for unauthorized usage
grep "API call" logs/*.log | tail -100

# Check cost impact
# Review Mistral billing dashboard
```

**3. Remediate**:

```bash
# Generate new keys
# Update all systems with new keys
# Add to .gitignore if not already

# Update .env
nano .env  # Replace with new key
```

**4. Prevent Recurrence**:

- Review what caused the leak
- Implement additional controls
- Document lessons learned

---

## 🛡️ Best Practices

### Development

- ❌ Never commit secrets to git
- ❌ Never log API keys
- ❌ Never share `.env` files
- ✅ Use environment variables
- ✅ Use `.gitignore` for sensitive files
- ✅ Test rate limiting before production

### Production

- ✅ Use HTTPS only
- ✅ Enable rate limiting
- ✅ Implement webhook signatures
- ✅ Whitelist IPs for admin access
- ✅ Monitor logs for anomalies
- ✅ Rotate secrets every 90 days
- ✅ Use secrets manager (AWS Secrets Manager, etc.)

### Code Review

```python
# ❌ BAD - Hardcoded secret
api_key = "dvNJMLdOwr5FuO0jqV41eYEwWblzoCGS"

# ✅ GOOD - Environment variable
api_key = os.getenv("MISTRAL_API_KEY")

# ❌ BAD - Logged secret
logging.info(f"Using API key: {api_key}")

# ✅ GOOD - Masked logging
logging.info(f"Using API key: {api_key[:4]}***")
```

---

## 📊 Security Monitoring

### Monitor These Metrics

```python
# Track in security dashboard
metrics = {
    "api_calls_today": 234,
    "cost_today": 0.54,
    "rate_limit_hits": 0,
    "failed_auth_attempts": 2,
    "unique_ips_accessed": 3
}
```

### Alerts to Set Up

**High Priority**:
- Daily cost > $5
- Rate limit exceeded
- Failed webhook signatures > 5
- Access from unknown IP

**Medium Priority**:
- Daily cost > $2
- API errors > 10%
- Scan failures > 20%

**Telegram Alerts**:

```python
if daily_cost > 5.0:
    send_telegram_message(
        token, chat_id,
        "🚨 ALERT: Daily cost limit exceeded! $5.00"
    )
```

---

## ✅ Security Verification

### Test Your Security

```bash
# 1. Test rate limiter
python3 security/security_utils.py

# 2. Test webhook security
python3 -c "
from security.security_utils import WebhookSecurity
w = WebhookSecurity()
sig = w.sign_payload('test')
print(f'Valid: {w.verify_signature(\"test\", sig)}')
"

# 3. Verify .env not in git
git status
# Should NOT show .env file

# 4. Test env var loading
python3 -c "
from security.security_utils import SecureConfig
config = SecureConfig.load_config()
print('AI enabled:', config.get('ai', {}).get('enabled'))
"
```

**Expected**:
- ✅ Rate limiter blocks after limit
- ✅ Signature verification works
- ✅ `.env` not tracked by git
- ✅ Config loads from env vars

---

## 🆘 Security Help

**Report Security Issues**:
- Email: security@your-domain.com (if applicable)
- GitHub: https://github.com/Peekabot/Couch.Potato/security/advisories

**Resources**:
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- API Security: https://apisecurity.io/
- Flask Security: https://flask.palletsprojects.com/en/2.3.x/security/

---

**Your mobile AI agent is now production-ready and secure!** 🔒✅
