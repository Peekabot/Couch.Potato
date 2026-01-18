# 🧪 Testing Guide - Mobile AI Agent

> **Comprehensive guide for testing the AI-powered reconnaissance agent**

---

## ⚠️ Important Note

This agent is designed to work on **real systems** with internet access. The development environment has network restrictions, so you'll need to test on:

- ✅ Your local machine
- ✅ PythonAnywhere
- ✅ Any VPS/server
- ✅ Termux (Android)

---

## 🚀 Quick Test (5 Minutes)

### On Your Local Machine

```bash
# 1. Navigate to agent directory
cd /path/to/Couch.Potato/mobile-ai-agent

# 2. Set up environment (recommended)
cp .env.example .env
nano .env  # Add your Mistral API key

# 3. Run test scan
python3 scripts/ai_recon_agent.py -t example.com

# 4. Check results
ls -la results/example_com/
```

### Expected Output

```
[2025-01-18 10:00:01] INFO - 🤖 Starting AI-enhanced scan for: example.com
[2025-01-18 10:00:02] INFO - Starting subdomain enumeration for example.com
[2025-01-18 10:00:15] INFO - crt.sh found 8 total unique subdomains
[2025-01-18 10:00:16] INFO - 🤖 AI prioritizing subdomains...
[2025-01-18 10:00:20] INFO - AI identified 3 priority targets
[2025-01-18 10:00:20] INFO -   1. www.example.com (score: 6/10) - Main website
[2025-01-18 10:00:20] INFO -   2. mail.example.com (score: 5/10) - Email server
[2025-01-18 10:00:21] INFO - Probing 8 subdomains for live hosts
[2025-01-18 10:00:35] INFO - Found 3 live hosts
[2025-01-18 10:00:36] INFO - Starting vulnerability scan on 3 hosts
[2025-01-18 10:00:45] INFO - 🤖 AI analyzing 2 findings...
[2025-01-18 10:00:50] INFO -   ⚠️  High-value finding: server_disclosure (exploitability: 3/10)
[2025-01-18 10:00:51] INFO - 🤖 AI generating PoCs for high-value findings...
[2025-01-18 10:00:55] INFO -   Generating PoC 1/1: server_disclosure
[2025-01-18 10:00:58] INFO -   PoC saved: poc_1_server_disclosure.md
[2025-01-18 10:00:59] INFO - Report saved: results/example_com/report_*.md
[2025-01-18 10:01:05] INFO - Enhanced report saved: ai_enhanced_report_*.md
[2025-01-18 10:01:10] INFO - 🎯 Recommended next steps:
[2025-01-18 10:01:10] INFO -   1. Check for subdomain takeover opportunities
[2025-01-18 10:01:10] INFO -   2. Test email server for open relay
[2025-01-18 10:01:11] INFO - ✅ AI-enhanced scan complete for example.com
```

---

## 📂 Output Files to Check

After a successful test, you should see:

```
results/example_com/
├── all_subdomains.txt           # ✅ Should have ~8 subdomains
├── live_hosts.txt               # ✅ Should have 2-3 hosts
├── findings.json                # ✅ Should have some findings
├── ai_priorities.json           # 🤖 AI rankings (JSON)
├── ai_analyzed_findings.json    # 🤖 AI analysis with scores
├── ai_next_steps.json           # 🤖 AI suggestions
├── pocs/
│   └── poc_1_*.md              # 🤖 AI-generated PoC
├── report_*.md                  # Standard report
└── ai_enhanced_report_*.md      # 🤖 Professional AI report

logs/
└── recon_agent.log              # Full execution log
```

---

## 🔍 Verify AI Features

### 1. Check AI Prioritization

```bash
cat results/example_com/ai_priorities.json
```

**Expected**:
```json
[
  {
    "subdomain": "www.example.com",
    "score": 6,
    "reason": "Main website, standard configuration"
  },
  {
    "subdomain": "mail.example.com",
    "score": 5,
    "reason": "Email server, check for open relay"
  }
]
```

### 2. Check AI Vulnerability Analysis

```bash
cat results/example_com/ai_analyzed_findings.json
```

**Expected**:
```json
[
  {
    "host": "https://www.example.com",
    "type": "server_disclosure",
    "severity": "low",
    "details": "Server: ECS (dcb/7EA3)",
    "ai_analysis": {
      "exploitability": 3,
      "impact": "Fingerprinting attack surface",
      "worth_reporting": false,
      "cvss_estimate": "2.0",
      "reasoning": "Low severity info disclosure..."
    }
  }
]
```

### 3. Check AI-Generated PoC

```bash
cat results/example_com/pocs/poc_1_*.md
```

**Expected**: Full markdown PoC with steps, commands, safety notes

### 4. Check AI Next Steps

```bash
cat results/example_com/ai_next_steps.json
```

**Expected**:
```json
[
  "Check for subdomain takeover on inactive DNS entries",
  "Test mail.example.com for open relay vulnerability",
  "Enumerate additional subdomains with dictionary attack"
]
```

---

## 💰 Test API Costs

### Monitor Your Spend

```python
# Add this to your test script
from security.security_utils import RateLimiter

limiter = RateLimiter(max_calls_per_hour=10, max_cost_per_day=1.0)

# Before each AI call
if limiter.check_limit(estimated_cost=0.01):
    # Make AI call
    pass
else:
    print("Rate limit reached!")

# Check stats
print(limiter.get_stats())
```

**Expected output**:
```json
{
  "calls_last_hour": 5,
  "max_calls_per_hour": 10,
  "daily_cost": 0.05,
  "max_cost_per_day": 1.0,
  "time_until_reset": 82345
}
```

---

## 🧪 Test Scenarios

### Scenario 1: Standard Website (Free)

```bash
# Uses only free APIs (crt.sh)
python3 scripts/recon_agent.py -t example.com --no-ai

# Expected cost: $0
# Expected time: 30-60 seconds
```

### Scenario 2: AI-Enhanced Scan (Small Cost)

```bash
# Uses Mistral API for AI features
python3 scripts/ai_recon_agent.py -t example.com

# Expected cost: $0.01-0.02
# Expected time: 1-2 minutes
```

### Scenario 3: Large Target (Medium Cost)

```bash
# Large bug bounty target with many subdomains
python3 scripts/ai_recon_agent.py -t bugcrowd.com

# Expected cost: $0.05-0.10
# Expected time: 5-10 minutes
```

### Scenario 4: Batch Targets (Controlled)

```bash
# Create targets file
echo -e "example.com\nexample.org\nexample.net" > targets.txt

# Run with rate limiting
python3 scripts/ai_recon_agent.py -l targets.txt

# Expected cost: $0.03-0.06
# Expected time: 3-6 minutes
```

---

## 🔒 Test Security Features

### Test 1: Environment Variables

```bash
# Set API key via environment
export MISTRAL_API_KEY="your_key_here"

# Remove from config.json
nano config/config.json  # Delete api_key line

# Run scan - should still work
python3 scripts/ai_recon_agent.py -t example.com
```

**Expected**: Scan works using env var ✅

### Test 2: Rate Limiting

```bash
# Test rate limiter
python3 security/security_utils.py
```

**Expected output**:
```
Testing Rate Limiter...
Call 1: ✅ Allowed
Call 2: ✅ Allowed
...
Call 10: ✅ Allowed
Call 11: ❌ Blocked
Call 12: ❌ Blocked
```

### Test 3: Webhook Security

```bash
# Test signature verification
python3 -c "
from security.security_utils import WebhookSecurity
webhook = WebhookSecurity()
payload = 'test'
sig = webhook.sign_payload(payload)
print(f'Valid: {webhook.verify_signature(payload, sig)}')
print(f'Invalid: {webhook.verify_signature(payload, \"wrong\")}')
"
```

**Expected**:
```
Valid: True
Invalid: False
```

---

## 📱 Test Mobile Access

### Test on PythonAnywhere

1. **Sign up**: https://www.pythonanywhere.com
2. **Upload files**: Use Files tab or git clone
3. **Install deps**:
   ```bash
   pip3 install --user -r requirements.txt
   ```
4. **Set environment variables**:
   - Dashboard → Web → Add env var
   - Or upload `.env` file
5. **Run test**:
   ```bash
   cd ~/Couch.Potato/mobile-ai-agent
   python3 scripts/ai_recon_agent.py -t example.com
   ```
6. **Check results**:
   ```bash
   ls -la results/example_com/
   ```

### Test Web Dashboard

```bash
# Start Flask app
cd web-interface
python3 app.py

# Access from mobile browser
# Open: http://localhost:5000 (or PythonAnywhere URL)
```

**Test checklist**:
- [ ] Can access dashboard
- [ ] Can start scan via web UI
- [ ] Can view logs
- [ ] Can download reports
- [ ] Mobile-responsive design works

---

## 🐛 Troubleshooting Tests

### Issue: "Mistral API call failed"

**Possible causes**:
1. Invalid API key
2. No internet connection
3. Network proxy/firewall blocking
4. API quota exceeded

**Solution**:
```bash
# Test API key manually
curl -X POST https://api.mistral.ai/v1/chat/completions \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"mistral-small-latest","messages":[{"role":"user","content":"test"}]}'

# Should return JSON response, not error
```

### Issue: "No subdomains found"

**Possible causes**:
1. crt.sh API is down
2. Target has no subdomains in CT logs
3. Network issues

**Solution**:
```bash
# Test crt.sh manually
curl "https://crt.sh/?q=%.example.com&output=json" | head -20

# Should return JSON array
```

### Issue: "AI features not working"

**Checklist**:
- [ ] `ai.enabled = true` in config?
- [ ] API key set (config or env var)?
- [ ] Internet connection working?
- [ ] API credits available?

**Debug**:
```bash
# Enable debug logging
python3 scripts/ai_recon_agent.py -t example.com 2>&1 | grep -i "ai\|mistral"
```

---

## ✅ Test Success Criteria

Your test is successful if:

1. **✅ Subdomain enumeration works**
   - `all_subdomains.txt` has entries
   - Logged "found X subdomains"

2. **✅ AI prioritization works**
   - `ai_priorities.json` exists
   - Contains scored subdomains

3. **✅ Live host detection works**
   - `live_hosts.txt` has entries
   - Logged "Found X live hosts"

4. **✅ AI analysis works**
   - `ai_analyzed_findings.json` exists
   - Contains exploitability scores

5. **✅ PoC generation works** (if findings exist)
   - `pocs/` directory has .md files
   - PoCs have proper format

6. **✅ Reports generated**
   - `report_*.md` exists
   - `ai_enhanced_report_*.md` exists

7. **✅ Logs are clean**
   - No Python exceptions
   - No "FAILED" errors (warnings OK)

---

## 📊 Performance Benchmarks

**Expected performance** (on typical target with ~50 subdomains):

| Phase | Time | Cost |
|-------|------|------|
| Subdomain enumeration | 10-30s | $0 |
| AI prioritization | 5-10s | $0.005 |
| Live host probing | 20-60s | $0 |
| Vulnerability scanning | 30-90s | $0 |
| AI analysis (per finding) | 3-5s | $0.002 |
| AI PoC generation | 5-10s | $0.003 |
| AI report enhancement | 10-15s | $0.005 |
| **Total** | **2-4 min** | **$0.01-0.03** |

---

## 🎯 Next Steps After Successful Test

1. **✅ Add real targets** to `config.json`
2. **✅ Set up Telegram** notifications
3. **✅ Deploy to PythonAnywhere** for 24/7 automation
4. **✅ Schedule daily scans**
5. **✅ Start hunting bugs!** 🐛💰

---

## 🆘 Getting Help

If tests fail:

1. **Check logs**: `cat logs/recon_agent.log`
2. **Enable debug**: Add `--debug` flag (if implemented)
3. **Verify config**: `python3 -m json.tool config/config.json`
4. **Test APIs manually**: See troubleshooting section above
5. **Open issue**: https://github.com/Peekabot/Couch.Potato/issues

---

**Happy testing!** 🧪✅

Once your tests pass, you're ready for production bug bounty hunting! 🎯
