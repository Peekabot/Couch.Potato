# 📱 Pythonista Bug Bounty Tools

Mobile-first security testing tools designed for iPhone/iPad using [Pythonista](https://apps.apple.com/us/app/pythonista-3/id1085978097).

---

## 🎯 What's Here

### 1. Mobile API Interceptor & Fuzzer (`mobile_api_interceptor.py`)

**Tests for**: IDOR, Parameter Tampering, Authentication Bypass (Bugcrowd VRT P1-P3)

**What it does**:
- Tests mobile app APIs for security flaws
- Automates IDOR testing (try different user IDs)
- Parameter fuzzing (price manipulation, privilege escalation)
- Authentication bypass testing (endpoints accessible without tokens)

**Usage**:
```python
from mobile_api_interceptor import MobileAPITester

# Initialize with your API details
api = MobileAPITester(
    base_url="https://api.example.com/v1",
    auth_token="your_jwt_token_here"
)

# Test for IDOR
api.test_idor(
    endpoint="/users/{user_id}/profile",
    id_param="user_id",
    test_ids=[1, 2, 3, 100, 101]  # Try different user IDs
)

# Test parameter tampering
api.test_parameter_tampering(
    endpoint="/purchases",
    method="POST",
    base_params={"product_id": 123, "price": 99.99},
    tamper_params=[
        {"price": 0.01},  # Nearly free
        {"price": -99.99},  # Negative price
        {"is_admin": True}  # Privilege escalation
    ]
)

# Test authentication bypass
api.test_authentication_bypass("/users/me")
```

**Typical findings**:
- **P2**: IDOR allowing access to other users' sensitive data
- **P2**: Price manipulation in purchase endpoints
- **P1/P2**: Authentication bypass on sensitive endpoints
- **P3**: Parameter tampering for privilege escalation

**Workflow**:
1. Capture mobile app traffic using Burp Suite
2. Extract API endpoints and auth tokens
3. Use this tool to fuzz parameters and test access control
4. Report findings using templates/BUGCROWD_TEMPLATE.md

### 2. GPS EXIF Scanner (`gps_exif_scanner.py`)

**Tests for**: Information Disclosure (Bugcrowd VRT P3/P4)

**What it does**:
- Picks an image from your iPhone photo library
- Extracts all EXIF metadata
- Checks for embedded GPS coordinates
- Identifies other sensitive metadata (camera model, timestamps, etc.)

**Bug bounty workflow**:
1. Take photo with GPS enabled on your iPhone
2. Upload to target website (profile pic, product image, etc.)
3. Download the image back from the website
4. Run this scanner on downloaded image
5. If GPS data still present → Write report using `templates/BUGCROWD_TEMPLATE.md`

**Vulnerability classification**:
- **Category**: Sensitive Data Exposure
- **Subcategory**: EXIF Geolocation Data Present
- **Priority**: P3 (Medium) if user data, P4 (Low) if low-risk context
- **Impact**: Attackers can track users' physical locations

**Example output**:
```
🔍 GPS EXIF SCANNER - Bug Bounty Edition
================================================

📍 GPS COORDINATE CHECK
================================================
🚨 VULNERABILITY FOUND: GPS Metadata Present!

   Latitude:  37.7749
   Longitude: -122.4194

   Google Maps: https://www.google.com/maps?q=37.7749,-122.4194

   ⚠️  If this image was uploaded to a website and
   this data is still present, it's an Information
   Disclosure vulnerability (Bugcrowd VRT: P3/P4)
```

**Requirements**:
- Pythonista 3 (iOS app)
- Python 3.6+
- Built-in libraries: `photos`, `PIL` (Pillow)

**Usage**:
```python
# In Pythonista
import gps_exif_scanner
gps_exif_scanner.analyze_image()
```

---

### 3. VRT Knowledge Agent (`vrt_knowledge_agent.py`)

**Tests for**: Nothing - this is a decision-making tool

**What it does**:
- Transforms Bugcrowd VRT into machine-readable knowledge base
- Answers questions about vulnerability priorities
- Recommends hunting strategies based on severity
- Lists vulnerabilities by priority level

**Why it matters**:
Instead of guessing "Is SQL injection a P1 or P4?", ask the agent. It uses structured VRT data to give authoritative answers on:
- What priority level a bug is worth
- How much time to invest in hunting it
- What bounty range to expect
- Whether to automate or manually test

**Example queries**:
```
❓ Ask: What priority is SQL injection?
🤖 Priority: P1 (Critical)
    Impact: Immediate threat to core systems/data...
    Bounty Range: $1,000 - $20,000+
    Time Investment: HIGH - Manually verify, create detailed PoC

❓ Ask: Show me all P1 vulnerabilities
🤖 🎯 P1 (Critical) VULNERABILITIES:
    Bounty Range: $1,000 - $20,000+

      • server_side_injection > sql_injection
      • server_side_injection > remote_code_execution
      • server_side_injection > command_injection
      • broken_access_control > privilege_escalation_to_admin
      ...

❓ Ask: What's the strategy for P3?
🤖 🎯 STRATEGY: MEDIUM PRIORITY
    - Focus: Semi-automated scanning + manual verification
    - PoC: Simple proof of concept, clear steps
    - Report: Concise writeup with key details
    - ROI: Moderate bounties, balance automation with manual work
```

**Requirements**:
- Python 3.6+
- Standard library only (no external dependencies)

**Usage**:
```python
# Interactive mode
python vrt_knowledge_agent.py

# Programmatic use
from vrt_knowledge_agent import ModularKnowledgeAgent

agent = ModularKnowledgeAgent()
print(agent.ask("What priority is IDOR?"))
```

**Available queries**:
- Priority lookup: `"What priority is [vulnerability]?"`
- List by priority: `"Show me all P2 vulnerabilities"`
- Hunting strategy: `"What's the strategy for P1?"`
- Category info: `"Tell me about broken access control"`

---

## 🚀 Quick Start

### For Pythonista Users (iPhone/iPad)

1. **Install Pythonista 3** from App Store ($9.99)

2. **Download scripts**:
   ```bash
   # On your computer (if you have access to this repo)
   git clone https://github.com/yourusername/Couch.Potato.git
   cd Couch.Potato/pythonista/

   # Transfer to iPhone via:
   # - AirDrop
   # - iCloud Drive
   # - Pythonista's built-in WebDAV server
   ```

3. **Or copy-paste manually**:
   - Open Pythonista on iPhone
   - Tap `+` to create new script
   - Copy code from GitHub/repo
   - Paste into Pythonista editor
   - Save and run

### For Desktop Users (Testing Before Mobile)

```bash
# Both scripts work on desktop Python too
python3 vrt_knowledge_agent.py

# GPS scanner requires iOS photo library, but you can adapt it:
# - Replace photos.pick_asset() with file path input
# - Use PIL to open image from disk
```

---

## 📚 Learn → Do → Teach

### Learn (Weeks 1-2)
- **Read**: [Sensitive Data Exposure](https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure) on OWASP
- **Study**: [Bugcrowd VRT](https://bugcrowd.com/vulnerability-rating-taxonomy)
- **Practice**: Run GPS scanner on your own photos, understand what metadata exists

### Do (Weeks 3-8)
- **Find programs**: Filter Bugcrowd/HackerOne for programs accepting "Information Disclosure"
- **Test workflow**:
  1. Take photo with GPS on
  2. Upload to target site
  3. Download it back
  4. Scan with `gps_exif_scanner.py`
  5. If GPS present → Report it
- **Use VRT agent**: Before hunting, ask "What priority is EXIF geolocation?" to set expectations

### Teach (Week 9+)
- **Share findings**: Post in bug bounty communities about which sites strip EXIF (secure) vs don't (vulnerable)
- **Improve scripts**: Add more EXIF tags to check, better output formatting
- **Extend VRT agent**: Add more VRT categories, integrate with Bugcrowd's official VRT JSON

---

## 🛠️ Extending the Tools

### Add More VRT Categories

Edit `vrt_knowledge_agent.py`:

```python
VRT_CATEGORIES = {
    # ... existing categories ...

    "cryptographic_issues": {
        "p1": ["weak_encryption_algorithm"],
        "p2": ["insecure_random_number_generation"],
        "p3": ["missing_ssl_certificate_validation"],
        "description": "Flaws in cryptographic implementation",
        "impact": "Data interception, weak encryption",
        "mitigation": "Use modern crypto libraries, TLS 1.2+"
    }
}
```

### Add More EXIF Checks

Edit `gps_exif_scanner.py`:

```python
risky_tags = [
    'Make',
    'Model',
    'Software',
    # Add more:
    'SerialNumber',      # Camera serial number
    'LensModel',         # Lens identification
    'OwnerName',         # Camera owner name
    'CameraOwnerName'    # Nikon-specific owner field
]
```

---

## 🔒 Ethics & Legal

**Always follow these rules**:

1. **Only test authorized targets**:
   - Bug bounty programs with clear scope
   - Your own photos and websites
   - Intentionally vulnerable test sites

2. **Respect privacy**:
   - Don't upload other people's photos without permission
   - Don't share GPS coordinates you discover
   - Report responsibly using proper channels

3. **Never cause harm**:
   - Don't download thousands of images (DoS)
   - Don't weaponize GPS data against users
   - Use findings only for responsible disclosure

**Consequence of violations**: Account bans, legal action, criminal charges.

---

## 📊 Real-World Results

**Programs that STRIP EXIF** (✅ Secure):
- Twitter
- Facebook
- Instagram
- LinkedIn
- Reddit

**Programs where this bug has been found** (❌ Vulnerable):
- Small business websites
- Dating apps (critical - reveals home address)
- Real estate platforms
- Local marketplace apps
- Photography portfolio sites

**Typical bounty range for EXIF GPS leak**:
- P3 (user-facing, sensitive context like dating): $200-$500
- P4 (low-risk context like public forum): $50-$100

---

## 🎓 Resources

### Bug Bounty Platforms
- [Bugcrowd](https://bugcrowd.com) - Filter programs by "Information Disclosure"
- [HackerOne](https://hackerone.com) - Search for "EXIF" in disclosed reports
- [Intigriti](https://intigriti.com) - European programs

### Learning
- [Bugcrowd VRT](https://bugcrowd.com/vulnerability-rating-taxonomy) - Official taxonomy
- [EXIF.org](https://exif.org) - EXIF specification
- [PIL Documentation](https://pillow.readthedocs.io/) - Python image library

### Communities
- r/bugbounty - Reddit community
- Bug Bounty Forum - Discuss findings
- Twitter: @NahamSec, @STOK, @InsiderPhD

---

## 🏆 Success Metrics

**First Week**:
- [ ] Run GPS scanner on 10 of your own photos
- [ ] Ask VRT agent 5 different questions
- [ ] Understand what EXIF metadata is and why it matters

**First Month**:
- [ ] Test 5 bug bounty programs for EXIF leakage
- [ ] Submit first report (even if duplicate/N/A - learning experience)
- [ ] Use VRT agent to prioritize which bugs to hunt

**First Quarter**:
- [ ] Find first accepted EXIF vulnerability
- [ ] Earn first bounty ($50-$500)
- [ ] Extend scripts with your own improvements

---

## 🤝 Contributing

Improvements welcome:
- Add more VRT categories to the agent
- Improve EXIF scanner output formatting
- Add new Pythonista security tools
- Share bug bounty findings and lessons learned

---

**Happy hunting from your iPhone! 📱🎯**

*Learn one, do one, teach one.*
