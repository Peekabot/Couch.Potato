# HackerOne Report Template

**Report ID**: [H1-YYYY-MM-###]
**Program**: [Company Name]
**Submitted**: [YYYY-MM-DD]
**Status**: [New/Triaged/Resolved/Informative/Duplicate/N/A]
**Severity**: [Critical/High/Medium/Low/None]
**Bounty**: [$XXX or Pending]

---

## Summary

[One-line description that will appear in the report title]

---

## Description

[Detailed explanation of the vulnerability. HackerOne supports Markdown.]

The [vulnerable component] at [URL] is vulnerable to [type of vulnerability]. This allows an attacker to [describe what an attacker can do].

---

## Steps To Reproduce

1. Go to https://example.com/vulnerable-page
2. Enter the following in the [field name]:
   ```
   [payload]
   ```
3. Click [button/action]
4. Observe [the vulnerability behavior]

---

## Supporting Material/References

### Screenshots
- Screenshot 1: [Description]
- Screenshot 2: [Description]

### Video
[Link to video demonstration if applicable]

### HTTP Requests
```http
POST /api/endpoint HTTP/1.1
Host: example.com
Content-Type: application/json

{"parameter": "malicious_value"}
```

### Attachments
- PoC script: `poc_script.py`
- Burp Suite request file: `request.txt`

---

## Impact

[Detailed explanation of the potential impact]

**What can an attacker achieve:**
- [Impact point 1]
- [Impact point 2]
- [Impact point 3]

**Business/User Impact:**
[Explain how this affects the business or users]

---

## Recommended Fix

[Suggestions for remediation]

---

## System Information

- **Browser**: Chrome 120.0.6099.109
- **OS**: macOS Sonoma 14.2
- **Tested on**: [Date]
- **Affected Versions**: [If known]

---

## References

- [OWASP Reference]
- [CWE Reference]
- [Other relevant links]

---

## Timeline

- **YYYY-MM-DD**: Discovered
- **YYYY-MM-DD**: Reported
- **YYYY-MM-DD**: Triaged
- **YYYY-MM-DD**: Resolved
- **YYYY-MM-DD**: Bounty awarded

---

## HackerOne Specific Notes

**Weakness**: [Select from HackerOne taxonomy]
**Severity**: [Auto-calculated or manual]
**Asset**: [Affected asset from program scope]

**Vulnerability Type Options**:
- Cross-site Scripting (XSS)
- SQL Injection
- Cross-Site Request Forgery (CSRF)
- Server-Side Request Forgery (SSRF)
- Remote Code Execution (RCE)
- Authentication Bypass
- Authorization Issues
- Insecure Direct Object Reference (IDOR)
- Security Misconfiguration
- Sensitive Data Exposure
- XML External Entity (XXE)
- Broken Access Control
- etc.
