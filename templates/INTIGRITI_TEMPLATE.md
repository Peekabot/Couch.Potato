# Intigriti Report Template

**Report ID**: [INTG-YYYY-MM-DD-###]
**Program**: [Company Name]
**Submitted**: [YYYY-MM-DD]
**Status**: [Pending/Triaged/Accepted/Rejected/Duplicate]
**Severity**: [Critical/High/Medium/Low/Info]
**Bounty**: [$XXX or Pending]

---

## Title
**[Brief, descriptive title of the vulnerability]**

Example: "Reflected XSS in search parameter allows account takeover"

---

## Summary
Brief 2-3 sentence overview of the vulnerability.

*What is it? Where is it? What's the impact?*

---

## Severity Assessment

**CVSS Score**: [Calculate at https://www.first.org/cvss/calculator/3.1]
**My Assessment**: [Critical/High/Medium/Low]

**Justification**:
- **Impact**: [Account takeover / Data breach / etc.]
- **Exploitability**: [Easy / Medium / Hard]
- **User Interaction**: [Required / Not required]

---

## Vulnerability Details

### Vulnerability Type
- [ ] XSS (Cross-Site Scripting)
- [ ] SQL Injection
- [ ] CSRF
- [ ] IDOR
- [ ] Authentication Bypass
- [ ] Authorization Issues
- [ ] Server-Side Request Forgery (SSRF)
- [ ] Remote Code Execution (RCE)
- [ ] Open Redirect
- [ ] Other: ___________

### Affected Endpoint/Component
```
URL: https://example.com/vulnerable/endpoint
Parameter: search
Method: GET/POST
```

### CWE Reference
[CWE-XX: Vulnerability Name](https://cwe.mitre.org/data/definitions/XX.html)

---

## Steps to Reproduce

**Prerequisites**:
- Account with [specific role/permissions]
- Access to [specific feature]

**Step-by-step reproduction**:

1. Navigate to `https://example.com/page`
2. Enter the following payload in the search field:
   ```
   <script>alert(document.domain)</script>
   ```
3. Click "Search"
4. Observe that the JavaScript executes in the browser context

**Expected Result**: Input should be sanitized
**Actual Result**: JavaScript code executes

---

## Proof of Concept

### Request
```http
GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Cookie: session=abc123
```

### Response
```http
HTTP/1.1 200 OK
Content-Type: text/html

<html>
<body>
  <h1>Search Results for: <script>alert(1)</script></h1>
</body>
</html>
```

### Video/Screenshots
[Attach or link to visual proof]

### PoC Code
```javascript
// If applicable, include exploit code
// Saved in: poc/INTG-YYYY-MM-DD-###/
```

---

## Impact

**What can an attacker do?**
- Steal session cookies and hijack user accounts
- Perform actions on behalf of the victim
- Deface the website
- Redirect users to malicious sites
- Steal sensitive information

**Business Impact**:
- User trust compromised
- Data breach potential
- Regulatory compliance issues (GDPR, etc.)

**Attack Scenario**:
1. Attacker crafts malicious link with XSS payload
2. Victim clicks link (via phishing, social media, etc.)
3. Payload executes in victim's browser
4. Attacker steals session cookie and takes over account
5. Attacker accesses sensitive data or performs unauthorized actions

---

## Recommended Fix

### Short-term Mitigation
- Implement input validation and output encoding
- Use Content Security Policy (CSP)
- Sanitize user input before reflecting it

### Long-term Solution
```javascript
// Example fix using DOMPurify
const clean = DOMPurify.sanitize(userInput);
element.textContent = clean; // Use textContent instead of innerHTML
```

### Code Changes
- File: `/app/controllers/search_controller.js`
- Line: 42
- Change from: `innerHTML` to `textContent`
- Add: Input validation library

---

## References

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [CWE-79: Improper Neutralization of Input](https://cwe.mitre.org/data/definitions/79.html)
- Similar vulnerabilities: [links if applicable]

---

## Additional Notes

- Tested on: Chrome 120.0.6099.109, Firefox 121.0
- Other affected endpoints: [list if multiple]
- Related findings: [if part of a chain]

---

## Timeline

- **2025-XX-XX**: Vulnerability discovered
- **2025-XX-XX**: Reported to Intigriti
- **2025-XX-XX**: Triaged by Intigriti
- **2025-XX-XX**: Accepted by program
- **2025-XX-XX**: Fixed by company
- **2025-XX-XX**: Bounty awarded

---

## Checklist Before Submission

- [ ] Tested and confirmed vulnerability exists
- [ ] Checked for duplicates
- [ ] Clear reproduction steps provided
- [ ] Impact clearly explained
- [ ] Screenshots/video included
- [ ] Suggested fix provided
- [ ] Followed responsible disclosure
- [ ] Only tested on authorized scope
- [ ] No user data compromised during testing
- [ ] Report is clear and professional
