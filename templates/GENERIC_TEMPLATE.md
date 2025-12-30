# Generic Vulnerability Report Template

**Report ID**: [GEN-YYYY-MM-DD-###]
**Platform/Program**: [Platform/Company Name]
**Submitted**: [YYYY-MM-DD]
**Status**: [Pending/Accepted/Rejected]
**Severity**: [Critical/High/Medium/Low/Info]
**Bounty**: [$XXX or Pending]

---

## Executive Summary

[One paragraph overview for non-technical stakeholders]

---

## Vulnerability Details

### Title
[Descriptive title]

### Type
[Vulnerability classification]

### Severity
- **CVSS Score**: [X.X]
- **Severity Rating**: [Critical/High/Medium/Low]

### Affected Assets
- **Target**: [URL/Application/API]
- **Component**: [Specific feature]
- **Endpoint**: [Specific endpoint/path]
- **Parameter**: [Vulnerable parameter]

### CWE/CVE References
- **CWE**: [CWE-XXX: Name]
- **CVE**: [If applicable]

---

## Technical Description

[Detailed technical explanation of the vulnerability]

**Root Cause:**
[Explain why the vulnerability exists]

**Attack Vector:**
[Explain how the vulnerability can be exploited]

---

## Proof of Concept

### Prerequisites
- [Required access/permissions]
- [Required tools]
- [Required setup]

### Step-by-Step Reproduction

1. **Step 1**: [Detailed instruction]
   ```bash
   [Command or code if applicable]
   ```

2. **Step 2**: [Detailed instruction]
   ```http
   [HTTP request if applicable]
   ```

3. **Step 3**: [Detailed instruction]

4. **Expected Result**: [What should happen]
   **Actual Result**: [What actually happens]

### Evidence

**Screenshots:**
- [Screenshot 1 description]
- [Screenshot 2 description]

**Video Proof:**
- [Link or file]

**Request/Response:**
```http
[Include relevant HTTP traffic]
```

**Exploit Code:**
```python
# PoC code (sanitized for responsible disclosure)
# Full code in: poc/GEN-YYYY-MM-DD-###/
```

---

## Impact Analysis

### Security Impact
[Describe the security implications]

### Business Impact
- **Confidentiality**: [Impact on data confidentiality]
- **Integrity**: [Impact on data integrity]
- **Availability**: [Impact on service availability]

### User Impact
[How does this affect end users?]

### Potential Attack Scenarios

**Scenario 1:**
1. [Attacker action]
2. [System response]
3. [Outcome]

**Scenario 2:**
[Additional scenarios if applicable]

### Exploitability
- **Skill Level Required**: [Low/Medium/High]
- **Attack Complexity**: [Low/Medium/High]
- **User Interaction**: [Required/Not Required]
- **Privileges Required**: [None/Low/High]

---

## Remediation

### Recommended Fix

**Priority**: [Immediate/High/Medium/Low]

**Short-term Mitigation:**
- [Temporary fix or workaround]

**Long-term Solution:**
- [Permanent fix]

### Implementation Example

```javascript
// Before (vulnerable code)
const userInput = req.query.search;
res.send(`<h1>Results for: ${userInput}</h1>`);

// After (secure code)
const userInput = validator.escape(req.query.search);
res.send(`<h1>Results for: ${userInput}</h1>`);
```

### Testing the Fix
[How to verify the fix works]

---

## References

### Standards & Guidelines
- [OWASP reference]
- [NIST reference]
- [Industry standard]

### Similar Vulnerabilities
- [CVE or public disclosure]
- [Related research]

### Tools Used
- [Tool 1]
- [Tool 2]

---

## Testing Environment

- **Date Tested**: [YYYY-MM-DD]
- **Browser/Client**: [Details]
- **Operating System**: [Details]
- **Tools Used**: [List]
- **Network**: [If relevant]

---

## Disclosure Timeline

| Date | Event |
|------|-------|
| YYYY-MM-DD | Vulnerability discovered |
| YYYY-MM-DD | Initial report submitted |
| YYYY-MM-DD | Acknowledged by vendor |
| YYYY-MM-DD | Triaged/validated |
| YYYY-MM-DD | Fix deployed |
| YYYY-MM-DD | Public disclosure (if applicable) |
| YYYY-MM-DD | Bounty awarded |

---

## Additional Notes

### Scope Verification
- [ ] Confirmed target is in scope
- [ ] Reviewed program rules
- [ ] Obtained necessary permissions

### Testing Notes
[Any important context about your testing process]

### Limitations
[Any limitations in your testing or PoC]

### Follow-up Items
- [Any additional testing needed]
- [Related areas to investigate]

---

## Communication Log

**2025-XX-XX**: [Communication with vendor]
**2025-XX-XX**: [Follow-up response]

---

## Attachments

1. [List all attachments]
2. [PoC scripts]
3. [Screenshots]
4. [Videos]
5. [HTTP traffic captures]

---

## Researcher Information

**Tested By**: [Your name/handle]
**Contact**: [How to reach you]
**PGP Key**: [If applicable]

---

## Legal & Ethics

- [ ] Testing authorized under bug bounty program
- [ ] No user data accessed or compromised
- [ ] No service disruption caused
- [ ] Responsible disclosure followed
- [ ] All testing within scope
- [ ] Proper authorization obtained

---

**Report prepared by**: [Your name]
**Report date**: [YYYY-MM-DD]
