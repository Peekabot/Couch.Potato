# Bugcrowd Report Template

**Report ID**: [BC-YYYY-MM-###]
**Program**: [Company Name]
**Submitted**: [YYYY-MM-DD]
**Status**: [Submitted/Triaged/Accepted/Rejected]
**Priority**: [P1/P2/P3/P4/P5]
**Bounty**: [$XXX or Pending]

---

## Title
[Clear, concise title following Bugcrowd format]

Example: "[Component] Vulnerability Type via [method/parameter]"

---

## Vulnerability Description

### Overview
[Brief description of the vulnerability]

### Target Information
- **URL**: https://example.com/path
- **Asset Type**: [Web App / API / Mobile / Cloud / etc.]
- **Component**: [Specific feature or endpoint]
- **Parameter**: [Vulnerable parameter]

---

## Bugcrowd VRT Classification

**Category**: [From Bugcrowd VRT]
**Subcategory**: [Specific vulnerability type]

Reference: [Bugcrowd VRT Link](https://bugcrowd.com/vulnerability-rating-taxonomy)

Example categories:
- Server Security Misconfiguration
- Broken Authentication and Session Management
- Cross-Site Scripting (XSS)
- Insecure Direct Object Reference (IDOR)
- SQL Injection
- etc.

---

## Reproduction Steps

**Environment:**
- Browser: [Browser and version]
- OS: [Operating system]
- Tools used: [If applicable]

**Prerequisites:**
- [Any required setup]

**Steps:**
1. [Step 1]
2. [Step 2]
3. [Step 3]
4. [Result]

---

## Proof of Concept

### Request
```http
[HTTP request showing the vulnerability]
```

### Response
```http
[HTTP response showing the vulnerability]
```

### Exploit Code
```python
# PoC script (if applicable)
# Saved in poc/BC-YYYY-MM-###/
```

### Evidence
- Screenshot 1: [Description]
- Screenshot 2: [Description]
- Video: [Link if applicable]

---

## Impact Assessment

**Bugcrowd Priority Mapping:**

| Priority | CVSS | Description |
|----------|------|-------------|
| P1 | 9.0-10.0 | Critical impact to business/users |
| P2 | 7.0-8.9 | High impact |
| P3 | 4.0-6.9 | Medium impact |
| P4 | 0.1-3.9 | Low impact |
| P5 | 0.0 | Informational |

**My Assessment**: P[X]

**Impact Details:**
[Explain the real-world impact of this vulnerability]

**Attack Scenario:**
1. [Attacker action 1]
2. [Attacker action 2]
3. [Outcome]

---

## Remediation Recommendations

### Immediate Fix
[Quick mitigation steps]

### Long-term Solution
[Proper fix implementation]

### Code Example
```javascript
// Example of secure implementation
```

---

## Additional Information

### Affected Endpoints
- [List all affected endpoints if multiple]

### Similar Issues
- [Reference any related findings]

### Testing Notes
- [Any important context about testing]

---

## References

- Bugcrowd VRT: [Link]
- OWASP: [Relevant OWASP page]
- CWE: [CWE reference]
- Other: [Additional references]

---

## Compliance Impact

**Relevant Standards:**
- [ ] PCI DSS
- [ ] HIPAA
- [ ] GDPR
- [ ] SOC 2
- [ ] ISO 27001

[Explain if applicable]

---

## Timeline

- **Discovery**: YYYY-MM-DD
- **Submission**: YYYY-MM-DD
- **Triage**: YYYY-MM-DD
- **Resolution**: YYYY-MM-DD
- **Payout**: YYYY-MM-DD

---

## Submission Checklist

- [ ] Vulnerability is within program scope
- [ ] Clear reproduction steps provided
- [ ] Impact clearly articulated
- [ ] Screenshots/video included
- [ ] Proper VRT classification selected
- [ ] Tested only on authorized targets
- [ ] No duplicate submission
- [ ] Professional and respectful tone
- [ ] Remediation suggestions provided
