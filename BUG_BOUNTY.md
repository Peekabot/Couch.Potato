# Bug Bounty Program

Welcome to the Couch.Potato Bug Bounty Program! We value the security community's contributions and offer rewards for responsibly disclosed security vulnerabilities.

## Overview

This bug bounty program is designed to encourage security researchers to help us identify and fix security vulnerabilities in the Couch.Potato interactive ragdoll physics application.

## Rewards

Rewards are based on the severity and impact of the vulnerability:

| Severity | Reward Range | Description |
|----------|--------------|-------------|
| **Critical** | $500 - $2,000 | Remote code execution, authentication bypass, data breach |
| **High** | $250 - $500 | XSS with significant impact, SQL injection, CSRF on sensitive actions |
| **Medium** | $100 - $250 | XSS (stored), insecure direct object references, session issues |
| **Low** | $50 - $100 | Information disclosure, clickjacking, minor security misconfigurations |
| **Informational** | Recognition | Security best practices, code quality improvements |

**Note**: Exact reward amounts are determined by our security team based on:
- Severity and impact of the vulnerability
- Quality of the report and steps to reproduce
- Suggested fixes or patches provided

## Scope

### In-Scope Assets

The following components are within scope for this bug bounty program:

- **Main Application**: index.html and all associated JavaScript code
- **Physics Engine Integration**: Matter.js usage and implementation
- **Client-Side Security**: XSS, DOM manipulation, CSP bypasses
- **User Input Handling**: Any interactive elements and controls
- **Session/State Management**: LocalStorage, cookies, session handling
- **Third-Party Dependencies**: Vulnerabilities in CDN-loaded libraries

### In-Scope Vulnerability Types

We're particularly interested in:

- **Cross-Site Scripting (XSS)** - Stored, Reflected, DOM-based
- **Cross-Site Request Forgery (CSRF)**
- **Client-Side Injection** - HTML, JavaScript, CSS
- **Authentication/Authorization Issues**
- **Session Management Flaws**
- **Insecure Data Storage** - LocalStorage, SessionStorage
- **Cryptographic Vulnerabilities**
- **Business Logic Flaws**
- **Content Security Policy Bypasses**
- **Clickjacking**
- **Open Redirects** (with demonstrable security impact)
- **DOM Clobbering**
- **Prototype Pollution**

### Out-of-Scope

The following are **NOT** eligible for rewards:

- **Denial of Service (DoS/DDoS)** attacks
- **Social Engineering** attacks against users or team members
- **Physical Security** testing
- **Spam or Social Network Issues**
- **Reports from Automated Tools** without validation
- **Third-Party Platform Issues** (GitHub, CDN providers)
- **Issues Already Known** or publicly disclosed
- **Theoretical Vulnerabilities** without proof of exploitability
- **Browser-Specific Issues** not caused by our code
- **Issues Requiring Unlikely User Interaction**
- **Self-XSS** without chaining to achieve greater impact
- **Best Practice Violations** without security impact
- **Rate Limiting** on non-sensitive functionality
- **Missing Security Headers** without demonstrable impact

## Submission Guidelines

### Before You Submit

1. **Check for Duplicates**: Review existing reports to avoid duplicates
2. **Verify Impact**: Ensure the vulnerability has real security impact
3. **Test Responsibly**: Only test against your own accounts/data
4. **Document Thoroughly**: Provide clear reproduction steps

### Report Requirements

A quality vulnerability report should include:

```markdown
## Vulnerability Summary
Brief description of the vulnerability

## Severity
Your assessment: Critical/High/Medium/Low

## Vulnerability Type
E.g., XSS, CSRF, etc.

## Affected Component
Specific file, function, or feature affected

## Reproduction Steps
1. Step-by-step instructions
2. Include specific URLs, parameters, payloads
3. Screenshots or video if helpful

## Proof of Concept
Code, curl commands, or demonstration

## Impact Analysis
What can an attacker achieve with this vulnerability?

## Suggested Fix
(Optional) How to remediate the issue

## References
Any relevant CVEs, articles, or documentation
```

### Submission Process

1. **Report** the vulnerability via our [Security Policy](./SECURITY.md)
2. **Wait** for our initial response (within 48 hours)
3. **Collaborate** with our team to verify and fix the issue
4. **Disclosure** - Coordinate public disclosure timing with our team
5. **Reward** - Receive your bounty after the fix is deployed

## Rules of Engagement

### DO:
- ✅ Test only against your own accounts and data
- ✅ Provide detailed, actionable reports
- ✅ Allow reasonable time for fixes before disclosure
- ✅ Follow responsible disclosure practices
- ✅ Report one vulnerability per submission
- ✅ Be respectful and professional

### DON'T:
- ❌ Exploit the vulnerability for malicious purposes
- ❌ Access, modify, or delete other users' data
- ❌ Perform DoS/DDoS attacks
- ❌ Spam or social engineer team members
- ❌ Publicly disclose before coordinated disclosure
- ❌ Violate any laws or regulations
- ❌ Run automated scanners without permission

## Legal

### Safe Harbor

We commit not to pursue legal action against researchers who:
- Act in good faith
- Follow these program rules
- Report vulnerabilities responsibly
- Avoid privacy violations and data destruction

### Disclosure Policy

- **Private Disclosure**: Initially report vulnerabilities privately
- **Coordinated Disclosure**: Work with us on timing public disclosure
- **Credit**: We'll publicly credit you (if desired) when disclosing fixes
- **Embargo Period**: Typically 90 days or until fix deployment

### Eligibility

- Must be 18+ or have parental consent
- Cannot be a current or former employee/contractor
- Cannot be located in a country under U.S. sanctions
- Must comply with all applicable laws

## Recognition

### Security Hall of Fame

Researchers who responsibly disclose valid vulnerabilities will be recognized in our [Security Hall of Fame](./SECURITY_HALL_OF_FAME.md) (unless anonymity is requested).

### Public Thanks

We'll publicly thank contributors when announcing security fixes (with permission).

## FAQ

**Q: How long does the review process take?**
A: Initial response within 48 hours. Full assessment within 7 days.

**Q: When do I receive payment?**
A: After the vulnerability is verified, fixed, and deployed to production.

**Q: Can I test in production?**
A: Yes, but only non-destructive testing. Do not impact other users.

**Q: What if I find the same bug in multiple places?**
A: Report them together. We may treat as a single issue depending on root cause.

**Q: Can I use automated scanners?**
A: Manual testing preferred. Automated tools must be carefully configured to avoid DoS.

**Q: What about security improvements without vulnerabilities?**
A: We appreciate suggestions! Submit via GitHub issues (not bug bounty).

## Contact

For questions about the bug bounty program:
- Create a discussion in the GitHub repository
- Reference our [Security Policy](./SECURITY.md) for reporting

## Program Updates

We may modify this program at any time. Check back regularly for updates.

**Last Updated**: 2025-12-30

---

**Happy Hunting! 🔍🛡️**

Thank you for helping make Couch.Potato more secure!
