# Bug Bounty Researcher Checklist

Quick reference guide for security researchers testing Couch.Potato.

## Before You Start

- [ ] Read the [Bug Bounty Program](./BUG_BOUNTY.md) rules
- [ ] Review the [Security Policy](./SECURITY.md)
- [ ] Check existing security reports for duplicates
- [ ] Understand the scope (what's in and out)
- [ ] Set up a test environment (local copy)

## Testing Checklist

### Client-Side Vulnerabilities

#### Cross-Site Scripting (XSS)
- [ ] Test all user inputs for DOM-based XSS
- [ ] Check URL parameters and hash fragments
- [ ] Test localStorage/sessionStorage manipulation
- [ ] Check for reflected XSS in error messages
- [ ] Test innerHTML, eval(), and other dangerous sinks
- [ ] Check Content Security Policy bypasses

#### Injection Attacks
- [ ] Test for HTML injection
- [ ] Check for JavaScript injection
- [ ] Test CSS injection attacks
- [ ] Look for DOM clobbering opportunities
- [ ] Test prototype pollution

#### CSRF & Clickjacking
- [ ] Test for CSRF on state-changing operations
- [ ] Check X-Frame-Options and frame busting
- [ ] Test for clickjacking vulnerabilities

#### Session & Storage
- [ ] Review localStorage security
- [ ] Check sessionStorage handling
- [ ] Test cookie security (if applicable)
- [ ] Look for sensitive data exposure in storage

### Logic & Business Flaws
- [ ] Test physics manipulation for unintended behavior
- [ ] Check for race conditions
- [ ] Test boundary conditions
- [ ] Look for privilege escalation opportunities

### Third-Party Dependencies
- [ ] Check Matter.js version for known CVEs
- [ ] Test CDN integrity (SRI checks)
- [ ] Look for supply chain vulnerabilities
- [ ] Check for outdated libraries

### Information Disclosure
- [ ] Look for exposed sensitive information
- [ ] Check source code comments
- [ ] Test error messages for information leakage
- [ ] Review console logs

### Open Redirects
- [ ] Test all URL handling for open redirects
- [ ] Check for JavaScript-based redirects

## Reporting Checklist

Before submitting your report:

- [ ] **Verified** the vulnerability exists and is exploitable
- [ ] **Documented** clear reproduction steps
- [ ] **Created** a proof-of-concept (PoC)
- [ ] **Assessed** the severity and impact
- [ ] **Checked** for duplicates
- [ ] **Followed** responsible disclosure practices
- [ ] **Tested** only on your own accounts/data
- [ ] **Included** suggested fixes (optional but appreciated)

## Report Quality Checklist

Your report should include:

- [ ] Clear vulnerability summary
- [ ] Severity assessment (Critical/High/Medium/Low)
- [ ] Vulnerability type (XSS, CSRF, etc.)
- [ ] Affected component (file, line number)
- [ ] Step-by-step reproduction steps
- [ ] Proof-of-concept code or demonstration
- [ ] Impact analysis
- [ ] Screenshots or video (if helpful)
- [ ] Suggested fix (optional)
- [ ] Environment details (browser, version, URL)

## Common Testing Payloads

### XSS Payloads
```javascript
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
javascript:alert(document.cookie)
<svg onload=alert(1)>
```

### DOM-based XSS
```javascript
location.hash = '<img src=x onerror=alert(1)>'
location.search = '?x=<script>alert(1)</script>'
```

### Prototype Pollution
```javascript
Object.prototype.polluted = 'Yes'
__proto__[polluted]=Yes
```

## Tools to Consider

- **Manual Testing** (preferred for quality)
- **Browser DevTools** (Console, Network, Storage tabs)
- **Burp Suite** (for request manipulation)
- **OWASP ZAP** (web app scanner)
- **DOM Invader** (DOM XSS testing)
- **Retire.js** (check for vulnerable libraries)

## Severity Guidelines

### Critical ($500-$2,000)
- Remote code execution
- Authentication bypass
- Direct data breach
- Full account takeover

### High ($250-$500)
- Stored XSS with significant impact
- SQL injection (if applicable)
- CSRF on sensitive actions
- Authorization bypass

### Medium ($100-$250)
- Reflected/DOM XSS
- Insecure direct object references
- Session fixation
- Significant information disclosure

### Low ($50-$100)
- Minor information disclosure
- Clickjacking
- Security misconfigurations with limited impact

## Best Practices

✅ **DO:**
- Test responsibly
- Report one vulnerability per submission
- Provide detailed, actionable reports
- Follow up on questions from the team
- Be patient with response times

❌ **DON'T:**
- Run automated scanners aggressively
- Test against production users
- Access other users' data
- Perform DoS attacks
- Disclose publicly before coordinated disclosure
- Submit low-quality automated reports

## Quick Links

- [Bug Bounty Program](./BUG_BOUNTY.md) - Full program details
- [Security Policy](./SECURITY.md) - Reporting guidelines
- [Issue Template](./.github/ISSUE_TEMPLATE/security-vulnerability.md) - Report format
- [Hall of Fame](./SECURITY_HALL_OF_FAME.md) - Recognized researchers

## Questions?

- Review the [FAQ in Bug Bounty Program](./BUG_BOUNTY.md#faq)
- Open a GitHub Discussion for non-sensitive questions
- Follow the reporting process for vulnerability questions

---

**Happy hunting! 🔍🐛**

Remember: Quality over quantity. A single well-researched, high-impact vulnerability is worth more than many low-quality reports.
