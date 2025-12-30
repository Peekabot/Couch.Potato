# Security Policy

## Reporting a Vulnerability

We take the security of Couch.Potato seriously. If you have discovered a security vulnerability, we appreciate your help in disclosing it to us responsibly.

### Bug Bounty Program

This project has an active bug bounty program. Security researchers who responsibly disclose vulnerabilities may be eligible for rewards based on the severity and impact of the issue.

For full bug bounty program details, see our [Bug Bounty Program](./BUG_BOUNTY.md).

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please use one of the following methods:

1. **Preferred**: Submit a private security advisory through GitHub
   - Go to the Security tab → Advisories → New draft security advisory
   - This allows for secure, private discussion before public disclosure

2. **Alternative**: Create a private issue using our [Security Vulnerability template](.github/ISSUE_TEMPLATE/security-vulnerability.md)
   - Mark the issue as private/confidential if possible

3. **Email**: If you prefer email communication, contact the maintainers directly through GitHub

### What to Include

When reporting a vulnerability, please include:

- **Type of vulnerability** (e.g., XSS, injection, authentication bypass)
- **Full paths of source file(s)** related to the vulnerability
- **Location of the affected code** (line numbers if possible)
- **Step-by-step instructions** to reproduce the issue
- **Proof-of-concept or exploit code** (if applicable)
- **Impact assessment** - what an attacker could achieve
- **Suggested fix** (if you have one)

### Response Timeline

- **Initial Response**: Within 48 hours of submission
- **Status Update**: Within 7 days with our assessment and next steps
- **Fix Timeline**: Depends on severity
  - Critical: 7-14 days
  - High: 14-30 days
  - Medium: 30-60 days
  - Low: 60-90 days

### Safe Harbor

We support safe harbor for security researchers who:

- Make a good faith effort to avoid privacy violations and data destruction
- Only interact with accounts you own or with explicit permission
- Do not exploit the vulnerability beyond the minimum necessary to demonstrate it
- Wait for us to address the issue before public disclosure
- Do not perform attacks that could harm reliability/integrity of our services

Researchers who follow these guidelines will not face legal action, and we will work with you on appropriate disclosure timing.

### Scope

Please see our [Bug Bounty Scope](./BUG_BOUNTY.md#scope) for in-scope and out-of-scope items.

### Recognition

We maintain a [Security Hall of Fame](./SECURITY_HALL_OF_FAME.md) to recognize security researchers who have helped make this project more secure.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| Older   | :x:                |

Currently, only the latest version receives security updates.
