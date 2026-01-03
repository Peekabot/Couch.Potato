# Plaid API Security Tester

A comprehensive security testing framework for Plaid API implementations, designed for bug bounty hunting and authorized security research.

## Overview

This toolkit provides automated security testing for Plaid API integrations, covering common vulnerabilities including:

- Authentication & Authorization flaws
- IDOR (Insecure Direct Object References)
- Rate limiting & DoS vulnerabilities
- Input validation issues (SQL injection, XSS, XXE)
- Account linking security
- Transaction data manipulation
- Webhook security (SSRF, injection)
- Token management vulnerabilities
- SSL/TLS configuration issues

## Features

- **Automated Testing:** Run comprehensive security tests with a single command
- **Detailed Reporting:** JSON reports with vulnerability severity ratings
- **Modular Design:** Run specific test categories independently
- **Educational:** Includes detailed test case documentation
- **Sandbox Safe:** Designed for Plaid Sandbox environment
- **Extensible:** Easy to add custom test cases

## Installation

### Prerequisites

- Python 3.7+
- pip package manager
- Plaid sandbox account (free at https://dashboard.plaid.com/signup)

### Setup

1. Clone the repository:
```bash
cd plaid-api-tester
```

2. Install dependencies:
```bash
pip3 install -r requirements.txt
```

3. Configure your credentials:
```bash
cp config.json.example config.json
```

4. Edit `config.json` with your Plaid sandbox credentials:
```json
{
  "base_url": "https://sandbox.plaid.com",
  "client_id": "your_sandbox_client_id",
  "secret": "your_sandbox_secret",
  "access_token": "access-sandbox-xxx",
  "webhook_url": "https://yourdomain.com/webhook"
}
```

## Usage

### Quick Start

Run all security tests:
```bash
python3 plaid_tester.py
```

### Specific Test Categories

Run individual test suites:

```bash
# Authentication testing
python3 plaid_tester.py -t auth

# IDOR vulnerability testing
python3 plaid_tester.py -t idor

# Rate limiting tests
python3 plaid_tester.py -t rate

# Account linking security
python3 plaid_tester.py -t linking

# Transaction manipulation tests
python3 plaid_tester.py -t transaction

# Input validation (SQL injection, XSS)
python3 plaid_tester.py -t input

# Webhook security (SSRF)
python3 plaid_tester.py -t webhook

# SSL/TLS configuration
python3 plaid_tester.py -t ssl
```

### Custom Configuration

Specify a different config file:
```bash
python3 plaid_tester.py -c my_config.json
```

### Custom Output Location

Specify report output location:
```bash
python3 plaid_tester.py -o reports/my_custom_report.json
```

## Configuration Options

### config.json Structure

```json
{
  "base_url": "https://sandbox.plaid.com",
  "client_id": "your_plaid_client_id",
  "secret": "your_plaid_secret",
  "access_token": "access-sandbox-token",
  "public_token": "public-sandbox-token",
  "webhook_url": "https://yourdomain.com/plaid/webhook",
  "environment": "sandbox",
  "test_settings": {
    "rate_limit_test_requests": 100,
    "timeout_seconds": 10,
    "enable_verbose_logging": true
  },
  "endpoints_to_test": [
    "/item/get",
    "/accounts/get",
    "/transactions/get",
    "/auth/get"
  ]
}
```

### Configuration Parameters

| Parameter | Description | Required |
|-----------|-------------|----------|
| `base_url` | Plaid API base URL (sandbox/production) | Yes |
| `client_id` | Your Plaid client ID | Yes |
| `secret` | Your Plaid secret key | Yes |
| `access_token` | Valid access token for testing | No |
| `webhook_url` | Webhook URL for webhook tests | No |
| `environment` | Environment (sandbox/production) | Yes |

## Test Categories

### 1. Authentication Testing

Tests for:
- Weak credential acceptance
- Credential enumeration
- Brute force protection
- Session fixation

**Command:** `python3 plaid_tester.py -t auth`

### 2. IDOR Testing

Tests for:
- Access token manipulation
- Account ID manipulation
- Item ID enumeration
- Unauthorized data access

**Command:** `python3 plaid_tester.py -t idor`

### 3. Rate Limiting

Tests for:
- API rate limit enforcement
- Per-endpoint rate limits
- Rate limit bypass attempts
- DoS protection

**Command:** `python3 plaid_tester.py -t rate`

### 4. Input Validation

Tests for:
- SQL injection
- Cross-Site Scripting (XSS)
- Path traversal
- Command injection
- XXE (XML External Entity)

**Command:** `python3 plaid_tester.py -t input`

### 5. Account Linking

Tests for:
- Public token reuse
- Expired token acceptance
- Link token manipulation
- Cross-account linking

**Command:** `python3 plaid_tester.py -t linking`

### 6. Transaction Security

Tests for:
- Historical data access limits
- Transaction manipulation
- Unauthorized account access
- Pagination manipulation

**Command:** `python3 plaid_tester.py -t transaction`

### 7. Webhook Security

Tests for:
- SSRF (Server-Side Request Forgery)
- Webhook verification bypass
- Webhook injection
- Open redirects

**Command:** `python3 plaid_tester.py -t webhook`

### 8. SSL/TLS Security

Tests for:
- HSTS header presence
- Certificate validation
- TLS version enforcement
- Weak cipher suites

**Command:** `python3 plaid_tester.py -t ssl`

## Understanding Reports

### Report Format

Reports are generated in JSON format:

```json
{
  "timestamp": "2026-01-03T10:30:00",
  "target": "https://sandbox.plaid.com",
  "total_tests": 45,
  "summary": {
    "CRITICAL": 2,
    "HIGH": 5,
    "MEDIUM": 8,
    "LOW": 3,
    "INFO": 27,
    "VULNERABLE": 2,
    "PASSED": 40,
    "ERROR": 3
  },
  "results": [...]
}
```

### Severity Levels

| Severity | Description | Action Required |
|----------|-------------|-----------------|
| **CRITICAL** | Immediate risk of data breach or account takeover | Report immediately |
| **HIGH** | Significant security risk | Report within 24 hours |
| **MEDIUM** | Moderate security concern | Document and report |
| **LOW** | Minor security issue | Note for improvement |
| **INFO** | Informational finding | No immediate action |

### Test Result Statuses

- **VULNERABLE:** Security vulnerability detected
- **PASSED:** Security control functioning correctly
- **ERROR:** Test encountered an error
- **SKIPPED:** Test was not applicable or not configured

## Example Output

```
==================================================
PLAID API SECURITY TESTER
==================================================
Target: https://sandbox.plaid.com
Started: 2026-01-03 10:30:00
==================================================

=== Testing Authentication ===
[INFO] Valid Credentials: PASSED
  └─ Authentication successful with valid credentials
[INFO] Invalid Credentials Rejection: PASSED
  └─ Invalid credentials properly rejected

=== Testing IDOR Vulnerabilities ===
[CRITICAL] IDOR Test: access-sandbox-invalid: VULNERABLE
  └─ Unauthorized access with token: access-sandbox-invalid

==================================================
SECURITY TEST SUMMARY
==================================================
Total Tests: 45

By Severity:
  CRITICAL: 2
  HIGH: 5
  MEDIUM: 8
  LOW: 3
  INFO: 27

By Status:
  VULNERABLE: 2
  PASSED: 40
  ERROR: 3
==================================================

[+] Report saved to: reports/plaid_security_test_20260103_103000.json
```

## Bug Bounty Workflow

### 1. Testing Phase

```bash
# Run comprehensive tests
python3 plaid_tester.py -c config.json

# Review generated report
cat reports/plaid_security_test_*.json
```

### 2. Vulnerability Validation

- Verify the vulnerability is reproducible
- Test impact and exploitability
- Document proof of concept
- Capture screenshots/logs

### 3. Reporting

Use the bug bounty report templates in `/templates`:

```bash
# Choose appropriate template
cp ../templates/GENERIC_TEMPLATE.md ../reports/plaid_vulnerability_report.md

# Fill in vulnerability details
# - Title
# - Severity
# - Description
# - Steps to reproduce
# - Impact
# - Remediation
```

### 4. Responsible Disclosure

1. **Never test production without authorization**
2. Check if Plaid has a bug bounty program
3. Follow responsible disclosure timeline (typically 90 days)
4. Document all communication
5. Do not publicly disclose until resolved

## Advanced Usage

### Custom Test Development

Add custom tests by extending the `PlaidAPITester` class:

```python
def test_custom_vulnerability(self):
    """Test for custom vulnerability."""
    print("\n=== Testing Custom Vulnerability ===")

    # Your test logic here
    response = requests.post(
        urljoin(self.base_url, "/custom/endpoint"),
        json={"test": "payload"}
    )

    if response.status_code == 200:
        self.log_result(
            "Custom Test",
            "VULNERABLE",
            "HIGH",
            "Description of vulnerability"
        )
```

### Integration with CI/CD

Run tests in continuous integration:

```yaml
# .github/workflows/security-test.yml
name: Security Testing
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run Plaid Security Tests
        run: |
          cd plaid-api-tester
          pip3 install -r requirements.txt
          python3 plaid_tester.py -c config.json
```

## Directory Structure

```
plaid-api-tester/
├── plaid_tester.py          # Main testing script
├── config.json.example      # Configuration template
├── config.json              # Your credentials (gitignored)
├── requirements.txt         # Python dependencies
├── README.md                # This file
├── tests/
│   └── TEST_CASES.md       # Detailed test case documentation
└── reports/                # Generated test reports
    └── *.json              # Timestamped report files
```

## Security Best Practices

### For Testing

1. **Always use Sandbox:** Never test production systems without explicit authorization
2. **Respect Rate Limits:** Avoid aggressive testing that could disrupt services
3. **Secure Credentials:** Never commit `config.json` with real credentials
4. **Document Everything:** Keep detailed logs of all testing activities
5. **Follow Responsible Disclosure:** Report vulnerabilities through proper channels

### For Development

1. **Input Validation:** Always validate and sanitize user input
2. **Authentication:** Implement strong authentication mechanisms
3. **Authorization:** Verify user permissions for every request
4. **Rate Limiting:** Implement appropriate rate limits
5. **Logging:** Log security-relevant events (without sensitive data)
6. **Encryption:** Use TLS 1.2+ for all API communications

## Troubleshooting

### Common Issues

**Issue:** `Authentication failed: 401`
**Solution:** Verify your `client_id` and `secret` in `config.json`

**Issue:** `Connection timeout`
**Solution:** Check your internet connection and Plaid API status

**Issue:** `ImportError: No module named 'requests'`
**Solution:** Install dependencies: `pip3 install -r requirements.txt`

**Issue:** `FileNotFoundError: config.json`
**Solution:** Copy `config.json.example` to `config.json` and configure

### Debug Mode

Enable verbose logging:

```bash
python3 plaid_tester.py -c config.json --verbose
```

## Contributing

Contributions are welcome! To add new test cases:

1. Review `tests/TEST_CASES.md` for existing tests
2. Add your test method to `plaid_tester.py`
3. Document the test case in `TEST_CASES.md`
4. Submit a pull request

## Legal Notice

**IMPORTANT LEGAL DISCLAIMER:**

This tool is provided for educational and authorized security testing purposes only. Users are responsible for:

- Obtaining proper authorization before testing any systems
- Complying with all applicable laws and regulations
- Following responsible disclosure practices
- Respecting terms of service and bug bounty program rules

**Unauthorized access to computer systems is illegal.** The authors of this tool are not responsible for any misuse or damage caused by this software.

## Resources

### Plaid Documentation
- [Plaid API Docs](https://plaid.com/docs/)
- [Plaid Sandbox Guide](https://plaid.com/docs/sandbox/)
- [Plaid Security](https://plaid.com/security/)

### Security Testing
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Bug Bounty Methodology](../methodology/API_TESTING.md)

### Bug Bounty Platforms
- [HackerOne](https://www.hackerone.com/)
- [Bugcrowd](https://www.bugcrowd.com/)
- [Intigriti](https://www.intigriti.com/)
- [YesWeHack](https://www.yeswehack.com/)

## License

This project is intended for educational and authorized security research purposes. Use responsibly and ethically.

## Support

For questions or issues:
1. Review the documentation in `/tests/TEST_CASES.md`
2. Check existing bug reports and methodology guides
3. Consult the main repository documentation

---

**Version:** 1.0.0
**Last Updated:** 2026-01-03
**Author:** Couch.Potato Bug Bounty Team
