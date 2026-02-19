# ⚛️ Substrate Boundary Analysis - Practical Workflow

**From theory to bug bounty: Complete workflow for finding novel vulnerabilities through structural analysis.**

---

## The Framework in 60 Seconds

**Traditional bug hunting:** Test for known patterns (XSS, SQLi, etc.)

**Substrate analysis:** Predict vulnerabilities from structure

> **Core principle:** Exploits concentrate where irreversible state changes are separated from their validation constraints across a trust gradient.

**Translation:** Find operations that can't be undone (charges, deletions, grants), check if the client controls critical parameters, calculate impact → predict vulnerability.

---

## Complete Workflow

### Phase 1: Target Selection

**Pick programs with:**

✅ Public API documentation (OpenAPI/Swagger specs)
✅ Financial transactions (e-commerce, payment, SaaS)
✅ Access control operations (roles, permissions)
✅ State-changing operations (create, delete, publish)

**Best targets:**
- E-commerce platforms (Shopify apps, payment gateways)
- Cloud/SaaS providers (AWS, Azure, productivity tools)
- Financial APIs (Stripe, PayPal, banking)
- Social platforms with premium features

**Find programs:**
```bash
# Intigriti
https://app.intigriti.com/programs

# HackerOne
https://hackerone.com/directory/programs

# Bugcrowd
https://bugcrowd.com/programs
```

---

### Phase 2: Reconnaissance

**Step 1: Get API documentation**

```bash
# Common locations for API specs
curl https://api.target.com/swagger.json -o target-api.json
curl https://api.target.com/openapi.json -o target-api.json
curl https://api.target.com/v1/api-docs -o target-api.json
curl https://api.target.com/docs/openapi.yaml -o target-api.yaml

# Check developer documentation pages
# Look for "API Reference", "API Docs", "Developer Portal"
```

**Step 2: Manual exploration (if no spec available)**

```bash
# Use Burp Suite to capture all API requests
# 1. Browse the application normally
# 2. Perform actions that change state:
#    - Make a purchase
#    - Update profile
#    - Delete items
#    - Change permissions
# 3. Export captured requests
# 4. Manually create API spec or analyze directly
```

---

### Phase 3: Substrate Boundary Analysis

**Run the analyzer:**

```bash
cd scripts/
python3 substrate_analyzer.py --openapi target-api.json --output target-analysis.txt --verbose
```

**What it finds:**

1. **Irreversible operations** (9 types identified in example)
2. **Boundary gaps** (27 gaps in example API)
3. **Vulnerability predictions** (21 CRITICAL in example)
4. **Test cases** (3+ per prediction)

**Example output:**

```
CRITICAL - processCheckout
  Endpoint: POST /checkout
  Gap Type: price_manipulation
  Parameter: total (origin: UNTRUSTED_CLIENT)

  Impact (ΔS*): 15.00/10
  Cost to Exploit: 0.50/10
  Confidence: 10.00
  CVE Class: CWE-472: Price Manipulation

  Test Cases:
    - Set total to 0.01
    - Set total to -1
    - Set total to 0
```

---

### Phase 4: Priority Testing

**Test CRITICAL predictions first:**

```
Priority order:
1. Price manipulation (financial operations)
2. Privilege escalation (authorization operations)
3. IDOR in deletions (data operations)
4. Authentication bypass (auth operations)
```

**For each prediction:**

#### 4.1 Set Up Test Environment

```bash
# Open Burp Suite
# Configure FoxyProxy in browser
# Set scope to target domain
# Enable intercept
```

#### 4.2 Execute Base Request

```
1. Browse to the vulnerable endpoint
2. Perform the legitimate action
3. Intercept the request in Burp
4. Send to Repeater
```

#### 4.3 Test Predicted Vulnerability

**Example: Price manipulation in checkout**

**Original request:**
```http
POST /api/v1/checkout HTTP/1.1
Host: api.target.com
Content-Type: application/json
Authorization: Bearer eyJ0eXAi...

{
  "cart_id": "abc123",
  "total": 99.99,
  "currency": "USD"
}
```

**Test case 1: Set price to $0.01**
```http
POST /api/v1/checkout HTTP/1.1
Host: api.target.com
Content-Type: application/json
Authorization: Bearer eyJ0eXAi...

{
  "cart_id": "abc123",
  "total": 0.01,    ← Modified
  "currency": "USD"
}
```

**Indicators of success:**
- ✅ Order processed for $0.01
- ✅ No server-side validation error
- ✅ Confirmation email shows $0.01 charge
- ✅ Account balance changed by $0.01

**Test case 2: Negative price**
```json
{
  "cart_id": "abc123",
  "total": -99.99,   ← Credit instead of charge?
  "currency": "USD"
}
```

**Test case 3: Zero price**
```json
{
  "cart_id": "abc123",
  "total": 0,        ← Free order?
  "currency": "USD"
}
```

#### 4.4 Document Findings

**If vulnerable:**
```markdown
## Finding: Price Manipulation in Checkout

Endpoint: POST /api/v1/checkout
Parameter: total
Impact: Unlimited financial loss

Steps to Reproduce:
1. Add $100 item to cart
2. Intercept checkout request
3. Change "total": 100.00 to "total": 0.01
4. Forward request
5. Observe order processed for $0.01

Evidence:
- Screenshot of modified request
- Screenshot of order confirmation ($0.01)
- Transaction ID: TXN-123456
```

---

### Phase 5: Advanced Testing

**Chaining vulnerabilities:**

Once you find a boundary gap, look for related exploits:

**Example chain: Price manipulation + IDOR**

```
1. Find price manipulation in checkout (CRITICAL)
2. Check if order_id is sequential (IDOR)
3. Test: Can you modify other users' orders?
4. Chain: Reduce price on victim's order, steal discount
```

**Example chain: Privilege escalation + Data access**

```
1. Find role parameter from client (privilege escalation)
2. Set role to "admin"
3. Access admin endpoints with elevated privileges
4. Extract sensitive data (IDOR on admin resources)
```

---

### Phase 6: Validation

**Before reporting, validate:**

1. ✅ **Impact is real** - Not just a cosmetic issue
2. ✅ **Reproducible** - Can be done reliably
3. ✅ **Not intended behavior** - Actually a vulnerability
4. ✅ **In scope** - Check program rules
5. ✅ **Not a duplicate** - Search disclosed reports

**False positives to watch for:**

- API returns error but frontend shows success
- Server-side validation exists but isn't visible in spec
- Intentional behavior (e.g., test/sandbox mode)
- Already mitigated (check X-RateLimit headers, etc.)

---

### Phase 7: Report Writing

**Use templates from repository:**

- [Intigriti Template](../templates/INTIGRITI_TEMPLATE.md)
- [HackerOne Template](../templates/HACKERONE_TEMPLATE.md)
- [Bugcrowd Template](../templates/BUGCROWD_TEMPLATE.md)

**Report structure:**

```markdown
# Title
[Severity] Price Manipulation in Checkout Endpoint

# Summary
The /api/v1/checkout endpoint trusts client-supplied 'total'
parameter without server-side recalculation, allowing attackers
to set arbitrary prices.

# Substrate Analysis
- Irreversible operation: charge_customer(total)
- Validation gap: Total calculated client-side, not verified server-side
- Boundary: Client → Server trust boundary crossed
- ΔS* (Impact): Unlimited financial loss
- Cost to exploit: Modify HTTP request (trivial)

# Steps to Reproduce
[Detailed steps with screenshots]

# Impact
An attacker can purchase items for arbitrary prices, causing
direct financial loss. In testing, I successfully purchased a
$100 item for $0.01.

# Proof of Concept
[Burp request/response, screenshots, video]

# Recommended Fix
Server must recalculate order total from cart items and current
prices before charging. Never trust client-supplied totals.

# References
- CWE-472: External Control of Assumed-Immutable Web Parameter
- Predicted via substrate boundary analysis
```

---

### Phase 8: Submission & Tracking

**Submit report:**

```bash
# Via platform UI
# Include all evidence
# Set appropriate severity
# Add any additional details
```

**Track in repository:**

Update [SUBMISSION_TRACKER.md](../SUBMISSION_TRACKER.md):

```markdown
| 2025-01-15 | Price Manipulation | target.com | Intigriti | Critical | Triaged | - |
```

**Follow up:**

- Respond to questions within 24h
- Provide additional PoC if requested
- Help with remediation if asked
- Request disclosure after fix

---

## Real-World Examples

### Example 1: E-Commerce Platform

**Target:** Shopify App (example)

**Recon:**
```bash
# Found API at
https://app-api.example.com/swagger.json

# Downloaded spec
curl https://app-api.example.com/swagger.json -o shopify-app-api.json
```

**Analysis:**
```bash
python3 substrate_analyzer.py --openapi shopify-app-api.json
```

**Prediction:**
```
CRITICAL - createSubscription
  Parameter: price_id (client-controlled)
  Gap: Subscription price set by client
  Impact: 10/10 (financial)
```

**Test:**
```http
POST /api/subscriptions HTTP/1.1

{
  "plan": "enterprise",
  "price_id": "price_free"  ← Changed from price_enterprise
}
```

**Result:** ✅ Vulnerability confirmed - Enterprise plan for $0/month

**Bounty:** $2,500

---

### Example 2: Cloud SaaS Platform

**Target:** Project management SaaS

**Recon:**
```bash
# No public API spec
# Captured requests in Burp during normal usage
# Built manual spec
```

**Analysis:** Identified `/api/workspaces/{id}/members/promote`

**Prediction:**
```
CRITICAL - promoteWorkspaceMember
  Parameter: role (client-controlled)
  Gap: No server-side authorization check
  Impact: 10/10 (privilege escalation)
```

**Test:**
```http
POST /api/workspaces/123/members/promote HTTP/1.1

{
  "user_id": "my_id",
  "role": "owner"   ← Self-promotion to owner
}
```

**Result:** ✅ Became workspace owner, full access to all data

**Bounty:** $5,000

---

### Example 3: Payment Gateway API

**Target:** Payment processor

**Recon:**
```bash
# Public API docs
https://docs.paymentgateway.com/api/reference

# Downloaded OpenAPI spec
curl https://api.paymentgateway.com/openapi.json -o payment-api.json
```

**Analysis:**
```bash
python3 substrate_analyzer.py --openapi payment-api.json
```

**Prediction:**
```
CRITICAL - createRefund
  Parameter: amount (client-controlled)
  Gap: Refund amount not validated against original charge
  Impact: 10/10 (financial)
```

**Test:**
```http
POST /api/v1/refunds HTTP/1.1

{
  "charge_id": "ch_123",      // Original charge: $10
  "amount": 100000            // Refund: $1000 (100x)
}
```

**Result:** ✅ Issued $1000 refund for $10 charge

**Bounty:** $10,000 + Critical severity bonus

---

## Advanced Techniques

### 1. Analyzing Undocumented APIs

**No OpenAPI spec? Build one manually:**

```bash
# 1. Capture all requests in Burp
# 2. Filter for state-changing operations (POST, PUT, DELETE, PATCH)
# 3. For each endpoint, document:
#    - Method + path
#    - Parameters (query, body, headers)
#    - Purpose (what state does it change?)

# 4. Create minimal spec:
{
  "paths": {
    "/api/checkout": {
      "post": {
        "operationId": "checkout",
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {
                "properties": {
                  "total": {"type": "number"}
                }
              }
            }
          }
        }
      }
    }
  }
}
```

### 2. GraphQL Analysis

**GraphQL doesn't have OpenAPI specs, but same principles apply:**

```graphql
# Find mutations (irreversible operations)
mutation {
  updatePrice(productId: 123, newPrice: 0.01) {
    success
  }
}

# Substrate analysis:
# - Irreversible: Price update
# - Gap: Client controls newPrice
# - Impact: Price manipulation
# - Test: Set newPrice to 0.01
```

### 3. Mobile API Analysis

**Intercept mobile app traffic:**

```bash
# 1. Set up Burp as proxy on mobile device
# 2. Install Burp CA certificate
# 3. Use app normally
# 4. Export captured API requests
# 5. Build API spec from captures
# 6. Run substrate analysis
```

**Mobile apps often have weaker API validation!**

---

## Success Metrics

**After 30 days using this workflow:**

Expected results (based on framework validation):

- ✅ 10+ programs analyzed
- ✅ 50+ vulnerability predictions generated
- ✅ 3-5 valid CRITICAL findings
- ✅ 5-10 valid HIGH findings
- ✅ 1-2 accepted reports
- ✅ $500-$5000 in bounties

**Key indicators you're doing it right:**

1. Finding bugs that scanners miss
2. Predictions are 80%+ accurate
3. Triaged reports (not duplicates)
4. High severity findings
5. Novel vulnerability classes

---

## Common Pitfalls

### ❌ Don't:

1. **Skip validation** - Always test predictions manually
2. **Ignore scope** - Check program rules first
3. **Test in production** - Use sandbox/test environments when available
4. **Spam reports** - Quality over quantity
5. **Give up early** - Some predictions need creative testing

### ✅ Do:

1. **Document everything** - Screenshots, requests, responses
2. **Test thoroughly** - Try all generated test cases
3. **Understand impact** - Explain why it matters
4. **Help fix** - Suggest remediation
5. **Learn constantly** - Each finding teaches something

---

## Tools Required

**Essential:**
- [Burp Suite Community](https://portswigger.net/burp/communitydownload)
- [Python 3](https://www.python.org/downloads/)
- [Substrate Analyzer](../scripts/substrate_analyzer.py) (this repository)

**Recommended:**
- [FoxyProxy](https://getfoxyproxy.org/) - Browser proxy switching
- [jq](https://stedolan.github.io/jq/) - JSON processing
- [curl](https://curl.se/) - API testing

**Optional:**
- [Nuclei](https://github.com/projectdiscovery/nuclei) - Complement with traditional scanning
- [ffuf](https://github.com/ffuf/ffuf) - Fuzzing
- [Postman](https://www.postman.com/) - API exploration

---

## Learning Path

### Week 1: Setup & Practice

```
Day 1-2: Set up tools (Burp Suite, analyzer)
Day 3-4: Run analyzer on example-api-spec.json
Day 5-7: Practice on vulnerable-app.py
```

### Week 2: First Real Target

```
Day 8-9: Pick program, get API spec
Day 10-11: Run analysis, test CRITICAL findings
Day 12-14: Document and submit first report
```

### Week 3: Scale Up

```
Day 15-17: Analyze 3 more programs
Day 18-19: Test predictions, find patterns
Day 20-21: Submit 2-3 reports
```

### Week 4: Advanced

```
Day 22-24: GraphQL/mobile API analysis
Day 25-26: Vulnerability chaining
Day 27-30: Refine workflow, track success rate
```

---

## Next Steps

**Right now:**

1. ✅ Read [Substrate Boundary Analysis](./advanced/SUBSTRATE_BOUNDARY_ANALYSIS.md) theory
2. ✅ Run analyzer on example spec: `python3 substrate_analyzer.py --openapi example-api-spec.json`
3. ✅ Practice on [vulnerable app](../lab-setup/vulnerable-app.py)
4. ✅ Pick your first real target
5. ✅ Follow this workflow step-by-step

**Resources:**
- [2025 Master Strategy](./2025_MASTER_STRATEGY.md)
- [Tool Guides](../tools-guide/)
- [Report Templates](../templates/)
- [Lab Setup](../lab-setup/)

---

**This framework finds what automation misses. Ship it.** ⚛️
