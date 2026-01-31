# Mobile App Security Testing Methodology

**Focus**: iOS and Android application security testing for bug bounty programs

**Platforms**: iPhone (Pythonista, Frida), Android (ADB, Frida, APKTool)

**Bugcrowd VRT Categories**: Mobile-specific vulnerabilities (P1-P4)

---

## 🎯 Mobile vs Web Testing

### Key Differences

| Aspect | Web Apps | Mobile Apps |
|--------|----------|-------------|
| **Surface** | Browser, HTTP/HTTPS | Binary, API, local storage, OS integration |
| **Tools** | Burp Suite, browser DevTools | Frida, objection, MobSF, APKTool |
| **Testing** | Inspect source, modify requests | Decompile, runtime instrumentation, proxy traffic |
| **Auth** | Cookies, tokens | Tokens, certificate pinning, biometrics |
| **Storage** | Browser storage, cookies | SQLite, Keychain, SharedPreferences, files |

### Why Mobile Matters for Bug Bounty

- **Higher bounties**: Mobile vulnerabilities often pay 1.5-2x web bugs
- **Less competition**: Fewer researchers test mobile (higher barrier to entry)
- **Critical bugs**: Certificate pinning bypass, insecure storage = P2/P3 regularly
- **API goldmine**: Mobile apps expose internal APIs not linked from web

---

## 📱 Mobile-Specific Vulnerability Classes

### P1 (Critical) - $1,000-$10,000

**1. Authentication Bypass**
- Biometric bypass (TouchID/FaceID spoofing)
- Certificate pinning bypass + MITM of sensitive operations
- Token theft via insecure storage + full account takeover

**2. Sensitive Data Exposure**
- Hardcoded API keys/secrets in binary
- Unencrypted local database with PII/credentials
- Backup files containing sensitive data

**3. Insecure Code Execution**
- Deep link injection leading to RCE
- Insecure WebView allowing JS injection
- Dynamic code loading vulnerabilities

### P2 (High) - $500-$3,000

**1. Broken Cryptography**
- Weak encryption algorithms (DES, RC4)
- Hardcoded encryption keys in binary
- Predictable random number generation

**2. Insecure Communication**
- Certificate pinning missing or bypassable
- Cleartext transmission of session tokens
- Man-in-the-middle of API calls

**3. Insecure Authorization**
- Client-side authorization checks only
- Privilege escalation via API manipulation
- IDOR in mobile API endpoints

### P3 (Medium) - $200-$1,000

**1. Insecure Data Storage**
- Sensitive data in app logs
- Caching of sensitive screens (app switcher screenshots)
- Unencrypted SQLite databases with non-critical data

**2. Insufficient Transport Layer Protection**
- Mixed HTTP/HTTPS content
- Weak TLS configuration
- Certificate validation issues

**3. Information Disclosure**
- Debug logs containing sensitive info
- Error messages revealing system details
- Excessive permissions granted

### P4 (Low) - $50-$250

**1. Binary Hardening Issues**
- Missing binary protections (PIE, stack canaries)
- Debug symbols in release builds
- Jailbreak/root detection bypassable

**2. Client-Side Injection**
- Self-XSS in WebViews
- SQL injection in local database (no backend impact)

---

## 🛠️ Mobile Testing Toolkit

### iOS Testing

**Required Hardware**:
- iPhone (jailbroken preferred, not required)
- Mac (for Xcode, iOS app analysis)
- USB cable

**Essential Tools**:
- **Burp Suite** - Proxy mobile traffic
- **Frida** - Runtime instrumentation framework
- **objection** - Frida-powered mobile exploration toolkit
- **Hopper/Ghidra** - Binary disassembly and analysis
- **iFunBox/iMazing** - File system access (non-jailbroken)
- **Cycript** - Runtime Objective-C/Swift manipulation (jailbroken)

**Pythonista Integration**:
- Use Pythonista for on-device testing
- Run Frida scripts from iPhone
- Inspect app containers, SQLite databases
- Test deep links, URL schemes

### Android Testing

**Required Hardware**:
- Android device (rooted preferred, not required)
- USB cable
- Computer (Windows/Mac/Linux)

**Essential Tools**:
- **ADB** (Android Debug Bridge) - Device communication
- **Frida** - Runtime instrumentation
- **objection** - Mobile security toolkit
- **APKTool** - Decompile/recompile APKs
- **jadx** - Decompile APK to Java source
- **MobSF** - Mobile Security Framework (automated analysis)
- **Genymotion** - Android emulator for testing

### Universal Tools

- **Burp Suite** - Intercept mobile API traffic
- **mitmproxy** - Alternative to Burp, scriptable
- **Postman** - API testing and documentation
- **SQLite Browser** - Inspect app databases
- **Wireshark** - Network traffic analysis

---

## 🚀 Mobile Testing Workflow

### Phase 1: Reconnaissance (30 min - 1 hour)

**iOS Apps**:
```bash
# 1. Download IPA from App Store (requires Apple ID)
# Use tools like: iMazing, Apple Configurator, or Frida-iOS-Dump

# 2. Extract IPA contents
unzip app.ipa -d app_extracted/

# 3. Analyze binary
otool -L app_extracted/Payload/AppName.app/AppName  # Check libraries
strings app_extracted/Payload/AppName.app/AppName | grep -i "http"  # Find URLs
strings app_extracted/Payload/AppName.app/AppName | grep -i "api"   # Find API keys

# 4. Check Info.plist for URL schemes, permissions
plutil -p app_extracted/Payload/AppName.app/Info.plist
```

**Android Apps**:
```bash
# 1. Download APK from device or APK mirror sites
adb pull /data/app/com.example.app/base.apk

# 2. Decompile APK
apktool d base.apk -o app_decompiled/

# 3. Convert to JAR and decompile to Java
d2j-dex2jar base.apk  # Creates base-dex2jar.jar
jd-gui base-dex2jar.jar  # View Java source

# 4. Search for secrets
grep -r "api_key" app_decompiled/
grep -r "password" app_decompiled/
grep -r "http://" app_decompiled/  # Cleartext URLs

# 5. Check AndroidManifest.xml for permissions, exported components
cat app_decompiled/AndroidManifest.xml
```

**What to look for**:
- Hardcoded API keys, secrets, credentials
- API endpoints (base URLs, versioning)
- URL schemes / deep links
- Debugging flags or test endpoints
- Third-party SDKs (analytics, crash reporting)
- Exported components (Android: activities, services, receivers)

---

### Phase 2: Traffic Interception (1-2 hours)

**Setup Burp Suite Proxy for Mobile**:

1. **Configure Burp**:
   - Proxy → Options → Proxy Listeners
   - Add listener: `*:8080` (all interfaces)
   - Import/Generate CA certificate

2. **Configure iPhone**:
   - Settings → Wi-Fi → (i) → HTTP Proxy → Manual
   - Server: [Your Computer IP], Port: 8080
   - Install Burp CA cert via Safari → Settings → General → Profile
   - Settings → About → Certificate Trust Settings → Enable Burp cert

3. **Configure Android**:
   - Settings → Wi-Fi → Long press network → Modify → Proxy Manual
   - Hostname: [Your Computer IP], Port: 8080
   - Install Burp CA cert: Settings → Security → Install from storage
   - For Android 7+: Add network security config to bypass user cert restrictions

4. **Test**:
   - Open app, perform actions
   - Watch Burp HTTP History for API calls
   - Look for: Auth tokens, API keys, sensitive data in requests/responses

**Certificate Pinning Bypass** (if app blocks proxy):

iOS (using Frida):
```bash
# Install objection
pip3 install objection

# Launch app with SSL pinning bypass
objection --gadget "com.example.app" explore

# Inside objection console
ios sslpinning disable
```

Android (using Frida):
```bash
# Attach Frida to app
frida -U -f com.example.app --no-pause

# Or use objection
objection -g com.example.app explore
android sslpinning disable
```

**What to test**:
- Replay API requests with modified parameters (IDOR, privilege escalation)
- Remove/modify auth tokens (broken auth)
- Test for injection in API parameters (SQLi, XSS, command injection)
- Check for sensitive data in responses (PII, secrets)

---

### Phase 3: Local Data Storage (1 hour)

**iOS - Inspect App Container**:

Non-jailbroken (requires backup):
```bash
# Create app backup
idevicebackup2 backup --source [UDID] .

# Extract backup
idevicebackup2 extract [backup_folder] [output_folder]

# Find app data
find [output_folder] -name "*.db"  # SQLite databases
find [output_folder] -name "*.plist"  # Property lists
```

Jailbroken (direct access):
```bash
# SSH into iPhone
ssh root@[iPhone_IP]

# Navigate to app container
cd /var/mobile/Containers/Data/Application/[UUID]/

# Check directories
ls Documents/  # User-generated content
ls Library/    # App settings, caches
ls tmp/        # Temporary files

# Inspect SQLite databases
sqlite3 Documents/app.db
.tables
SELECT * FROM users;
```

**Android - Inspect App Data**:

Rooted:
```bash
# Access app data directly
adb shell
su
cd /data/data/com.example.app/

# Check directories
ls databases/  # SQLite databases
ls shared_prefs/  # XML preference files
ls files/  # App files
ls cache/  # Cached data

# Pull database for analysis
exit
adb pull /data/data/com.example.app/databases/app.db
sqlite3 app.db
.tables
SELECT * FROM users;
```

Non-rooted (requires debuggable app or backup):
```bash
# Create backup
adb backup -f app.ab com.example.app

# Convert backup to tar (requires Android Backup Extractor)
java -jar abe.jar unpack app.ab app.tar

# Extract tar
tar -xvf app.tar

# Inspect contents
cd apps/com.example.app/db/
sqlite3 app.db
```

**What to look for**:
- ❌ Unencrypted passwords, tokens, API keys
- ❌ Sensitive PII (SSN, credit cards) in plaintext
- ❌ Session tokens stored insecurely
- ✅ Encrypted databases (check if encryption key is hardcoded)
- ❌ Sensitive data in logs (`console.log`, `NSLog`)

**Common Vulnerabilities**:
- **P2**: Cleartext storage of credentials or session tokens
- **P3**: Sensitive data in logs or cache
- **P4**: Debug info, stack traces in local storage

---

### Phase 4: Runtime Instrumentation (2-4 hours)

**Frida Basics**:

Install Frida:
```bash
pip3 install frida-tools
```

List running apps:
```bash
# iOS
frida-ps -Uai

# Android
frida-ps -U
```

Attach to app:
```bash
frida -U -n "App Name"
# OR by bundle ID
frida -U -f com.example.app --no-pause
```

**Common Frida Scripts**:

1. **Bypass Jailbreak/Root Detection**:
```javascript
// iOS jailbreak bypass
Java.perform(function() {
    var JailbreakDetection = ObjC.classes.JailbreakDetectionClass;
    JailbreakDetection['- isJailbroken'].implementation = function() {
        console.log('[*] Jailbreak detection bypassed');
        return false;
    };
});
```

2. **Hook Function to See Arguments**:
```javascript
// iOS (Objective-C)
var LoginController = ObjC.classes.LoginViewController;
LoginController['- loginWithUsername:password:'].implementation = function(user, pass) {
    console.log('[*] Login attempt:');
    console.log('    Username: ' + user);
    console.log('    Password: ' + pass);
    return this['- loginWithUsername:password:'](user, pass);
};

// Android (Java)
Java.perform(function() {
    var AuthManager = Java.use('com.example.app.AuthManager');
    AuthManager.login.implementation = function(username, password) {
        console.log('[*] Login attempt:');
        console.log('    Username: ' + username);
        console.log('    Password: ' + password);
        return this.login(username, password);
    };
});
```

3. **Dump Encryption Keys**:
```javascript
// Find where crypto keys are used
Interceptor.attach(Module.findExportByName("libSystem.B.dylib", "CCCrypt"), {
    onEnter: function(args) {
        console.log('[*] CCCrypt called');
        console.log('    Key: ' + hexdump(ptr(args[3]), { length: 32 }));
    }
});
```

**objection - Easier Frida Interface**:
```bash
# Launch objection
objection -g com.example.app explore

# Common commands
ios info binary  # Get app info
ios plist cat Info.plist  # Read plist files
ios nsurlcredentialstorage dump  # Dump stored credentials
ios cookies get  # Get cookies
ios keychain dump  # Dump keychain (jailbroken)
memory dump all app.dump  # Dump memory
```

**What to test**:
- Bypass client-side checks (jailbreak/root, biometric, PIN)
- Intercept encryption/decryption to find keys
- Hook sensitive functions (login, payment, API calls)
- Modify return values (isPremium, isAdmin)
- Dump memory for secrets

---

### Phase 5: Deep Links & URL Schemes (30 min - 1 hour)

**iOS URL Schemes**:

Find registered schemes:
```bash
# In Info.plist
grep -A 10 "CFBundleURLSchemes" app_extracted/Payload/App.app/Info.plist
```

Test deep links:
```bash
# From Mac Safari or iOS Notes app
myapp://login?user=admin&token=abc123
myapp://payment?amount=1&recipient=attacker

# Or use Pythonista
import webbrowser
webbrowser.open("myapp://sensitive-action?param=evil")
```

**Android Deep Links**:

Find registered intent filters:
```xml
<!-- In AndroidManifest.xml -->
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <data android:scheme="myapp" android:host="login" />
</intent-filter>
```

Test deep links:
```bash
# Using ADB
adb shell am start -W -a android.intent.action.VIEW \
  -d "myapp://login?user=admin&redirect=http://evil.com"

# Or from browser
<a href="myapp://payment?amount=9999">Click me</a>
```

**Common Vulnerabilities**:
- **P1**: Deep link injection leading to RCE or account takeover
- **P2**: Insecure redirect via deep link
- **P3**: Authorization bypass via deep link
- **P4**: Information disclosure via deep link

**Test Cases**:
- Inject SQL/XSS/command injection in parameters
- Open redirect (redirect parameter to external URL)
- IDOR (user_id parameter to access other accounts)
- Privilege escalation (admin=true, isPremium=1)

---

### Phase 6: Binary Analysis (Advanced, 2-4 hours)

**iOS Binary Analysis**:

Tools: Hopper Disassembler, Ghidra, IDA Pro

```bash
# Dump class names and methods
class-dump app_extracted/Payload/App.app/App > classes.txt

# Find interesting methods
grep -i "password\|secret\|token\|key" classes.txt

# Disassemble with Hopper
# Look for:
# - Hardcoded secrets in __cstring section
# - Weak crypto (DES, MD5, hardcoded IV/keys)
# - Logic flaws in auth/authorization checks
```

**Android Binary Analysis**:

Tools: jadx, JEB Decompiler, Ghidra

```bash
# Decompile to readable Java
jadx -d output/ app.apk

# Search for sensitive patterns
grep -r "password" output/
grep -r "api_key" output/
grep -r "http://" output/  # Cleartext communication

# Look for weak crypto
grep -r "DES\|RC4\|MD5" output/

# Check for security misconfigurations
grep -r "setJavaScriptEnabled(true)" output/  # Insecure WebView
grep -r "setAllowFileAccess(true)" output/  # File access in WebView
```

**What to look for**:
- Hardcoded secrets (API keys, passwords, encryption keys)
- Weak crypto algorithms
- Insecure WebView configurations
- Debug code in production
- Third-party SDK vulnerabilities

---

## 📝 Mobile Bug Report Template

```markdown
## Title
[iOS/Android] [Vulnerability Type] in [Feature/Component]

Example: [Android] Hardcoded API Key in APK Binary

## Vulnerability Details

**Platform**: iOS 15+ / Android 11+
**App Version**: 1.2.3 (Build 456)
**Device Tested**: iPhone 13 / Pixel 6

**VRT Classification**:
- Category: Sensitive Data Exposure
- Subcategory: Hardcoded Secrets in Binary
- Priority: P2 (High)

## Reproduction Steps

**Prerequisites**:
- Jailbroken iPhone / Rooted Android device (if required)
- Tools: Frida, objection, APKTool, etc.

**Steps**:
1. Download app from App Store / Play Store
2. [iOS] Extract IPA using iMazing
   [Android] Pull APK using: `adb pull /data/app/com.example.app/base.apk`
3. [iOS] Unzip IPA: `unzip app.ipa -d extracted/`
   [Android] Decompile: `apktool d base.apk -o decompiled/`
4. Search for API key:
   ```bash
   strings extracted/Payload/App.app/App | grep "api_key"
   # OR
   grep -r "api_key" decompiled/
   ```
5. Observed hardcoded API key: `sk_live_abc123xyz456`

## Proof of Concept

**Screenshot**: [Binary strings showing API key]

**API Key Found**:
```
API_KEY = "sk_live_abc123xyz456"
BASE_URL = "https://api.example.com/v1"
```

**Verification**:
```bash
curl -H "Authorization: Bearer sk_live_abc123xyz456" \
  https://api.example.com/v1/users/me
# Returns: {"id": 12345, "email": "admin@example.com", ...}
```

## Impact

**Severity**: High (P2)

An attacker can:
1. Extract API key from APK/IPA (no special tools required)
2. Use key to authenticate as the mobile app
3. Access backend API with full app privileges
4. Potentially access user data, modify records, etc.

**Business Impact**:
- API key compromise affects all users
- Attacker could abuse API quotas, incur costs
- Potential data breach if API exposes sensitive data

## Mitigation

**Immediate**:
- Revoke compromised API key
- Issue app update with key removed

**Long-term**:
- Never hardcode secrets in binaries
- Use certificate pinning + per-device tokens
- Implement backend API authentication (OAuth, JWT)
- Use dynamic API key provisioning (fetch at runtime after user auth)

## References

- OWASP Mobile Top 10: M9 - Reverse Engineering
- CWE-798: Use of Hard-coded Credentials
```

---

## 🎯 Mobile-Specific Bug Hunting Tips

### High-ROI Targets

1. **Financial Apps** (banking, fintech, crypto)
   - Focus: Insecure data storage, weak crypto, transaction replay
   - Bounties: $1,000-$10,000 for critical bugs

2. **Healthcare Apps**
   - Focus: HIPAA violations, PII exposure, insecure communication
   - Bounties: $500-$5,000

3. **Social/Dating Apps**
   - Focus: IDOR, privilege escalation, GPS spoofing
   - Bounties: $200-$2,000

4. **E-commerce Apps**
   - Focus: Payment manipulation, inventory bypass, promo code abuse
   - Bounties: $300-$3,000

### Common Low-Hanging Fruit

- **Hardcoded API keys**: Grep strings, check decompiled code
- **Insecure local storage**: No encryption on SQLite databases
- **Certificate pinning bypass**: Test with Frida/objection
- **Deep link injection**: Test all URL scheme handlers
- **Cleartext traffic**: Check for HTTP (not HTTPS) API calls

### Tools ROI

| Tool | Cost | Learning Curve | Bug Finding Rate |
|------|------|----------------|------------------|
| Frida | Free | Medium | High |
| objection | Free | Low | High |
| MobSF | Free | Low | Medium (automated) |
| Burp Suite | $0-$449/yr | Low-Medium | Very High |
| Hopper/IDA | $99-$1,800 | High | Medium |

**Recommendation**: Start with free tools (Frida, objection, MobSF, Burp Community). Upgrade to Burp Pro when earning $500+/month.

---

## 🧪 Practice Labs

**Free Mobile Security Labs**:

1. **DVIA (Damn Vulnerable iOS App)**
   - Download: https://github.com/prateek147/DVIA-v2
   - 18 vulnerable scenarios (jailbreak bypass, keychain, crypto, etc.)

2. **InsecureBankv2 (Android)**
   - Download: https://github.com/dineshshetty/Android-InsecureBankv2
   - Insecure crypto, weak auth, root detection, etc.

3. **MSTG Hacking Playground**
   - iOS: https://github.com/OWASP/MSTG-Hacking-Playground
   - Android: https://github.com/OWASP/MSTG-Hacking-Playground
   - OWASP's official vulnerable apps

4. **Frida Labs**
   - https://github.com/DERE-ad2001/Frida-Labs
   - Practice Frida scripting challenges

**Paid Training**:
- **Mobile Application Hacker's Handbook** (Book, $40)
- **PentesterLab Mobile Challenges** ($20/month)
- **Hack The Box Mobile Challenges** ($10-$20/month)

---

## 📊 Success Metrics

**Week 1-2** (Learning):
- [ ] Set up Burp proxy for mobile
- [ ] Install Frida + objection
- [ ] Decompile first iOS app (IPA) or Android app (APK)
- [ ] Complete DVIA challenge #1

**Month 1** (First Bugs):
- [ ] Test 5 mobile apps from bug bounty programs
- [ ] Find first vulnerability (even if duplicate)
- [ ] Submit first mobile bug report
- [ ] Bypass certificate pinning on 1 app

**Quarter 1** (Consistent Findings):
- [ ] 3+ accepted mobile vulnerabilities
- [ ] $500+ earned from mobile bugs
- [ ] Master Frida scripting (5+ custom scripts)
- [ ] Develop specialty (iOS vs Android, fintech vs social, etc.)

---

**Mobile testing = Higher bounties, less competition, more fun!** 📱🎯

*Learn one, do one, teach one.*
