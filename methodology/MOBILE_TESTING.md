# 📱 Mobile Application Testing Methodology

Comprehensive checklist for testing iOS and Android applications.

## OWASP Mobile Top 10 (2024)

### 1. Improper Credential Usage
- [ ] Hardcoded credentials
- [ ] Credentials in shared preferences
- [ ] Insecure credential storage
- [ ] Credentials in logs

**Tests:**
```bash
# Android - Check for hardcoded credentials
grep -r "password\|api_key\|secret" .
apktool d app.apk
grep -r "password" app/

# iOS - Check plist files
plutil -p Info.plist
grep -r "password\|api_key" .

# Check SharedPreferences (Android)
adb shell
run-as com.app.package
cat shared_prefs/*.xml
```

### 2. Inadequate Supply Chain Security
- [ ] Third-party library vulnerabilities
- [ ] Unsigned libraries
- [ ] Outdated dependencies
- [ ] Malicious SDKs

**Tests:**
```bash
# Android - Check dependencies
./gradlew dependencies

# iOS - Check pods
pod outdated

# Check for known CVEs
# MobSF can help identify vulnerable libraries
```

### 3. Insecure Authentication/Authorization
- [ ] Weak password policies
- [ ] Biometric bypass
- [ ] Token exposure
- [ ] Session management issues

**Tests:**
```bash
# Test biometric bypass
# Remove fingerprint requirement via runtime manipulation

# Check token storage
# Android: SharedPreferences, SQLite
# iOS: Keychain, UserDefaults

# Test session timeout
# Check if tokens expire properly

# Test OAuth implementation
# Check redirect URI validation
```

### 4. Insufficient Input/Output Validation
- [ ] SQL Injection
- [ ] Path Traversal
- [ ] XSS in WebViews
- [ ] Command Injection

**Tests:**
```bash
# SQL Injection in SQLite
' OR '1'='1
'; DROP TABLE users--

# Path Traversal
../../private/data
../../../etc/passwd

# XSS in WebView
<script>alert(1)</script>
<img src=x onerror=alert(1)>

# Check WebView settings
setJavaScriptEnabled(true)
setAllowFileAccess(true)
```

### 5. Insecure Communication
- [ ] Unencrypted HTTP traffic
- [ ] Certificate validation disabled
- [ ] SSL pinning bypass
- [ ] Man-in-the-Middle vulnerabilities

**Tests:**
```bash
# Check for HTTP URLs
grep -r "http://" .

# Test certificate pinning
# Use Frida to bypass pinning
frida -U -f com.app.package -l ssl-unpinning.js

# Proxy traffic through Burp
# Check if certificate validation is proper

# Android Network Security Config
cat res/xml/network_security_config.xml
```

### 6. Inadequate Privacy Controls
- [ ] PII leakage
- [ ] Excessive permissions
- [ ] Data shared with third parties
- [ ] Analytics tracking

**Tests:**
```bash
# Android - Check permissions
aapt dump permissions app.apk

# Check for PII in logs
adb logcat | grep -i "email\|phone\|password"

# Check analytics endpoints
# Monitor network traffic

# iOS - Check privacy manifest
# Review tracking domains
```

### 7. Insufficient Binary Protections
- [ ] No code obfuscation
- [ ] Debug mode enabled
- [ ] Easily reversible
- [ ] No root/jailbreak detection

**Tests:**
```bash
# Android - Check if debuggable
aapt dump badging app.apk | grep debuggable

# Check ProGuard/R8 usage
# Decompile and check code readability

# iOS - Check encryption
otool -l app | grep -i crypt

# Test root detection bypass
# Use Magisk Hide or Frida
```

### 8. Security Misconfiguration
- [ ] Debug features in production
- [ ] Backup enabled
- [ ] Exported components
- [ ] Insecure file permissions

**Tests:**
```bash
# Android - Check exported components
aapt dump xmltree app.apk AndroidManifest.xml

# Check backup flag
android:allowBackup="true"

# Check file permissions
ls -la /data/data/com.app.package/

# iOS - Check app transport security
# Review Info.plist settings
```

### 9. Insecure Data Storage
- [ ] Sensitive data in SQLite
- [ ] Unencrypted files
- [ ] Data in cache
- [ ] Keyboard cache

**Tests:**
```bash
# Android - Check databases
adb shell
run-as com.app.package
ls databases/
sqlite3 database.db
.tables
SELECT * FROM sensitive_table;

# Check SharedPreferences
cat shared_prefs/*.xml

# Check external storage
ls /sdcard/Android/data/com.app.package/

# iOS - Check UserDefaults
plutil -p Library/Preferences/com.app.package.plist

# Check SQLite
sqlite3 Library/Application\ Support/database.sqlite
```

### 10. Insufficient Cryptography
- [ ] Weak encryption algorithms
- [ ] Hardcoded keys
- [ ] Weak random number generation
- [ ] Improper key management

**Tests:**
```bash
# Search for weak crypto
grep -r "DES\|MD5\|SHA1" .

# Android - Check for hardcoded keys
grep -r "AES\|key\|encrypt" .

# Check random number generation
# Look for insecure Random() usage

# iOS - Check CommonCrypto usage
# Review encryption implementations
```

---

## Android-Specific Testing

### Static Analysis

```bash
# Decompile APK
apktool d app.apk

# Convert to JAR and decompile
d2j-dex2jar app.apk
jd-gui app-dex2jar.jar

# Extract strings
strings app.apk

# Analyze with MobSF
# Upload APK to MobSF for automated analysis

# Check AndroidManifest.xml
aapt dump xmltree app.apk AndroidManifest.xml
```

### Dynamic Analysis

```bash
# Install APK
adb install app.apk

# Start app
adb shell am start -n com.app.package/.MainActivity

# Monitor logs
adb logcat | grep com.app.package

# Pull data
adb pull /data/data/com.app.package/ .

# Use Frida for runtime manipulation
frida -U -f com.app.package

# Hook methods
frida -U -l hook.js com.app.package
```

### Intent Manipulation

```bash
# Send broadcast intent
adb shell am broadcast -a com.app.ACTION

# Start activity with extras
adb shell am start -n com.app/.Activity --es "key" "value"

# Test exported activities
adb shell am start -n com.app/.ExportedActivity

# Fuzz intents with Drozer
drozer console connect
run app.package.list
run app.activity.info -a com.app.package
```

### Root Detection Bypass

```bash
# Using Frida
frida -U -f com.app.package -l root-bypass.js

# Using Magisk Hide
# Hide root from specific apps

# Modify APK to remove root checks
# Decompile, remove checks, recompile
```

---

## iOS-Specific Testing

### Static Analysis

```bash
# Extract IPA
unzip app.ipa

# Analyze with class-dump
class-dump app > headers.txt

# Check for encryption
otool -l Payload/App.app/App | grep -i crypt

# Decrypt if needed (jailbroken device)
# Use Clutch or frida-ios-dump

# Analyze with MobSF
# Upload IPA for automated analysis

# Check Info.plist
plutil -p Info.plist
```

### Dynamic Analysis

```bash
# Install IPA (jailbroken)
ipainstaller app.ipa

# Or use Xcode/libimobiledevice
ideviceinstaller -i app.ipa

# SSH into device
ssh root@device-ip

# Find app directory
find /var/mobile/Containers/Bundle/Application -name "App.app"

# Use Frida
frida-ps -U
frida -U -f com.app.bundle

# Runtime manipulation
frida -U -l bypass.js com.app.bundle
```

### Keychain Analysis

```bash
# Dump keychain (jailbroken)
# Use Keychain-Dumper
/path/to/keychain_dumper > keychain.txt

# Check for sensitive data
grep -i "password\|token\|key" keychain.txt

# Test keychain protection levels
# Check kSecAttrAccessible values
```

### URL Scheme Testing

```bash
# Find custom URL schemes
grep -r "CFBundleURLSchemes" .

# Test URL schemes
xcrun simctl openurl booted "appscheme://test"

# Test for parameter injection
appscheme://open?url=http://evil.com

# Test deep links
appscheme://action?param=value
```

### Jailbreak Detection Bypass

```bash
# Using Frida
frida -U -f com.app.bundle -l jailbreak-bypass.js

# Common detection methods to bypass:
# - File system checks
# - Cydia check
# - Fork check
# - Dyld check

# Use Liberty or other tweak
# Shadow for jailbreak hiding
```

---

## API Testing (Mobile Context)

### Intercept Traffic

```bash
# Set up proxy (Burp Suite)
# Android
adb shell settings put global http_proxy <proxy-ip>:8080

# iOS (via WiFi settings)
# Configure manual proxy

# Install CA certificate
# Android: Settings > Security > Install from storage
# iOS: Settings > General > VPN & Device Management

# For SSL pinning bypass
# Use Frida or modify app
```

### Test API Endpoints

```bash
# Common mobile API issues
# - Missing rate limiting
# - Weak authentication
# - IDOR vulnerabilities
# - Excessive data exposure

# Test different API versions
/api/v1/users
/api/v2/users

# Test with different tokens
# Expired tokens
# Other user's tokens
# Modified tokens
```

---

## WebView Testing

### Android WebView

```java
// Check WebView settings
WebView.setJavaScriptEnabled(true)  // XSS risk
WebView.setAllowFileAccess(true)    // File access risk
WebView.setAllowUniversalAccessFromFileURLs(true)  // CORS bypass

// JavaScript Interface
webView.addJavascriptInterface(new Object(), "Android")
```

**Tests:**
```bash
# XSS in WebView
<script>alert(document.cookie)</script>

# File access
file:///data/data/com.app.package/

# JavaScript bridge abuse
Android.sensitiveMethod()

# Check for UXSS
# Universal XSS vulnerabilities
```

### iOS WKWebView

```swift
// Check configuration
WKWebViewConfiguration.preferences.javaScriptEnabled
```

**Tests:**
```bash
# XSS testing
<script>alert(1)</script>

# File access via file://
file:///var/mobile/

# JavaScript bridge testing
# Check for exposed methods
```

---

## Data Storage Testing

### Android

```bash
# Internal Storage
/data/data/com.app.package/

# External Storage
/sdcard/Android/data/com.app.package/

# SharedPreferences
/data/data/com.app.package/shared_prefs/

# SQLite Databases
/data/data/com.app.package/databases/

# Cache
/data/data/com.app.package/cache/

# Check for sensitive data in all locations
```

### iOS

```bash
# App Bundle
/var/containers/Bundle/Application/<UUID>/

# Data Container
/var/mobile/Containers/Data/Application/<UUID>/

# Library
Library/Preferences/
Library/Caches/
Library/Application Support/

# Documents
Documents/

# Keychain (most secure)
# Use security tool or Keychain-Dumper
```

---

## Testing Checklist

### Pre-Testing Setup
- [ ] Set up testing device (rooted/jailbroken)
- [ ] Install testing tools (Frida, Objection, etc.)
- [ ] Configure proxy (Burp Suite)
- [ ] Install app on device
- [ ] Read bug bounty scope

### Static Analysis
- [ ] Decompile app
- [ ] Analyze AndroidManifest.xml / Info.plist
- [ ] Check for hardcoded secrets
- [ ] Review permissions
- [ ] Check for vulnerable libraries
- [ ] Analyze code for security issues

### Dynamic Analysis
- [ ] Intercept network traffic
- [ ] Test API endpoints
- [ ] Check data storage
- [ ] Test authentication/authorization
- [ ] Test input validation
- [ ] Check for insecure logging

### Platform-Specific
- [ ] Android: Test intent handling
- [ ] Android: Test exported components
- [ ] iOS: Test URL schemes
- [ ] iOS: Test keychain storage
- [ ] Test WebViews
- [ ] Test cryptographic implementations

### Post-Testing
- [ ] Verify findings
- [ ] Create PoC
- [ ] Document steps to reproduce
- [ ] Take screenshots/videos
- [ ] Assess impact and severity
- [ ] Write detailed report

---

## Tools

### Static Analysis
- **MobSF** - Mobile Security Framework
- **APKTool** - Android APK decompiler
- **dex2jar** - DEX to JAR converter
- **JD-GUI** - Java decompiler
- **class-dump** - iOS header dumper
- **Hopper/Ghidra** - Disassemblers

### Dynamic Analysis
- **Frida** - Dynamic instrumentation toolkit
- **Objection** - Runtime mobile exploration
- **Burp Suite** - Web proxy
- **ADB** - Android Debug Bridge
- **libimobiledevice** - iOS communication
- **Drozer** - Android security assessment

### Traffic Analysis
- **Burp Suite**
- **mitmproxy**
- **Wireshark**
- **Charles Proxy**

### Specialized Tools
- **Magisk** - Root management
- **Xposed Framework** - Android hooking
- **Cydia Substrate** - iOS hooking
- **SSL Kill Switch 2** - SSL pinning bypass
- **Keychain-Dumper** - iOS keychain extraction

---

## Resources

- [OWASP Mobile Security Testing Guide](https://mobile-security.gitbook.io/mobile-security-testing-guide/)
- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)
- [Android Security Documentation](https://source.android.com/security)
- [iOS Security Guide](https://support.apple.com/guide/security/welcome/web)
- [Frida Documentation](https://frida.re/docs/home/)
- [HackTricks Mobile](https://book.hacktricks.xyz/mobile-pentesting/android-app-pentesting)
- [PayloadsAllTheThings - Mobile](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Mobile%20Application)
