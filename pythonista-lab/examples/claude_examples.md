# 🤖 Claude Code Examples for Python Development

This guide demonstrates how to effectively use Claude Code for Python development in your bug bounty workflow.

## 🎯 Basic Usage Patterns

### 1. Generate a New Security Tool

**Prompt to Claude:**
```
Create a Python script that checks for common CORS misconfigurations.
It should:
- Accept a URL as input
- Send requests with different Origin headers
- Check for overly permissive Access-Control-Allow-Origin
- Detect credentials exposure risks
- Output findings in a clear format
```

**What Claude will do:**
- Generate complete Python script with error handling
- Include proper documentation
- Add usage examples
- Implement security best practices

### 2. Debug Existing Code

**Prompt to Claude:**
```
I'm getting a "ConnectionTimeout" error in my port scanner.
Here's the error: [paste error]
Can you help me add proper timeout handling and retry logic?
```

**What Claude will do:**
- Analyze the error
- Suggest fixes with code examples
- Explain the root cause
- Recommend best practices

### 3. Add Features to Existing Tools

**Prompt to Claude:**
```
Can you add these features to the subdomain_enum.py script:
1. Export results to JSON
2. Add DNS wildcard detection
3. Include CNAME records in output
4. Add progress bar for long-running scans
```

**What Claude will do:**
- Read the existing script
- Add requested features while maintaining code style
- Update documentation
- Test compatibility

### 4. Optimize Performance

**Prompt to Claude:**
```
My directory bruteforcer is too slow. Can you:
- Add async/await for concurrent requests
- Implement rate limiting
- Add caching for DNS resolution
- Reduce memory usage for large wordlists
```

**What Claude will do:**
- Refactor code for better performance
- Implement modern Python patterns
- Maintain readability
- Add performance metrics

## 💡 Advanced Workflows

### Creating a Custom Reconnaissance Framework

**Step 1: Initial Design**
```
Claude, I want to build a reconnaissance framework that:
- Enumerates subdomains
- Checks for live hosts
- Identifies web technologies
- Scans for open ports
- Takes screenshots of web pages

Can you help me design the architecture?
```

**Step 2: Implementation**
```
Let's start implementing the subdomain enumeration module.
It should support multiple sources (DNS, certificate transparency, etc.)
```

**Step 3: Testing**
```
Can you add unit tests for the subdomain enumeration module?
```

**Step 4: Documentation**
```
Generate comprehensive documentation for the framework including:
- Installation instructions
- Usage examples
- API reference
- Contributing guidelines
```

### Automating Bug Report Generation

**Example Prompt:**
```
Create a Python script that:
1. Takes vulnerability details as input
2. Generates a report using our template in /templates/GENERIC_TEMPLATE.md
3. Includes PoC code formatting
4. Adds CVSS score calculation
5. Exports to markdown and PDF
```

## 🔧 Common Development Tasks

### 1. Setting Up Virtual Environment

**Ask Claude:**
```
Help me set up a Python virtual environment for this project
with all necessary dependencies for security testing
```

### 2. Managing Dependencies

**Ask Claude:**
```
Create a requirements.txt with all dependencies for my security tools,
organized by category (web, network, parsing, etc.)
```

### 3. Creating Tests

**Ask Claude:**
```
Write pytest tests for the header_analyzer.py utility.
Include edge cases and mock HTTP responses.
```

### 4. Error Handling

**Ask Claude:**
```
Add comprehensive error handling to this script including:
- Network timeouts
- Invalid input validation
- Graceful shutdown on Ctrl+C
- Logging errors to file
```

## 🎓 Learning with Claude

### Understanding Complex Code

**Ask Claude:**
```
Can you explain how this async/await code works in the context
of concurrent HTTP requests? Break it down step by step.
```

### Security Best Practices

**Ask Claude:**
```
Review this script for security issues:
- Input validation
- Command injection risks
- Safe handling of user data
- Proper credential storage
```

### Python Patterns

**Ask Claude:**
```
What's the best way to implement a retry mechanism with
exponential backoff in Python? Show me an example.
```

## 📚 Example Conversations

### Example 1: Building a SSRF Scanner

**You:**
```
I need a Python tool to test for SSRF vulnerabilities.
It should:
- Test multiple injection points (URL params, headers, etc.)
- Use various payloads (localhost, internal IPs, cloud metadata)
- Detect blind SSRF using out-of-band techniques
- Generate a detailed report
```

**Claude's Response:**
- Asks clarifying questions about scope
- Proposes tool architecture
- Generates complete implementation
- Includes usage documentation
- Suggests testing methodology

### Example 2: Fixing a Bug

**You:**
```
My script crashes with "UnicodeDecodeError" when processing responses.
Here's the code: [paste code]
```

**Claude's Response:**
- Identifies the encoding issue
- Explains why it occurs
- Provides fixed code
- Suggests prevention strategies
- Adds error handling

### Example 3: Code Review

**You:**
```
Review this subdomain enumeration script for:
- Code quality
- Performance issues
- Security problems
- Best practices
```

**Claude's Response:**
- Comprehensive code review
- Specific improvement suggestions
- Refactored code examples
- Performance optimization tips

## 🚀 Pro Tips

### 1. Be Specific
❌ "Make this better"
✅ "Add rate limiting with 10 requests/second and exponential backoff on errors"

### 2. Provide Context
❌ "Fix this error"
✅ "I'm getting a timeout error when scanning large networks. Here's the error and my current code: [paste]"

### 3. Iterate Incrementally
❌ "Build a complete penetration testing framework"
✅ "Let's start by building a port scanner, then we'll add service detection"

### 4. Ask for Explanations
✅ "Can you explain why you chose asyncio over threading for this use case?"

### 5. Request Best Practices
✅ "What's the most secure way to handle API credentials in this script?"

## 🎯 Common Use Cases

| Task | Example Prompt |
|------|---------------|
| **Generate Script** | "Create a Python script that extracts URLs from JavaScript files" |
| **Debug Error** | "Why am I getting 'SSL certificate verify failed' and how do I fix it safely?" |
| **Add Feature** | "Add proxy support with rotation to this web scraper" |
| **Optimize Code** | "This script takes 10 minutes to run. How can we make it faster?" |
| **Write Tests** | "Create pytest tests for all functions in this module" |
| **Document Code** | "Add docstrings and type hints to all functions" |
| **Refactor** | "Refactor this script to use classes instead of functions" |
| **Security Review** | "Review this code for injection vulnerabilities" |

## 🔐 Security-Focused Prompts

### Input Validation
```
Add input validation to prevent:
- Command injection
- Path traversal
- SQL injection (if using databases)
- XSS (if generating HTML)
```

### Secure Coding
```
Review this code for OWASP Top 10 vulnerabilities
and suggest fixes with examples
```

### Credential Handling
```
I need to store API keys for multiple services.
Show me the secure way to handle credentials in Python
```

## 📊 Workflow Integration

### 1. Development Phase
```
Claude, let's build a new tool for testing authentication bypasses
```

### 2. Testing Phase
```
Write comprehensive tests for the auth bypass tool
```

### 3. Documentation Phase
```
Generate user documentation and inline code comments
```

### 4. Optimization Phase
```
Profile this script and suggest performance improvements
```

### 5. Security Review Phase
```
Perform a security review of the complete tool
```

## 🎓 Learning Resources

### Ask Claude to Recommend
- Python security libraries
- Best practices for async programming
- Design patterns for tool development
- Testing strategies
- Performance optimization techniques

### Example:
```
What are the best Python libraries for:
1. HTTP requests with retry logic
2. Concurrent processing
3. HTML/XML parsing
4. Regular expressions
5. Command-line interfaces
```

---

**Remember:** Claude Code is your pair programmer. Don't hesitate to ask questions, request explanations, and iterate on solutions!
