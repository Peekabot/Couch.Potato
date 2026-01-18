# Contributing Guide

## Welcome!

Thank you for your interest in contributing to **Couch Potato**. This guide will help you understand how to contribute effectively.

---

## What Can I Contribute?

### Open Source Components (MIT License)

✅ **Cybersecurity Tools**
- Bug bounty automation
- Recon scripts
- Exploit development
- Reporting templates
- Mobile AI Agent improvements

✅ **Documentation**
- Guides and tutorials
- Code comments
- Workflow improvements
- Examples and templates

✅ **Bug Fixes**
- Security vulnerabilities
- Performance issues
- Code quality improvements

---

### Proprietary Components (Restricted)

⚠️ **Financial Coordinator IP**

Core theory and implementation are **proprietary** and require:
- Member status (approved via vote)
- Contribution agreement
- Revenue sharing arrangement

**Contact**: Create an [issue](https://github.com/Peekabot/Couch.Potato/issues) to discuss membership

---

## How to Contribute

### 1. Find an Issue

**Browse existing issues**:
- [Good First Issues](https://github.com/Peekabot/Couch.Potato/labels/good%20first%20issue)
- [Help Wanted](https://github.com/Peekabot/Couch.Potato/labels/help%20wanted)
- [Bug Reports](https://github.com/Peekabot/Couch.Potato/labels/bug)

**Or create a new issue**:
- Feature request
- Bug report
- Documentation improvement
- Question

---

### 2. Fork the Repository

```bash
# Fork on GitHub, then clone
git clone https://github.com/YOUR-USERNAME/Couch.Potato.git
cd Couch.Potato

# Add upstream
git remote add upstream https://github.com/Peekabot/Couch.Potato.git
```

---

### 3. Create a Branch

```bash
# Create feature branch
git checkout -b feature/your-feature-name

# Or bugfix branch
git checkout -b bugfix/issue-123
```

**Branch naming**:
- `feature/` - New features
- `bugfix/` - Bug fixes
- `docs/` - Documentation changes
- `refactor/` - Code refactoring

---

### 4. Make Changes

**Code Guidelines**:
- Follow PEP 8 (Python)
- Add docstrings to functions
- Include type hints
- Write clear commit messages
- Test your changes

**Example**:
```python
def analyze_target(target: str, depth: str = "medium") -> dict:
    """
    Analyze a target domain for vulnerabilities.

    Args:
        target: Domain name to analyze (e.g., "example.com")
        depth: Scan depth ("quick", "medium", "thorough")

    Returns:
        Dictionary containing analysis results
    """
    # Implementation
    pass
```

---

### 5. Test Your Changes

**Run local tests**:
```bash
# For cybersecurity tools
cd revenue-streams/cybersecurity/tools/mobile-ai-agent
python warmup.py  # Progressive testing

# For specific features
python test_mistral.py
```

**Manual testing**:
- Test on clean environment
- Verify no breaking changes
- Check security implications

---

### 6. Commit Your Changes

**Commit message format**:
```
<type>: <short description>

<detailed description>

Fixes #123
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `refactor`: Code restructuring
- `test`: Testing improvements
- `chore`: Maintenance

**Example**:
```bash
git add .
git commit -m "feat: Add AI-powered subdomain prioritization

Implement Mistral AI integration to rank subdomains by
vulnerability likelihood. Uses GPT-4 for intelligent analysis.

Fixes #45"
```

---

### 7. Push and Create PR

```bash
# Push to your fork
git push origin feature/your-feature-name

# Create PR on GitHub
# Use the PR template
```

**PR Template**:
```markdown
## Description
Brief description of changes

## Motivation
Why is this change needed?

## Changes
- Change 1
- Change 2
- Change 3

## Testing
How did you test this?

## Screenshots (if applicable)
```

---

## Code Review Process

### What We Look For

✅ **Code Quality**
- Readable and maintainable
- Follows Python conventions
- Proper error handling
- Secure implementation

✅ **Testing**
- Changes are tested
- No breaking changes
- Edge cases considered

✅ **Documentation**
- Clear docstrings
- Updated README if needed
- Examples provided

---

### Review Timeline

- **Initial review**: Within 48 hours
- **Feedback**: Within 72 hours
- **Merge**: After approval (1-7 days)

**Be patient!** We're a small team.

---

## Contribution Examples

### Example 1: Bug Fix

**Issue**: Rate limiter allows 11 requests instead of 10

**Fix**:
```python
# Before
if self.requests < 10:
    self.requests += 1
    return True

# After
if self.requests < 10:
    self.requests += 1
    return True
return False  # Explicit rejection
```

**PR**: "fix: Enforce rate limit correctly at 10 requests"

---

### Example 2: New Feature

**Issue**: Add Shodan integration for IP analysis

**Implementation**:
```python
class ShodanClient:
    """Integration with Shodan API for IP intelligence."""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.shodan.io"

    def analyze_ip(self, ip: str) -> dict:
        """
        Get Shodan data for IP address.

        Args:
            ip: IP address to analyze

        Returns:
            Shodan intelligence data
        """
        # Implementation
        pass
```

**PR**: "feat: Add Shodan API integration for IP intelligence"

---

### Example 3: Documentation

**Issue**: Missing quickstart guide for mobile AI agent

**Addition**: Create `QUICKSTART.md`:
```markdown
# Quick Start Guide

## Setup (5 minutes)

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Configure API key:
   ```bash
   export MISTRAL_API_KEY="your-key-here"
   ```

3. Run warmup tests:
   ```bash
   python warmup.py
   ```

## First Scan

...
```

**PR**: "docs: Add quickstart guide for mobile AI agent"

---

## Recognition

### Contributors Hall of Fame

All contributors get:
- Credit in README.md
- Listed in CONTRIBUTORS.md
- Recognition in release notes
- Public shoutout (Twitter/LinkedIn)

### Member Consideration

Consistent high-quality contributors may be invited to become **members**:
- Vote on governance
- Earn ULU for contributions
- Participate in profit sharing

**Requirements**:
- 5+ merged PRs
- Consistent quality
- Good communication
- Alignment with values

---

## Getting Help

### Stuck?

**Ask for help**:
1. Comment on the issue
2. Join [GitHub Discussions](https://github.com/Peekabot/Couch.Potato/discussions)
3. Create a question issue
4. Email (coming soon)

**We're friendly!** Don't hesitate to ask.

---

## Code of Conduct

### Our Values

✅ **Respect**: Be kind and professional
✅ **Transparency**: Share openly
✅ **Collaboration**: Help each other
✅ **Excellence**: Quality over quantity
✅ **Ethics**: Security research only

### Unacceptable Behavior

❌ Harassment or discrimination
❌ Malicious code
❌ Unauthorized testing/hacking
❌ Spam or self-promotion
❌ Theft of intellectual property

**Violations**: Will be reported and banned

---

## Security Vulnerabilities

### Responsible Disclosure

**Found a security issue?**

⚠️ **DO NOT** open a public issue

**Instead**:
1. Create a [security advisory](https://github.com/Peekabot/Couch.Potato/security/advisories)
2. Email (coming soon)
3. Encrypted message (GPG key - coming soon)

**We commit to**:
- Acknowledge within 48 hours
- Provide timeline within 7 days
- Credit you in release notes
- Possible bounty reward (future)

---

## Legal

### License Agreement

By contributing, you agree:

1. **Open Source Components** (MIT):
   - Your contribution is licensed under MIT
   - You have right to contribute
   - No patent claims

2. **Proprietary Components**:
   - Requires separate agreement
   - Revenue sharing applies
   - Contact for details

### Copyright

You retain copyright, but grant Couch Potato:
- Perpetual, irrevocable license
- Right to modify and distribute
- Right to relicense (with attribution)

**Standard for open source projects**

---

## FAQ

### Q: Can I contribute without coding?

**A**: Yes! We need:
- Documentation writers
- Designers
- Testers
- Community managers

---

### Q: Will I get paid?

**A**: For open source work, no immediate payment.

**However**:
- Consistent contributors → member consideration
- Members → ULU profit sharing
- Bounty rewards (future)

---

### Q: How do I become a member?

**A**:
1. Contribute consistently (5+ PRs)
2. Show expertise and reliability
3. Align with company values
4. Receive invite from existing members
5. Pass supermajority vote (≥66%)

---

### Q: Can I use Couch Potato code in my project?

**A**:
- **MIT components**: Yes! (attribution required)
- **Proprietary components**: No (contact for licensing)

---

## Thank You!

Every contribution makes Couch Potato better. Whether it's a typo fix or a major feature, we appreciate your time and effort.

**Let's build something amazing together.**

---

*Last Updated: 2026-01-18*
*Version: 1.0*
*Status: Active*
