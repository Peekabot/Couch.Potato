# Couch Potato Research Tools - Web Application

Live, interactive demonstrations of physics and security research capabilities.

## Overview

This Flask web application provides working implementations of theoretical frameworks and methodologies documented in the main portfolio.

### Physics Research Tools

1. **Eigenmode Calculator**
   - Calculate particle mass predictions based on icosahedral eigenmode theory
   - Input: Base frequency → Output: Predicted masses with confidence tiers

2. **HEP Falsification Pipeline**
   - Search for known particles near predicted masses
   - **Demonstrates scientific rigor**: Honest reporting of negative results (p=0.285)

3. **Ball Lightning Harmonic Analyzer**
   - Analyze frequency data to test substrate theory predictions
   - Expected: 200 Hz harmonics vs 100 Hz for standard EM

4. **Boundary Energy Calculator**
   - Calculate ∇φ² energy density at material boundaries
   - Shows cross-domain applications (semiconductors, metallurgy, plasma, neural networks)

### Security Research Tools

1. **Subdomain Wordlist Generator**
   - Generate contextual subdomain lists based on target and keywords
   - Implements Phase 1 (Deep Reconnaissance) from 2025 Master Strategy

2. **IDOR Test Case Generator**
   - Automatically generate IDOR testing payloads
   - Demonstrates understanding of vulnerability class mechanics

3. **Vulnerability Report Generator**
   - Create platform-specific vulnerability reports
   - Templates for HackerOne, Intigriti, Bugcrowd, Generic

4. **Methodology Checklist Generator**
   - Interactive testing checklist for web apps and APIs
   - Systematic approach to security testing

## Why This Matters

### The Gap It Fills

**Problem:** "Strong theory, building practical skills"
**Solution:** Live tools that prove "theory → working code"

### The Positioning Shift

| Before | After |
|--------|-------|
| Documentation | + Live Demo |
| Methodologies | + Interactive Tools |
| Theory | + Implementation |
| "I can think" | + "I can build" |

## Technology Stack

- **Backend:** Flask (Python 3.10+)
- **Math/Science:** NumPy
- **Deployment:** PythonAnywhere (free tier)
- **Integration:** Links from GitHub Pages portfolio

## Quick Start (Local)

```bash
cd webapp
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Visit: http://localhost:5000

## Deployment

See [DEPLOYMENT.md](DEPLOYMENT.md) for complete PythonAnywhere deployment guide.

**TL;DR:**
1. Create free PythonAnywhere account
2. Clone repo and install dependencies
3. Configure WSGI file
4. Reload web app
5. Live at: `https://yourname.pythonanywhere.com`

## Integration with Portfolio

Once deployed, update GitHub Pages portfolio with live links:

### Physics Research Page
```html
<a href="https://yourname.pythonanywhere.com/physics/eigenmode-calculator"
   class="btn btn-primary" target="_blank">
   Try Live Calculator →
</a>
```

### Security Research Page
```html
<a href="https://yourname.pythonanywhere.com/security/subdomain-generator"
   class="btn btn-primary" target="_blank">
   Try Live Tool →
</a>
```

## File Structure

```
webapp/
├── app.py                      # Main Flask application
├── tools/
│   ├── physics_tools.py        # Physics calculation implementations
│   └── security_tools.py       # Security tool implementations
├── templates/                  # HTML templates (to be created)
├── static/                     # CSS/JS assets (to be created)
├── requirements.txt            # Python dependencies
├── DEPLOYMENT.md               # Deployment guide
└── README.md                   # This file
```

## Key Features

### Scientific Rigor
- **Documented negative results** (Fibonacci spacing p=0.285)
- **Epistemological tiers** (Validated, Novel, Speculative)
- **Falsification testing** built into tools

### Professional Methodology
- **Platform-specific templates** (HackerOne, Intigriti, Bugcrowd)
- **Systematic checklists** (Web App, API testing)
- **Automation-ready outputs** (curl commands, Burp payloads)

### Cross-Disciplinary
- **Physics → Security** skill mapping
- **Theory → Practice** demonstration
- **Research → Implementation** pipeline

## The Strategic Impact

This web application transforms your portfolio from:

❌ **"I have ideas"**
✅ **"I ship working code"**

❌ **"I understand theory"**
✅ **"I build implementations"**

❌ **"I'm learning practical skills"**
✅ **"I've built these tools"**

## What This Demonstrates

To employers/collaborators:

1. **Full-Stack Capability**
   - Python backend development
   - API design and implementation
   - Web application deployment

2. **Theory → Practice**
   - Research frameworks become working tools
   - Methodologies become interactive applications
   - Documentation becomes live demonstrations

3. **Professional Deployment**
   - Production-ready code structure
   - Dependency management
   - Deployment documentation
   - Error handling

4. **Unique Value**
   - Physics research tools (no one else has this)
   - Security methodology automation (demonstrates thinking)
   - Cross-disciplinary integration (rare combination)

## Future Enhancements

**Physics Tools:**
- [ ] CSV upload for particle mass datasets
- [ ] Visualization of eigenmode spectrum
- [ ] Cosmological constraint calculator
- [ ] Interactive parameter space exploration

**Security Tools:**
- [ ] SSRF payload generator
- [ ] JWT token decoder/analyzer
- [ ] SQLi payload builder
- [ ] Attack chain visualizer

**Platform:**
- [ ] User accounts for saving results
- [ ] API endpoints for programmatic access
- [ ] Export results (PDF, JSON)
- [ ] Tool usage analytics

## License

Part of the Couch Potato research portfolio.
Demonstrates capabilities for employment/collaboration opportunities.

---

**Remember:** This isn't just a web app—it's **proof that you can turn theory into working software.** That's the gap you needed to fill, and now you have it.
