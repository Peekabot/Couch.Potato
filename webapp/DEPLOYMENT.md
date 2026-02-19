# PythonAnywhere Deployment Guide

Complete guide to deploying the Couch Potato Research Tools web application on PythonAnywhere.

## Overview

This web application provides **live, interactive demonstrations** of physics and security research capabilities:

- **Physics Tools**: Eigenmode calculator, particle mass search, ball lightning analyzer, boundary energy calculator
- **Security Tools**: Subdomain generator, IDOR tester, vulnerability report generator, methodology checklist

## Why PythonAnywhere?

- **Free tier** suitable for portfolio demonstrations
- **No credit card required** for basic deployment
- **Python-optimized** hosting perfect for Flask apps
- **Easy deployment** with Git integration
- **Professional subdomain** (yourname.pythonanywhere.com)

## Step-by-Step Deployment

### 1. Create PythonAnywhere Account

1. Go to https://www.pythonanywhere.com
2. Click "Pricing & signup"
3. Choose "Create a Beginner account" (FREE)
4. Complete registration

### 2. Clone Repository

In the PythonAnywhere Bash console:

```bash
# Clone your repository
git clone https://github.com/Peekabot/Couch.Potato.git
cd Couch.Potato/webapp

# Create virtual environment
mkvirtualenv --python=/usr/bin/python3.10 myenv

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure Web App

1. Go to "Web" tab in PythonAnywhere dashboard
2. Click "Add a new web app"
3. Choose "Manual configuration"
4. Select Python 3.10
5. **Important settings:**

#### Source code directory:
```
/home/YOUR_USERNAME/Couch.Potato/webapp
```

#### Working directory:
```
/home/YOUR_USERNAME/Couch.Potato/webapp
```

#### WSGI configuration file:
Edit the WSGI file to:

```python
import sys
import os

# Add your project directory to the sys.path
project_home = '/home/YOUR_USERNAME/Couch.Potato/webapp'
if project_home not in sys.path:
    sys.path.insert(0, project_home)

# Import Flask app
from app import app as application
```

#### Virtualenv:
```
/home/YOUR_USERNAME/.virtualenvs/myenv
```

### 4. Static Files Configuration

In the "Web" tab, add static files mapping:

| URL | Directory |
|-----|-----------|
| /static/ | /home/YOUR_USERNAME/Couch.Potato/webapp/static/ |

### 5. Reload Web App

Click the big green "Reload" button in the Web tab.

Your app will be live at: `https://YOUR_USERNAME.pythonanywhere.com`

## Testing Deployment

### Test Physics Tools
- Visit: `https://YOUR_USERNAME.pythonanywhere.com/physics`
- Try eigenmode calculator
- Run particle mass search
- Test ball lightning analyzer

### Test Security Tools
- Visit: `https://YOUR_USERNAME.pythonanywhere.com/security`
- Generate subdomain wordlist
- Create IDOR test cases
- Generate vulnerability report

## Integration with GitHub Pages Portfolio

### Update Portfolio Links

In your GitHub Pages portfolio (`index.html`, `physics-research.html`, `security-research.html`), add live tool buttons:

```html
<!-- Physics Research Page -->
<a href="https://YOUR_USERNAME.pythonanywhere.com/physics/eigenmode-calculator"
   target="_blank"
   class="btn btn-primary">
   Try Live Calculator →
</a>

<!-- Security Research Page -->
<a href="https://YOUR_USERNAME.pythonanywhere.com/security/subdomain-generator"
   target="_blank"
   class="btn btn-primary">
   Try Live Tool →
</a>
```

### The Power of This Integration

**Static Portfolio (GitHub Pages):**
- Professional presentation
- Research documentation
- Methodology frameworks
- SEO-friendly content

**Live Tools (PythonAnywhere):**
- Interactive demonstrations
- Working implementations
- Proof of capability
- Hands-on experience

**Together:** Theory + Practice = Complete Package

## Updating Your Deployment

When you make changes:

```bash
# SSH into PythonAnywhere bash console
cd ~/Couch.Potato
git pull origin main
cd webapp
pip install -r requirements.txt  # if requirements changed

# Reload web app from Web tab
```

## Free Tier Limitations

PythonAnywhere free tier includes:
- ✅ 1 web app
- ✅ subdomain.pythonanywhere.com domain
- ✅ 512 MB disk space
- ✅ Enough for portfolio demonstration
- ❌ No custom domain (upgrade to paid)
- ❌ Limited CPU time (daily quota)
- ❌ No outbound HTTPS (can't call external APIs from code)

**For a portfolio: Free tier is perfect!**

## Troubleshooting

### App shows "Something went wrong"
- Check error log in "Web" tab → "Error log"
- Verify WSGI configuration
- Confirm virtualenv path
- Check file permissions

### Tools not working
- Verify imports in app.py
- Check tools directory in sys.path
- Review server logs
- Test locally first: `python app.py`

### Static files not loading
- Confirm static files mapping in Web tab
- Check file paths are absolute
- Clear browser cache

## Local Development

Before deploying, test locally:

```bash
cd webapp
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Visit: http://localhost:5000

## Next Steps

After deployment:

1. ✅ Test all physics tools
2. ✅ Test all security tools
3. ✅ Update GitHub Pages portfolio with live links
4. ✅ Share portfolio URL
5. ✅ Monitor PythonAnywhere usage/quota

## The Strategic Impact

**Before:**
- "I have methodologies" (static documentation)
- "I understand theory" (research papers)
- "I can code" (GitHub repos)

**After:**
- "I have methodologies" → **"Try my live tools"**
- "I understand theory" → **"Run my calculations"**
- "I can code" → **"Use my working apps"**

**Positioning shift:** From "aspiring researcher" to **"ships working software"**

## Support

- PythonAnywhere Help: https://help.pythonanywhere.com
- Flask Documentation: https://flask.palletsprojects.com
- Your GitHub Issues: https://github.com/Peekabot/Couch.Potato/issues

---

**Remember:** The goal isn't just to have tools—it's to **demonstrate capability through working implementations.** This separates you from portfolios that only show documentation.
