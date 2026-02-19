#!/usr/bin/env python3
"""
Mobile Bug Bounty Dashboard
Touch-optimized web interface for iPhone bug bounty hunting
Run on iPhone using a-Shell or access remotely
"""

from flask import Flask, render_template_string, request, jsonify
import sys
from pathlib import Path

# Add parent directories to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'utilities'))

app = Flask(__name__)

# Mobile-optimized HTML template
MOBILE_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <title>📱 Bug Bounty Mobile</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            -webkit-tap-highlight-color: transparent;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #fff;
            padding: env(safe-area-inset-top) env(safe-area-inset-right) env(safe-area-inset-bottom) env(safe-area-inset-left);
            min-height: 100vh;
            padding-bottom: 80px;
        }

        .header {
            background: rgba(0,0,0,0.3);
            backdrop-filter: blur(10px);
            padding: 20px;
            text-align: center;
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .header h1 {
            font-size: 1.5em;
            font-weight: 700;
        }

        .container {
            max-width: 600px;
            margin: 20px auto;
            padding: 0 15px;
        }

        .tool-card {
            background: rgba(255,255,255,0.15);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 20px;
            margin-bottom: 20px;
            border: 2px solid rgba(255,255,255,0.2);
        }

        .tool-card h2 {
            font-size: 1.3em;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        input, textarea, select {
            width: 100%;
            padding: 15px;
            margin: 10px 0;
            background: rgba(0,0,0,0.3);
            border: 2px solid rgba(255,255,255,0.2);
            border-radius: 12px;
            color: #fff;
            font-size: 16px; /* Prevents iOS zoom */
            font-family: inherit;
        }

        input::placeholder, textarea::placeholder {
            color: rgba(255,255,255,0.6);
        }

        .btn {
            width: 100%;
            padding: 18px;
            margin: 10px 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            border-radius: 12px;
            color: #fff;
            font-size: 18px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
        }

        .btn:active {
            transform: scale(0.98);
            box-shadow: 0 2px 8px rgba(0,0,0,0.2);
        }

        .btn-success {
            background: linear-gradient(135deg, #00b09b 0%, #96c93d 100%);
        }

        .btn-danger {
            background: linear-gradient(135deg, #eb3349 0%, #f45c43 100%);
        }

        .result-box {
            background: rgba(0,0,0,0.4);
            border-radius: 12px;
            padding: 15px;
            margin: 15px 0;
            max-height: 400px;
            overflow-y: auto;
            font-size: 14px;
            line-height: 1.6;
            white-space: pre-wrap;
            word-wrap: break-word;
        }

        .loading {
            text-align: center;
            padding: 20px;
        }

        .spinner {
            border: 3px solid rgba(255,255,255,0.3);
            border-top: 3px solid #fff;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .tabs {
            display: flex;
            gap: 10px;
            overflow-x: auto;
            margin-bottom: 20px;
            -webkit-overflow-scrolling: touch;
        }

        .tab {
            min-width: 120px;
            padding: 12px 20px;
            background: rgba(255,255,255,0.1);
            border-radius: 12px;
            text-align: center;
            cursor: pointer;
            white-space: nowrap;
            transition: background 0.3s;
        }

        .tab.active {
            background: rgba(255,255,255,0.3);
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        .stats {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            margin: 20px 0;
        }

        .stat-card {
            background: rgba(255,255,255,0.1);
            border-radius: 12px;
            padding: 15px;
            text-align: center;
        }

        .stat-value {
            font-size: 2em;
            font-weight: 700;
        }

        .stat-label {
            font-size: 0.9em;
            opacity: 0.8;
            margin-top: 5px;
        }

        .bottom-nav {
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            background: rgba(0,0,0,0.5);
            backdrop-filter: blur(20px);
            display: flex;
            justify-content: space-around;
            padding: 15px;
            padding-bottom: max(15px, env(safe-area-inset-bottom));
        }

        .nav-item {
            text-align: center;
            cursor: pointer;
            padding: 10px;
            border-radius: 8px;
            transition: background 0.3s;
        }

        .nav-item:active {
            background: rgba(255,255,255,0.1);
        }

        .nav-icon {
            font-size: 24px;
        }

        .nav-label {
            font-size: 11px;
            margin-top: 5px;
        }

        .badge {
            background: #ff4444;
            color: white;
            border-radius: 10px;
            padding: 2px 6px;
            font-size: 10px;
            margin-left: 5px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>📱 Bug Bounty Mobile</h1>
    </div>

    <div class="container">
        <div class="tabs">
            <div class="tab active" onclick="switchTab('recon')">🔍 Recon</div>
            <div class="tab" onclick="switchTab('headers')">🛡️ Headers</div>
            <div class="tab" onclick="switchTab('jwt')">🔑 JWT</div>
            <div class="tab" onclick="switchTab('report')">📝 Report</div>
            <div class="tab" onclick="switchTab('stats')">📊 Stats</div>
        </div>

        <!-- RECON TAB -->
        <div id="recon-tab" class="tab-content active">
            <div class="tool-card">
                <h2>🔍 Quick Recon</h2>
                <input type="text" id="recon-domain" placeholder="example.com">
                <button class="btn" onclick="runRecon()">Scan Subdomains</button>
                <div id="recon-result" class="result-box" style="display:none"></div>
            </div>
        </div>

        <!-- HEADERS TAB -->
        <div id="headers-tab" class="tab-content">
            <div class="tool-card">
                <h2>🛡️ Security Headers</h2>
                <input type="text" id="header-url" placeholder="https://example.com">
                <button class="btn" onclick="checkHeaders()">Check Headers</button>
                <div id="header-result" class="result-box" style="display:none"></div>
            </div>
        </div>

        <!-- JWT TAB -->
        <div id="jwt-tab" class="tab-content">
            <div class="tool-card">
                <h2>🔑 JWT Decoder</h2>
                <textarea id="jwt-token" rows="4" placeholder="Paste JWT token here"></textarea>
                <button class="btn" onclick="decodeJWT()">Decode Token</button>
                <button class="btn btn-success" onclick="pasteFromClipboard()">📋 Paste from Clipboard</button>
                <div id="jwt-result" class="result-box" style="display:none"></div>
            </div>
        </div>

        <!-- REPORT TAB -->
        <div id="report-tab" class="tab-content">
            <div class="tool-card">
                <h2>📝 Quick Report</h2>
                <select id="report-type">
                    <option value="xss">XSS</option>
                    <option value="idor">IDOR</option>
                    <option value="ssrf">SSRF</option>
                    <option value="sqli">SQL Injection</option>
                    <option value="open_redirect">Open Redirect</option>
                </select>
                <input type="text" id="report-target" placeholder="Target URL">
                <textarea id="report-description" rows="3" placeholder="Brief description"></textarea>
                <button class="btn" onclick="generateReport()">Generate Report</button>
                <div id="report-result" class="result-box" style="display:none"></div>
            </div>
        </div>

        <!-- STATS TAB -->
        <div id="stats-tab" class="tab-content">
            <div class="tool-card">
                <h2>📊 Your Stats</h2>
                <div class="stats">
                    <div class="stat-card">
                        <div class="stat-value">0</div>
                        <div class="stat-label">Scans Today</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">0</div>
                        <div class="stat-label">Bugs Found</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">$0</div>
                        <div class="stat-label">Bounties</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">0</div>
                        <div class="stat-label">Programs</div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="bottom-nav">
        <div class="nav-item" onclick="switchTab('recon')">
            <div class="nav-icon">🔍</div>
            <div class="nav-label">Recon</div>
        </div>
        <div class="nav-item" onclick="switchTab('headers')">
            <div class="nav-icon">🛡️</div>
            <div class="nav-label">Headers</div>
        </div>
        <div class="nav-item" onclick="switchTab('jwt')">
            <div class="nav-icon">🔑</div>
            <div class="nav-label">JWT</div>
        </div>
        <div class="nav-item" onclick="switchTab('report')">
            <div class="nav-icon">📝</div>
            <div class="nav-label">Report</div>
        </div>
    </div>

    <script>
        function switchTab(tabName) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            document.querySelector(`#${tabName}-tab`).classList.add('active');
            event.target.classList.add('active');
        }

        function showLoading(elementId) {
            document.getElementById(elementId).style.display = 'block';
            document.getElementById(elementId).innerHTML = '<div class="loading"><div class="spinner"></div><p>Processing...</p></div>';
        }

        function showResult(elementId, content) {
            document.getElementById(elementId).style.display = 'block';
            document.getElementById(elementId).innerHTML = content;
        }

        async function runRecon() {
            const domain = document.getElementById('recon-domain').value;
            if (!domain) {
                alert('Please enter a domain');
                return;
            }

            showLoading('recon-result');

            try {
                const response = await fetch('/api/recon', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({domain: domain})
                });

                const data = await response.json();
                showResult('recon-result', formatReconResult(data));
            } catch (error) {
                showResult('recon-result', `Error: ${error.message}`);
            }
        }

        async function checkHeaders() {
            const url = document.getElementById('header-url').value;
            if (!url) {
                alert('Please enter a URL');
                return;
            }

            showLoading('header-result');

            try {
                const response = await fetch('/api/headers', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url: url})
                });

                const data = await response.json();
                showResult('header-result', formatHeaderResult(data));
            } catch (error) {
                showResult('header-result', `Error: ${error.message}`);
            }
        }

        async function decodeJWT() {
            const token = document.getElementById('jwt-token').value;
            if (!token) {
                alert('Please paste a JWT token');
                return;
            }

            showLoading('jwt-result');

            try {
                const parts = token.split('.');
                if (parts.length !== 3) {
                    throw new Error('Invalid JWT format');
                }

                const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
                const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));

                const result = `HEADER:\\n${JSON.stringify(header, null, 2)}\\n\\nPAYLOAD:\\n${JSON.stringify(payload, null, 2)}`;
                showResult('jwt-result', result);
            } catch (error) {
                showResult('jwt-result', `Error: ${error.message}`);
            }
        }

        async function pasteFromClipboard() {
            try {
                const text = await navigator.clipboard.readText();
                document.getElementById('jwt-token').value = text;
            } catch (error) {
                alert('Clipboard access denied. Please paste manually.');
            }
        }

        async function generateReport() {
            const type = document.getElementById('report-type').value;
            const target = document.getElementById('report-target').value;
            const description = document.getElementById('report-description').value;

            if (!target) {
                alert('Please enter target URL');
                return;
            }

            showLoading('report-result');

            const report = `# ${type.toUpperCase()} Report\\n\\nTarget: ${target}\\nDate: ${new Date().toISOString()}\\n\\nDescription: ${description}\\n\\n[Add steps to reproduce]`;
            showResult('report-result', report);
        }

        function formatReconResult(data) {
            if (data.error) return `Error: ${data.error}`;
            return `Found ${data.subdomains?.length || 0} subdomains\\n\\n` + (data.subdomains?.join('\\n') || 'No results');
        }

        function formatHeaderResult(data) {
            if (data.error) return `Error: ${data.error}`;
            let result = 'Security Headers:\\n\\n';
            for (let [key, value] of Object.entries(data.headers || {})) {
                result += `${key}: ${value}\\n`;
            }
            return result || 'No headers found';
        }

        // Service Worker for offline support (optional)
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.register('/sw.js').catch(() => {});
        }
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    """Serve the mobile dashboard"""
    return render_template_string(MOBILE_TEMPLATE)

@app.route('/api/recon', methods=['POST'])
def api_recon():
    """Quick subdomain enumeration"""
    data = request.get_json()
    domain = data.get('domain', '').strip()

    if not domain:
        return jsonify({'error': 'Domain required'}), 400

    # Simple subdomain check (replace with actual tool)
    subdomains = []
    test_subs = ['www', 'mail', 'ftp', 'admin', 'api', 'dev']

    try:
        import dns.resolver
        for sub in test_subs:
            try:
                full_domain = f"{sub}.{domain}"
                dns.resolver.resolve(full_domain, 'A')
                subdomains.append(full_domain)
            except:
                pass
    except ImportError:
        return jsonify({'error': 'DNS resolver not available'}), 500

    return jsonify({'subdomains': subdomains, 'count': len(subdomains)})

@app.route('/api/headers', methods=['POST'])
def api_headers():
    """Check security headers"""
    data = request.get_json()
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'URL required'}), 400

    try:
        import requests
        resp = requests.get(url, timeout=5)
        headers = dict(resp.headers)

        security_headers = {
            'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Missing'),
            'Content-Security-Policy': headers.get('Content-Security-Policy', 'Missing'),
            'X-Frame-Options': headers.get('X-Frame-Options', 'Missing'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Missing'),
        }

        return jsonify({'headers': security_headers})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Mobile Bug Bounty Dashboard')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8080, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')

    args = parser.parse_args()

    print(f"""
╔═══════════════════════════════════════╗
║  📱 Mobile Bug Bounty Dashboard      ║
╚═══════════════════════════════════════╝

🌐 Access at: http://{args.host}:{args.port}

📱 On iPhone:
   1. Open Safari
   2. Navigate to the URL above
   3. Tap Share → Add to Home Screen

🎯 Ready to hunt bugs on the go!
""")

    app.run(host=args.host, port=args.port, debug=args.debug)
