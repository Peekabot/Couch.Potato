#!/usr/bin/env python3
"""
Intentionally Vulnerable Web Application for Bug Bounty Practice
DO NOT deploy to production or expose to internet!
For local practice only.

Run: python3 vulnerable-app.py
Access: http://localhost:5000
"""

from flask import Flask, request, render_template_string, jsonify, redirect, make_response
import sqlite3
import hashlib
import jwt
import datetime
import os

app = Flask(__name__)
app.secret_key = "insecure_secret_key_12345"  # VULNERABLE: Weak secret

# Initialize database
def init_db():
    conn = sqlite3.connect('vulnapp.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, role TEXT, ssn TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS posts
                 (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, content TEXT)''')

    # Insert sample users
    users = [
        (1, 'admin', hashlib.md5(b'admin123').hexdigest(), 'admin@vulnapp.local', 'admin', '123-45-6789'),
        (2, 'user', hashlib.md5(b'password').hexdigest(), 'user@vulnapp.local', 'user', '987-65-4321'),
        (3, 'test', hashlib.md5(b'test123').hexdigest(), 'test@vulnapp.local', 'user', '555-12-3456')
    ]

    c.execute('DELETE FROM users')
    c.executemany('INSERT INTO users VALUES (?,?,?,?,?,?)', users)

    conn.commit()
    conn.close()

init_db()

# Home page
@app.route('/')
def index():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Vulnerable Practice App</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { background: white; padding: 30px; border-radius: 8px; max-width: 800px; margin: 0 auto; }
            h1 { color: #d32f2f; }
            .warning { background: #fff3cd; border: 1px solid #ffc107; padding: 15px; margin: 20px 0; border-radius: 4px; }
            .vuln-list { list-style: none; padding: 0; }
            .vuln-list li { background: #e3f2fd; margin: 10px 0; padding: 15px; border-radius: 4px; }
            .vuln-list a { text-decoration: none; color: #1976d2; font-weight: bold; }
            code { background: #f5f5f5; padding: 2px 6px; border-radius: 3px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🎯 Vulnerable Practice App</h1>

            <div class="warning">
                <strong>⚠️ WARNING:</strong> This application is INTENTIONALLY VULNERABLE for educational purposes.
                <br><strong>DO NOT DEPLOY TO PRODUCTION OR EXPOSE TO INTERNET!</strong>
            </div>

            <h2>Practice Targets:</h2>
            <ul class="vuln-list">
                <li>
                    <a href="/login">1. SQL Injection (Login)</a><br>
                    <small>Try: username=<code>admin' OR '1'='1</code>, password=<code>anything</code></small>
                </li>
                <li>
                    <a href="/search">2. Cross-Site Scripting (XSS)</a><br>
                    <small>Try: <code>&lt;script&gt;alert(1)&lt;/script&gt;</code></small>
                </li>
                <li>
                    <a href="/profile/1">3. Insecure Direct Object Reference (IDOR)</a><br>
                    <small>Change the user ID in URL to 2 or 3</small>
                </li>
                <li>
                    <a href="/file?name=test.txt">4. Path Traversal</a><br>
                    <small>Try: <code>?name=../vulnerable-app.py</code></small>
                </li>
                <li>
                    <a href="/api/login">5. Weak JWT (API)</a><br>
                    <small>Login via API, decode JWT, modify claims</small>
                </li>
                <li>
                    <a href="/ssrf">6. Server-Side Request Forgery</a><br>
                    <small>Try: <code>http://localhost:5000/admin</code></small>
                </li>
                <li>
                    <a href="/upload">7. File Upload Bypass</a><br>
                    <small>Upload .php file as .jpg</small>
                </li>
            </ul>

            <h3>Credentials:</h3>
            <ul>
                <li>admin / admin123</li>
                <li>user / password</li>
                <li>test / test123</li>
            </ul>

            <h3>Pro Tips:</h3>
            <ul>
                <li>Use Burp Suite to intercept requests</li>
                <li>Send requests to Repeater for testing</li>
                <li>Try fuzzing with ffuf</li>
                <li>Document each vulnerability you find</li>
                <li>After finding a bug, try to understand HOW TO FIX IT</li>
            </ul>
        </div>
    </body>
    </html>
    ''')

# Vulnerability 1: SQL Injection
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        password_hash = hashlib.md5(password.encode()).hexdigest()

        # VULNERABLE: SQL Injection via string concatenation
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password_hash}'"

        conn = sqlite3.connect('vulnapp.db')
        c = conn.cursor()

        try:
            result = c.execute(query).fetchone()
            conn.close()

            if result:
                return f'''
                    <h2 style="color: green;">✅ Login Successful!</h2>
                    <p>Welcome, {result[1]}!</p>
                    <p>Role: {result[4]}</p>
                    <p><strong>SQL Query Executed:</strong></p>
                    <pre style="background: #f5f5f5; padding: 10px;">{query}</pre>
                    <a href="/">← Back</a>
                '''
            else:
                return f'<h2 style="color: red;">❌ Login Failed</h2><p>Query: {query}</p><a href="/login">Try Again</a>'
        except Exception as e:
            conn.close()
            return f'<h2 style="color: red;">Error:</h2><pre>{str(e)}</pre><p>Query: {query}</p><a href="/login">Back</a>'

    return render_template_string('''
        <h2>🔐 SQL Injection Practice</h2>
        <form method="post">
            <p>Username: <input name="username" value="admin"></p>
            <p>Password: <input name="password" type="password" value="admin123"></p>
            <button type="submit">Login</button>
        </form>
        <h3>Try these payloads:</h3>
        <ul>
            <li>username: <code>admin' OR '1'='1</code></li>
            <li>username: <code>admin'--</code></li>
            <li>username: <code>' UNION SELECT 1,2,3,4,5,6--</code></li>
        </ul>
        <a href="/">← Back</a>
    ''')

# Vulnerability 2: XSS
@app.route('/search')
def search():
    query = request.args.get('q', '')

    # VULNERABLE: No output escaping
    return render_template_string(f'''
        <h2>🔍 XSS Practice</h2>
        <form method="get">
            <input name="q" value="{query}" placeholder="Search...">
            <button>Search</button>
        </form>
        <h3>Search Results for: {query}</h3>
        <p>No results found (this is just for XSS practice)</p>

        <h3>Try these payloads:</h3>
        <ul>
            <li><code>&lt;script&gt;alert(1)&lt;/script&gt;</code></li>
            <li><code>&lt;img src=x onerror=alert(document.domain)&gt;</code></li>
            <li><code>&lt;svg onload=alert(1)&gt;</code></li>
        </ul>
        <a href="/">← Back</a>
    ''')

# Vulnerability 3: IDOR
@app.route('/profile/<user_id>')
def profile(user_id):
    # VULNERABLE: No authorization check
    conn = sqlite3.connect('vulnapp.db')
    c = conn.cursor()
    user = c.execute(f"SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()

    if user:
        return render_template_string('''
            <h2>👤 User Profile (IDOR Practice)</h2>
            <div style="background: #f5f5f5; padding: 20px; border-radius: 4px;">
                <p><strong>ID:</strong> {{user[0]}}</p>
                <p><strong>Username:</strong> {{user[1]}}</p>
                <p><strong>Email:</strong> {{user[2]}}</p>
                <p><strong>Role:</strong> {{user[4]}}</p>
                <p><strong>SSN:</strong> {{user[5]}} <span style="color: red;">← Sensitive data!</span></p>
            </div>
            <h3>IDOR Testing:</h3>
            <ul>
                <li>Change user_id in URL to 1, 2, or 3</li>
                <li>You should NOT be able to access other users' profiles!</li>
                <li>But you can... because there's no authorization check 🐛</li>
            </ul>
            <p><a href="/profile/1">User 1</a> | <a href="/profile/2">User 2</a> | <a href="/profile/3">User 3</a></p>
            <a href="/">← Back</a>
        ''', user=user)

    return '<h2>User not found</h2><a href="/">← Back</a>'

# Vulnerability 4: Path Traversal
@app.route('/file')
def read_file():
    filename = request.args.get('name', 'test.txt')

    try:
        # VULNERABLE: No path sanitization
        with open(filename, 'r') as f:
            content = f.read()

        return render_template_string('''
            <h2>📄 File Reader (Path Traversal Practice)</h2>
            <p><strong>Reading:</strong> {{filename}}</p>
            <pre style="background: #f5f5f5; padding: 20px; border-radius: 4px;">{{content}}</pre>
            <h3>Try these paths:</h3>
            <ul>
                <li><code>?name=../vulnerable-app.py</code></li>
                <li><code>?name=../../etc/passwd</code> (if on Linux)</li>
                <li><code>?name=test.txt</code></li>
            </ul>
            <a href="/">← Back</a>
        ''', filename=filename, content=content)
    except Exception as e:
        return f'<h2>Error reading file:</h2><pre>{str(e)}</pre><a href="/">← Back</a>'

# Vulnerability 5: Weak JWT
@app.route('/api/login', methods=['GET', 'POST'])
def api_login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        # Check credentials (simplified)
        if username == 'admin' and password == 'admin123':
            # VULNERABLE: Weak secret, client-controlled claims
            token = jwt.encode({
                'username': username,
                'role': 'user',  # ← Modify this to 'admin' in decoded JWT!
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            }, app.secret_key, algorithm='HS256')

            return jsonify({
                'token': token,
                'hint': 'Decode this JWT at jwt.io, change role to admin, re-encode with secret: insecure_secret_key_12345'
            })

        return jsonify({'error': 'Invalid credentials'}), 401

    return render_template_string('''
        <h2>🔑 JWT API (Weak JWT Practice)</h2>
        <h3>Step 1: Get Token</h3>
        <pre style="background: #f5f5f5; padding: 10px;">
curl -X POST http://localhost:5000/api/login \\
  -H "Content-Type: application/json" \\
  -d '{"username":"admin","password":"admin123"}'
        </pre>

        <h3>Step 2: Decode at jwt.io</h3>
        <p>Change <code>"role": "user"</code> to <code>"role": "admin"</code></p>
        <p>Secret: <code>insecure_secret_key_12345</code></p>

        <h3>Step 3: Access Admin Endpoint</h3>
        <pre style="background: #f5f5f5; padding: 10px;">
curl http://localhost:5000/api/admin \\
  -H "Authorization: Bearer [YOUR_MODIFIED_TOKEN]"
        </pre>
        <a href="/">← Back</a>
    ''')

@app.route('/api/admin')
def api_admin():
    auth = request.headers.get('Authorization', '')

    if not auth.startswith('Bearer '):
        return jsonify({'error': 'No token provided'}), 401

    token = auth.replace('Bearer ', '')

    try:
        # VULNERABLE: Trusts client-controlled JWT claims
        payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])

        if payload.get('role') == 'admin':
            return jsonify({
                'message': '🎉 Success! You accessed the admin endpoint!',
                'flag': 'FLAG{jwt_tampering_works}',
                'user': payload.get('username'),
                'role': payload.get('role')
            })

        return jsonify({'error': 'Admin role required'}), 403
    except Exception as e:
        return jsonify({'error': str(e)}), 401

# Vulnerability 6: SSRF
@app.route('/ssrf', methods=['GET', 'POST'])
def ssrf():
    if request.method == 'POST':
        url = request.form.get('url', '')

        try:
            # VULNERABLE: No URL validation
            import urllib.request
            response = urllib.request.urlopen(url, timeout=5)
            content = response.read().decode('utf-8')

            return render_template_string('''
                <h2>📡 SSRF Result</h2>
                <p><strong>Fetched:</strong> {{url}}</p>
                <pre style="background: #f5f5f5; padding: 20px; max-height: 400px; overflow: auto;">{{content}}</pre>
                <a href="/ssrf">← Back</a>
            ''', url=url, content=content)
        except Exception as e:
            return f'<h2>Error:</h2><pre>{str(e)}</pre><a href="/ssrf">← Back</a>'

    return render_template_string('''
        <h2>🌐 SSRF Practice</h2>
        <form method="post">
            <p>URL: <input name="url" value="http://localhost:5000/" style="width: 400px;"></p>
            <button>Fetch URL</button>
        </form>
        <h3>Try these URLs:</h3>
        <ul>
            <li><code>http://localhost:5000/</code> (internal access)</li>
            <li><code>http://localhost:5000/admin</code> (hidden endpoint)</li>
            <li><code>file:///etc/passwd</code> (local file - may not work)</li>
        </ul>
        <a href="/">← Back</a>
    ''')

# Hidden admin endpoint (for SSRF)
@app.route('/admin')
def admin():
    return '''
        <h2>🚨 Hidden Admin Panel</h2>
        <p>You shouldn't be able to access this from outside...</p>
        <p>...but SSRF makes it possible!</p>
        <p><strong>FLAG:</strong> FLAG{ssrf_internal_access}</p>
    '''

# Vulnerability 7: File Upload (simplified)
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        if 'file' in request.files:
            file = request.files['file']
            filename = file.filename

            # VULNERABLE: No file type validation
            file.save(f'uploads/{filename}')

            return f'''
                <h2>✅ File Uploaded!</h2>
                <p>Filename: {filename}</p>
                <p><strong>Vulnerability:</strong> No validation - try uploading a .php file!</p>
                <a href="/upload">← Back</a>
            '''

    return render_template_string('''
        <h2>📤 File Upload Practice</h2>
        <form method="post" enctype="multipart/form-data">
            <p>File: <input type="file" name="file"></p>
            <button>Upload</button>
        </form>
        <h3>Try:</h3>
        <ul>
            <li>Upload a .php file</li>
            <li>Upload .php with .jpg extension</li>
            <li>Upload file with null byte (file.php%00.jpg)</li>
        </ul>
        <a href="/">← Back</a>
    ''')

if __name__ == '__main__':
    os.makedirs('uploads', exist_ok=True)
    print("=" * 60)
    print("🎯 Vulnerable Practice App Starting...")
    print("=" * 60)
    print("⚠️  WARNING: This is INTENTIONALLY VULNERABLE!")
    print("    For local practice only - DO NOT expose to internet!")
    print("=" * 60)
    print("📍 Access at: http://localhost:5000")
    print("=" * 60)
    app.run(debug=True, host='127.0.0.1', port=5000)
