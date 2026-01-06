#!/usr/bin/env python3
"""
Academy Node for Pythonista
HTTP server that integrates with The Academy orchestrator
Provides GitHub access, mobile tools, and bug bounty capabilities
"""

from flask import Flask, request, jsonify
import sys
from pathlib import Path
import json
import os
import hmac
import hashlib
from datetime import datetime

# Import our GitHub client
try:
    from github_client import GitHubClient, BugBountyGitHub
    GITHUB_AVAILABLE = True
except ImportError:
    GITHUB_AVAILABLE = False
    print("⚠️  GitHub client not available")

# Import mobile tools
try:
    from quick_recon import MobileRecon
    RECON_AVAILABLE = True
except ImportError:
    RECON_AVAILABLE = False

try:
    from mobile_reporter import MobileReporter
    REPORTER_AVAILABLE = True
except ImportError:
    REPORTER_AVAILABLE = False

app = Flask(__name__)

# ===================================================================
# SECURITY & CONFIGURATION
# ===================================================================

# Academy secret key for HMAC verification
# IMPORTANT: Change this to match your orchestrator's SECRET_KEY
SECRET_KEY = os.environ.get(
    'ACADEMY_SECRET_KEY',
    b'5fb9c5db0e37d58bf7ef8e86070d545199b587756ed0026330854ab4a023274e'
)

if isinstance(SECRET_KEY, str):
    SECRET_KEY = SECRET_KEY.encode('utf-8')


def verify_signature(payload: bytes, signature: str) -> bool:
    """
    Verify HMAC signature for secure communication

    Args:
        payload: Request payload as bytes
        signature: HMAC signature from request header

    Returns:
        True if signature is valid
    """
    expected = hmac.new(SECRET_KEY, payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, expected)


def require_signature(f):
    """Decorator to require HMAC signature on endpoints"""
    def decorated_function(*args, **kwargs):
        signature = request.headers.get('X-Academy-Signature')

        if not signature:
            return jsonify({'error': 'Missing signature'}), 403

        # Get raw request data
        payload = json.dumps(request.get_json(), sort_keys=True).encode('utf-8')

        if not verify_signature(payload, signature):
            return jsonify({'error': 'Invalid signature'}), 403

        return f(*args, **kwargs)

    decorated_function.__name__ = f.__name__
    return decorated_function


# ===================================================================
# FILE MANAGEMENT ENDPOINTS
# ===================================================================

@app.route('/write_file', methods=['POST'])
@require_signature
def write_file():
    """
    Write content to a file on the iPhone

    POST /write_file
    Headers: X-Academy-Signature: <hmac_signature>
    {
        "path": "BugBounty/reports/xss_finding.md",
        "content": "# XSS Report\\n...",
        "append": false
    }
    """
    data = request.get_json()
    file_path = data.get('path')
    content = data.get('content')
    append = data.get('append', False)

    if not file_path or content is None:
        return jsonify({'error': 'path and content required'}), 400

    try:
        # Base directory for file operations (iOS Documents folder)
        base_dir = Path.home() / 'Documents'
        full_path = base_dir / file_path

        # Security: Ensure path is within Documents directory
        try:
            full_path.resolve().relative_to(base_dir.resolve())
        except ValueError:
            return jsonify({'error': 'Path must be within Documents directory'}), 403

        # Create parent directories
        full_path.parent.mkdir(parents=True, exist_ok=True)

        # Write file
        mode = 'a' if append else 'w'
        with open(full_path, mode, encoding='utf-8') as f:
            f.write(content)

        return jsonify({
            'success': True,
            'message': f'File written successfully',
            'path': str(full_path.relative_to(base_dir)),
            'size': full_path.stat().st_size,
            'mode': 'append' if append else 'write'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/read_file', methods=['POST'])
@require_signature
def read_file():
    """
    Read a file from the iPhone

    POST /read_file
    Headers: X-Academy-Signature: <hmac_signature>
    {
        "path": "BugBounty/reports/findings.md"
    }
    """
    data = request.get_json()
    file_path = data.get('path')

    if not file_path:
        return jsonify({'error': 'path required'}), 400

    try:
        base_dir = Path.home() / 'Documents'
        full_path = base_dir / file_path

        # Security check
        try:
            full_path.resolve().relative_to(base_dir.resolve())
        except ValueError:
            return jsonify({'error': 'Path must be within Documents directory'}), 403

        if not full_path.exists():
            return jsonify({'error': 'File not found'}), 404

        content = full_path.read_text(encoding='utf-8')

        return jsonify({
            'success': True,
            'content': content,
            'path': str(full_path.relative_to(base_dir)),
            'size': full_path.stat().st_size,
            'modified': datetime.fromtimestamp(full_path.stat().st_mtime).isoformat()
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/list_files', methods=['POST'])
@require_signature
def list_files():
    """
    List files in a directory

    POST /list_files
    Headers: X-Academy-Signature: <hmac_signature>
    {
        "path": "BugBounty/reports",
        "pattern": "*.md"
    }
    """
    data = request.get_json()
    dir_path = data.get('path', '')
    pattern = data.get('pattern', '*')

    try:
        base_dir = Path.home() / 'Documents'
        full_path = base_dir / dir_path

        # Security check
        try:
            full_path.resolve().relative_to(base_dir.resolve())
        except ValueError:
            return jsonify({'error': 'Path must be within Documents directory'}), 403

        if not full_path.exists():
            return jsonify({'error': 'Directory not found'}), 404

        files = []
        for item in full_path.glob(pattern):
            files.append({
                'name': item.name,
                'path': str(item.relative_to(base_dir)),
                'type': 'file' if item.is_file() else 'directory',
                'size': item.stat().st_size if item.is_file() else 0,
                'modified': datetime.fromtimestamp(item.stat().st_mtime).isoformat()
            })

        return jsonify({
            'success': True,
            'files': sorted(files, key=lambda x: x['name']),
            'count': len(files)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/delete_file', methods=['POST'])
@require_signature
def delete_file():
    """
    Delete a file

    POST /delete_file
    Headers: X-Academy-Signature: <hmac_signature>
    {
        "path": "BugBounty/temp/old_scan.txt"
    }
    """
    data = request.get_json()
    file_path = data.get('path')

    if not file_path:
        return jsonify({'error': 'path required'}), 400

    try:
        base_dir = Path.home() / 'Documents'
        full_path = base_dir / file_path

        # Security check
        try:
            full_path.resolve().relative_to(base_dir.resolve())
        except ValueError:
            return jsonify({'error': 'Path must be within Documents directory'}), 403

        if not full_path.exists():
            return jsonify({'error': 'File not found'}), 404

        full_path.unlink()

        return jsonify({
            'success': True,
            'message': f'File deleted successfully',
            'path': str(Path(file_path))
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ===================================================================
# GITHUB ENDPOINTS
# ===================================================================

@app.route('/github_fetch_file', methods=['POST'])
def github_fetch_file():
    """
    Fetch a file from GitHub repository

    POST /github_fetch_file
    {
        "repo": "owner/repo",
        "path": "path/to/file.py",
        "branch": "main",
        "token": "optional_github_token"
    }
    """
    if not GITHUB_AVAILABLE:
        return jsonify({'error': 'GitHub client not available'}), 500

    data = request.get_json()
    repo = data.get('repo')
    path = data.get('path')
    branch = data.get('branch', 'main')
    token = data.get('token', os.environ.get('GITHUB_TOKEN'))

    if not repo or not path:
        return jsonify({'error': 'repo and path required'}), 400

    try:
        client = GitHubClient(token)
        file_data = client.get_file(repo, path, branch)

        return jsonify({
            'success': True,
            'content': file_data.get('decoded_content', ''),
            'name': file_data.get('name'),
            'size': file_data.get('size'),
            'sha': file_data.get('sha'),
            'url': file_data.get('html_url')
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/github_list_dir', methods=['POST'])
def github_list_dir():
    """
    List files in a GitHub directory

    POST /github_list_dir
    {
        "repo": "owner/repo",
        "path": "directory/path",
        "branch": "main",
        "token": "optional_github_token"
    }
    """
    if not GITHUB_AVAILABLE:
        return jsonify({'error': 'GitHub client not available'}), 500

    data = request.get_json()
    repo = data.get('repo')
    path = data.get('path', '')
    branch = data.get('branch', 'main')
    token = data.get('token', os.environ.get('GITHUB_TOKEN'))

    if not repo:
        return jsonify({'error': 'repo required'}), 400

    try:
        client = GitHubClient(token)
        items = client.list_directory(repo, path, branch)

        return jsonify({
            'success': True,
            'items': [
                {
                    'name': item.get('name'),
                    'path': item.get('path'),
                    'type': item.get('type'),
                    'size': item.get('size')
                }
                for item in items
            ]
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/github_clone_repo', methods=['POST'])
def github_clone_repo():
    """
    Clone a repository (download files via API)

    POST /github_clone_repo
    {
        "repo": "owner/repo",
        "local_dir": "/path/to/save",
        "branch": "main",
        "patterns": ["*.py", "*.md"],
        "token": "optional_github_token"
    }
    """
    if not GITHUB_AVAILABLE:
        return jsonify({'error': 'GitHub client not available'}), 500

    data = request.get_json()
    repo = data.get('repo')
    local_dir = data.get('local_dir')
    branch = data.get('branch', 'main')
    patterns = data.get('patterns')
    token = data.get('token', os.environ.get('GITHUB_TOKEN'))

    if not repo or not local_dir:
        return jsonify({'error': 'repo and local_dir required'}), 400

    try:
        client = GitHubClient(token)
        result_path = client.clone_repo(
            repo,
            Path(local_dir),
            branch,
            include_patterns=patterns
        )

        return jsonify({
            'success': True,
            'path': str(result_path),
            'message': f'Repository cloned to {result_path}'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/github_search_code', methods=['POST'])
def github_search_code():
    """
    Search for code on GitHub

    POST /github_search_code
    {
        "query": "search query",
        "repo": "optional_owner/repo",
        "token": "optional_github_token"
    }
    """
    if not GITHUB_AVAILABLE:
        return jsonify({'error': 'GitHub client not available'}), 500

    data = request.get_json()
    query = data.get('query')
    repo = data.get('repo')
    token = data.get('token', os.environ.get('GITHUB_TOKEN'))

    if not query:
        return jsonify({'error': 'query required'}), 400

    try:
        client = GitHubClient(token)
        results = client.search_code(query, repo)

        return jsonify({
            'success': True,
            'results': [
                {
                    'name': r.get('name'),
                    'path': r.get('path'),
                    'repository': r.get('repository', {}).get('full_name'),
                    'url': r.get('html_url')
                }
                for r in results[:20]  # Limit to 20 results
            ]
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ===================================================================
# BUG BOUNTY TOOLS ENDPOINTS
# ===================================================================

@app.route('/recon', methods=['POST'])
def run_recon():
    """
    Run quick reconnaissance

    POST /recon
    {
        "domain": "example.com",
        "verbose": false
    }
    """
    if not RECON_AVAILABLE:
        return jsonify({'error': 'Recon tool not available'}), 500

    data = request.get_json()
    domain = data.get('domain')
    verbose = data.get('verbose', False)

    if not domain:
        return jsonify({'error': 'domain required'}), 400

    try:
        recon = MobileRecon(domain, verbose=verbose)
        recon.enumerate_subdomains()

        return jsonify({
            'success': True,
            'domain': domain,
            'subdomains': [s['domain'] for s in recon.results['subdomains']],
            'ips': list(recon.results['ips']),
            'count': len(recon.results['subdomains'])
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/report', methods=['POST'])
def generate_report():
    """
    Generate bug report

    POST /report
    {
        "template": "xss",
        "target": "https://example.com",
        "description": "Brief description",
        "poc": "Proof of concept",
        "steps": "Steps to reproduce"
    }
    """
    if not REPORTER_AVAILABLE:
        return jsonify({'error': 'Reporter tool not available'}), 500

    data = request.get_json()
    template_key = data.get('template', 'xss')
    target = data.get('target')
    details = {
        'description': data.get('description', ''),
        'poc': data.get('poc', ''),
        'steps': data.get('steps', ''),
        'url': data.get('url', target)
    }

    if not target:
        return jsonify({'error': 'target required'}), 400

    try:
        reporter = MobileReporter()
        report_content = reporter.generate_report(template_key, target, details)

        # Optionally save
        if data.get('save', False):
            filename = reporter.save_report(report_content, target, template_key)
            return jsonify({
                'success': True,
                'report': report_content,
                'saved': str(filename)
            })

        return jsonify({
            'success': True,
            'report': report_content
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ===================================================================
# HEALTH & STATUS
# ===================================================================

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'node': 'pythonista',
        'capabilities': {
            'github': GITHUB_AVAILABLE,
            'recon': RECON_AVAILABLE,
            'reporter': REPORTER_AVAILABLE
        }
    })


@app.route('/api/ping', methods=['GET'])
def ping():
    """Simple ping endpoint for device discovery"""
    return jsonify({
        'status': 'online',
        'device': 'iPhone',
        'node': 'Pythonista Academy Node'
    })


@app.route('/capabilities', methods=['GET'])
def capabilities():
    """Return available capabilities and tools"""
    tools = []

    if GITHUB_AVAILABLE:
        tools.extend([
            'github_fetch_file',
            'github_list_dir',
            'github_clone_repo',
            'github_search_code'
        ])

    if RECON_AVAILABLE:
        tools.append('recon')

    if REPORTER_AVAILABLE:
        tools.append('report')

    return jsonify({
        'node': 'pythonista',
        'platform': 'iOS',
        'tools': tools,
        'status': 'ready'
    })


# ===================================================================
# MAIN
# ===================================================================

def main():
    """Start the Academy node server"""
    import argparse

    parser = argparse.ArgumentParser(description='Academy Node for Pythonista')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')

    args = parser.parse_args()

    print(f"""
╔═══════════════════════════════════════╗
║  🎓 Academy Node - Pythonista        ║
╚═══════════════════════════════════════╝

📱 Device: iPhone/iPad
🐍 Platform: Pythonista
🌐 Server: http://{args.host}:{args.port}

Available Capabilities:
{'✅ GitHub Integration' if GITHUB_AVAILABLE else '❌ GitHub Integration (install requests)'}
{'✅ Mobile Recon' if RECON_AVAILABLE else '❌ Mobile Recon'}
{'✅ Report Generator' if REPORTER_AVAILABLE else '❌ Report Generator'}

🎯 Ready to serve The Academy!
""")

    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == '__main__':
    main()
