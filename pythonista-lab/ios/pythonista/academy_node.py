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
