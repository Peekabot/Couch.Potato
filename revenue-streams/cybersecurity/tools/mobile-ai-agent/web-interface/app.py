#!/usr/bin/env python3
"""
Mobile-Friendly Web Control Interface
Simple Flask app for controlling the recon agent from mobile browser
"""

from flask import Flask, render_template, request, jsonify, send_file
import os
import json
import subprocess
from datetime import datetime
from pathlib import Path

app = Flask(__name__)

# Configuration
BASE_DIR = Path(__file__).parent.parent
CONFIG_FILE = BASE_DIR / "config" / "config.json"
RESULTS_DIR = BASE_DIR / "results"
LOGS_DIR = BASE_DIR / "logs"


def load_config():
    """Load configuration"""
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}


def save_config(config):
    """Save configuration"""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)


def get_recent_scans(limit=10):
    """Get recent scan results"""
    scans = []
    if RESULTS_DIR.exists():
        for target_dir in RESULTS_DIR.iterdir():
            if target_dir.is_dir():
                # Get latest report
                reports = list(target_dir.glob("report_*.md"))
                if reports:
                    latest_report = max(reports, key=lambda p: p.stat().st_mtime)
                    scans.append({
                        "target": target_dir.name.replace('_', '.'),
                        "timestamp": datetime.fromtimestamp(latest_report.stat().st_mtime).isoformat(),
                        "report_path": str(latest_report)
                    })

    return sorted(scans, key=lambda x: x['timestamp'], reverse=True)[:limit]


def get_logs(lines=50):
    """Get recent log lines"""
    log_file = LOGS_DIR / "recon_agent.log"
    if log_file.exists():
        with open(log_file, 'r') as f:
            all_lines = f.readlines()
            return all_lines[-lines:]
    return []


@app.route('/')
def index():
    """Main dashboard"""
    config = load_config()
    recent_scans = get_recent_scans()
    logs = get_logs(30)

    return render_template('index.html',
                         config=config,
                         recent_scans=recent_scans,
                         logs=logs)


@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new scan"""
    data = request.json
    target = data.get('target', '').strip()

    if not target:
        return jsonify({"error": "Target required"}), 400

    # Run scan in background
    try:
        script_path = BASE_DIR / "scripts" / "recon_agent.py"
        subprocess.Popen([
            'python3',
            str(script_path),
            '-t',
            target
        ])

        return jsonify({
            "status": "started",
            "target": target,
            "message": f"Scan started for {target}"
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/config', methods=['GET', 'POST'])
def manage_config():
    """Get or update configuration"""
    if request.method == 'GET':
        config = load_config()
        # Redact sensitive info
        if 'notification' in config:
            if 'telegram_bot_token' in config['notification']:
                config['notification']['telegram_bot_token'] = '***'
            if 'smtp_password' in config['notification']:
                config['notification']['smtp_password'] = '***'
        return jsonify(config)

    elif request.method == 'POST':
        try:
            new_config = request.json
            save_config(new_config)
            return jsonify({"status": "success", "message": "Configuration updated"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500


@app.route('/api/targets', methods=['GET', 'POST', 'DELETE'])
def manage_targets():
    """Manage target list"""
    config = load_config()

    if request.method == 'GET':
        return jsonify({"targets": config.get('targets', [])})

    elif request.method == 'POST':
        data = request.json
        new_target = data.get('target', '').strip()

        if new_target:
            if 'targets' not in config:
                config['targets'] = []
            if new_target not in config['targets']:
                config['targets'].append(new_target)
                save_config(config)
                return jsonify({"status": "success", "targets": config['targets']})
            else:
                return jsonify({"error": "Target already exists"}), 400
        else:
            return jsonify({"error": "Target required"}), 400

    elif request.method == 'DELETE':
        data = request.json
        target = data.get('target', '').strip()

        if target and 'targets' in config and target in config['targets']:
            config['targets'].remove(target)
            save_config(config)
            return jsonify({"status": "success", "targets": config['targets']})
        else:
            return jsonify({"error": "Target not found"}), 404


@app.route('/api/scans')
def list_scans():
    """List recent scans"""
    scans = get_recent_scans(20)
    return jsonify({"scans": scans})


@app.route('/api/logs')
def view_logs():
    """View recent logs"""
    lines = request.args.get('lines', 50, type=int)
    logs = get_logs(lines)
    return jsonify({"logs": logs})


@app.route('/api/report/<path:report_path>')
def get_report(report_path):
    """Download or view a report"""
    try:
        full_path = RESULTS_DIR / report_path
        if full_path.exists():
            return send_file(full_path, as_attachment=False)
        else:
            return jsonify({"error": "Report not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/status')
def status():
    """Get system status"""
    return jsonify({
        "status": "running",
        "timestamp": datetime.now().isoformat(),
        "total_scans": len(get_recent_scans(999)),
        "disk_usage": "N/A"  # Could add disk usage check
    })


if __name__ == '__main__':
    # Create necessary directories
    RESULTS_DIR.mkdir(exist_ok=True)
    LOGS_DIR.mkdir(exist_ok=True)
    (BASE_DIR / "config").mkdir(exist_ok=True)

    # Run app
    app.run(debug=False, host='0.0.0.0', port=5000)
