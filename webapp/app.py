"""
Flask application for Couch Potato Research Tools
Live demonstrations of physics and security research capabilities
"""

from flask import Flask, render_template, request, jsonify
import sys
import os

# Add tools directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'tools'))

from physics_tools import (
    calculate_eigenmode_predictions,
    search_particle_masses,
    analyze_ball_lightning_harmonics,
    calculate_boundary_energy
)

from security_tools import (
    generate_subdomain_wordlist,
    generate_idor_test_cases,
    generate_vulnerability_report,
    create_methodology_checklist
)

app = Flask(__name__)

# ===== Main Routes =====

@app.route('/')
def index():
    """Landing page for live tools"""
    return render_template('index.html')

# ===== Physics Research Tools =====

@app.route('/physics')
def physics_tools():
    """Physics research tools landing page"""
    return render_template('physics_tools.html')

@app.route('/physics/eigenmode-calculator')
def eigenmode_calculator():
    """Interactive eigenmode mass prediction calculator"""
    return render_template('eigenmode_calculator.html')

@app.route('/api/physics/eigenmode', methods=['POST'])
def api_eigenmode():
    """Calculate eigenmode predictions"""
    data = request.get_json()
    try:
        icosahedron_freq = float(data.get('frequency', 1.0))
        results = calculate_eigenmode_predictions(icosahedron_freq)
        return jsonify({'success': True, 'results': results})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/physics/hep-falsification')
def hep_falsification():
    """Particle mass search tool"""
    return render_template('hep_falsification.html')

@app.route('/api/physics/search-masses', methods=['POST'])
def api_search_masses():
    """Search for particle masses in predicted ranges"""
    data = request.get_json()
    try:
        predicted_masses = data.get('masses', [2.04, 4.6, 12.8])
        tolerance = float(data.get('tolerance', 0.1))
        results = search_particle_masses(predicted_masses, tolerance)
        return jsonify({'success': True, 'results': results})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/physics/ball-lightning-analyzer')
def ball_lightning_analyzer():
    """Ball lightning harmonic analysis tool"""
    return render_template('ball_lightning_analyzer.html')

@app.route('/api/physics/analyze-harmonics', methods=['POST'])
def api_analyze_harmonics():
    """Analyze ball lightning spectroscopy data"""
    data = request.get_json()
    try:
        frequency_data = data.get('frequencies', [])
        results = analyze_ball_lightning_harmonics(frequency_data)
        return jsonify({'success': True, 'results': results})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/physics/boundary-energy')
def boundary_energy():
    """Boundary energy density calculator"""
    return render_template('boundary_energy.html')

@app.route('/api/physics/boundary-energy', methods=['POST'])
def api_boundary_energy():
    """Calculate ∇φ² energy density at boundaries"""
    data = request.get_json()
    try:
        field_gradient = float(data.get('gradient', 1.0))
        boundary_width = float(data.get('width', 1.0))
        results = calculate_boundary_energy(field_gradient, boundary_width)
        return jsonify({'success': True, 'results': results})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

# ===== Security Research Tools =====

@app.route('/security')
def security_tools():
    """Security research tools landing page"""
    return render_template('security_tools.html')

@app.route('/security/subdomain-generator')
def subdomain_generator():
    """Smart subdomain wordlist generator"""
    return render_template('subdomain_generator.html')

@app.route('/api/security/generate-subdomains', methods=['POST'])
def api_generate_subdomains():
    """Generate contextual subdomain wordlist"""
    data = request.get_json()
    try:
        domain = data.get('domain', 'example.com')
        keywords = data.get('keywords', [])
        results = generate_subdomain_wordlist(domain, keywords)
        return jsonify({'success': True, 'wordlist': results})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/security/idor-tester')
def idor_tester():
    """IDOR parameter test case generator"""
    return render_template('idor_tester.html')

@app.route('/api/security/generate-idor-tests', methods=['POST'])
def api_generate_idor_tests():
    """Generate IDOR test cases"""
    data = request.get_json()
    try:
        endpoint = data.get('endpoint', '/api/user/profile')
        param_name = data.get('param', 'user_id')
        current_value = data.get('value', '123')
        results = generate_idor_test_cases(endpoint, param_name, current_value)
        return jsonify({'success': True, 'test_cases': results})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/security/report-generator')
def report_generator():
    """Vulnerability report template generator"""
    return render_template('report_generator.html')

@app.route('/api/security/generate-report', methods=['POST'])
def api_generate_report():
    """Generate formatted vulnerability report"""
    data = request.get_json()
    try:
        platform = data.get('platform', 'generic')
        vuln_type = data.get('type', 'IDOR')
        severity = data.get('severity', 'Medium')
        results = generate_vulnerability_report(platform, vuln_type, severity)
        return jsonify({'success': True, 'report': results})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/security/methodology-checklist')
def methodology_checklist():
    """Interactive testing methodology checklist"""
    return render_template('methodology_checklist.html')

@app.route('/api/security/get-checklist', methods=['POST'])
def api_get_checklist():
    """Get methodology checklist for target type"""
    data = request.get_json()
    try:
        target_type = data.get('type', 'web_app')
        results = create_methodology_checklist(target_type)
        return jsonify({'success': True, 'checklist': results})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

# ===== Error Handlers =====

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    # For local development
    app.run(debug=True, host='0.0.0.0', port=5000)
