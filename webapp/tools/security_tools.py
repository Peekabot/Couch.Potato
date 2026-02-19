"""
Security Research Tools
Live implementations of bug bounty methodologies and automation
"""

from typing import List, Dict, Any
import re

def generate_subdomain_wordlist(domain: str, keywords: List[str] = None) -> Dict[str, Any]:
    """
    Generate contextual subdomain wordlist based on target domain and keywords

    This demonstrates systematic reconnaissance methodology

    Args:
        domain: Target domain (e.g., "example.com")
        keywords: Additional context keywords

    Returns:
        Generated wordlist with contextual subdomains
    """
    if keywords is None:
        keywords = []

    # Common subdomain patterns (based on 2025 Master Strategy)
    base_patterns = [
        # Development/Staging
        'dev', 'staging', 'stage', 'test', 'qa', 'uat', 'demo',
        'development', 'sandbox', 'preview',

        # API & Services
        'api', 'api-v1', 'api-v2', 'rest', 'graphql', 'ws', 'websocket',
        'service', 'services', 'internal',

        # Admin & Management
        'admin', 'administrator', 'management', 'panel', 'dashboard',
        'console', 'portal', 'control',

        # Infrastructure
        'mail', 'smtp', 'pop', 'imap', 'vpn', 'remote', 'ftp', 'sftp',
        'ssh', 'git', 'gitlab', 'jenkins', 'ci', 'cd',

        # Cloud & Hosting
        'cloud', 'aws', 'azure', 'gcp', 's3', 'storage', 'cdn',
        'static', 'assets', 'media', 'images',

        # Database
        'db', 'database', 'mysql', 'postgres', 'mongo', 'redis',
        'elastic', 'elasticsearch',

        # Monitoring & Logs
        'monitoring', 'metrics', 'logs', 'logging', 'grafana',
        'kibana', 'prometheus', 'splunk',

        # Legacy/Backup
        'old', 'legacy', 'backup', 'bak', 'archive', 'temp',
        'old-site', 'v1', 'v2', 'beta', 'alpha'
    ]

    # Environmental variations
    env_prefixes = ['dev', 'staging', 'test', 'prod', 'beta']
    env_variations = []
    for env in env_prefixes:
        env_variations.extend([
            f'{env}-api',
            f'{env}-admin',
            f'{env}-portal',
            f'{env}-dashboard'
        ])

    # Keyword-based generation
    keyword_variations = []
    for keyword in keywords:
        keyword_variations.extend([
            keyword,
            f'{keyword}-api',
            f'{keyword}-admin',
            f'{keyword}-portal',
            f'dev-{keyword}',
            f'staging-{keyword}',
            f'{keyword}-dev',
            f'{keyword}-staging'
        ])

    # Combine all
    all_subdomains = list(set(base_patterns + env_variations + keyword_variations))
    all_subdomains.sort()

    return {
        'domain': domain,
        'total_subdomains': len(all_subdomains),
        'wordlist': all_subdomains[:100],  # Limit for display
        'full_count': len(all_subdomains),
        'categories': {
            'base_patterns': len(base_patterns),
            'env_variations': len(env_variations),
            'keyword_variations': len(keyword_variations)
        },
        'usage': f'subfinder -d {domain} -w generated_wordlist.txt',
        'methodology': 'Phase 1: Deep Reconnaissance (2025 Master Strategy)'
    }

def generate_idor_test_cases(endpoint: str, param_name: str, current_value: str) -> Dict[str, Any]:
    """
    Generate IDOR (Insecure Direct Object Reference) test cases

    Demonstrates understanding of IDOR vulnerability class

    Args:
        endpoint: API endpoint (e.g., "/api/user/profile")
        param_name: Parameter to test (e.g., "user_id")
        current_value: Current user's value (e.g., "123")

    Returns:
        Test cases for IDOR vulnerability discovery
    """
    test_cases = []

    # Sequential ID manipulation
    try:
        current_int = int(current_value)
        test_cases.extend([
            {
                'test': 'Sequential -1',
                'value': str(current_int - 1),
                'description': 'Access previous user',
                'expected': 'Should return 403/401 if properly protected'
            },
            {
                'test': 'Sequential +1',
                'value': str(current_int + 1),
                'description': 'Access next user',
                'expected': 'Should return 403/401 if properly protected'
            },
            {
                'test': 'Admin user (ID=1)',
                'value': '1',
                'description': 'Attempt to access likely admin account',
                'expected': 'Should return 403/401 if properly protected'
            },
            {
                'test': 'High-value target',
                'value': '100',
                'description': 'Access established user account',
                'expected': 'Should return 403/401 if properly protected'
            }
        ])
    except ValueError:
        pass

    # Array parameter manipulation
    test_cases.append({
        'test': 'Array injection',
        'value': f'["{current_value}", "124", "125"]',
        'description': 'Try to access multiple IDs simultaneously',
        'expected': 'Should validate array contents or reject'
    })

    # UUID manipulation (if applicable)
    if '-' in current_value and len(current_value) > 20:
        test_cases.append({
            'test': 'UUID manipulation',
            'value': current_value[:-1] + 'a',  # Change last character
            'description': 'Modified UUID to access different resource',
            'expected': 'Should return 404 or 403'
        })

    # Wildcard attempts
    test_cases.extend([
        {
            'test': 'Wildcard (*)',
            'value': '*',
            'description': 'Attempt to access all resources',
            'expected': 'Should reject or sanitize'
        },
        {
            'test': 'SQL injection (basic)',
            'value': "1' OR '1'='1",
            'description': 'Test for SQL injection vulnerability',
            'expected': 'Should sanitize input'
        }
    ])

    # Negative/special values
    test_cases.extend([
        {
            'test': 'Zero value',
            'value': '0',
            'description': 'Edge case testing',
            'expected': 'Should handle gracefully'
        },
        {
            'test': 'Negative value',
            'value': '-1',
            'description': 'Negative ID (might bypass checks)',
            'expected': 'Should validate and reject'
        },
        {
            'test': 'Large number',
            'value': '999999999',
            'description': 'Integer overflow attempt',
            'expected': 'Should handle gracefully'
        }
    ])

    # Generate curl commands for testing
    curl_examples = []
    for test in test_cases[:5]:  # First 5 examples
        curl_examples.append({
            'test_name': test['test'],
            'command': f'curl "{endpoint}?{param_name}={test["value"]}" -H "Authorization: Bearer YOUR_TOKEN"'
        })

    return {
        'endpoint': endpoint,
        'parameter': param_name,
        'current_value': current_value,
        'test_cases': test_cases,
        'total_tests': len(test_cases),
        'curl_examples': curl_examples,
        'methodology': 'Phase 3: Logic Testing - IDOR Deep-Dive',
        'automation': {
            'burp_intruder': 'Use Intruder with generated payloads',
            'python_script': 'Iterate through test cases with requests library'
        }
    }

def generate_vulnerability_report(platform: str, vuln_type: str, severity: str) -> Dict[str, Any]:
    """
    Generate formatted vulnerability report template

    Demonstrates documentation and reporting skills

    Args:
        platform: Target platform (intigriti, hackerone, bugcrowd, generic)
        vuln_type: Vulnerability type (IDOR, SSRF, XSS, etc.)
        severity: Severity level (Critical, High, Medium, Low)

    Returns:
        Formatted vulnerability report template
    """
    # Platform-specific formatting
    platform_templates = {
        'hackerone': {
            'header': '## Summary\n\n',
            'sections': ['Description', 'Steps to Reproduce', 'Impact', 'Mitigation']
        },
        'intigriti': {
            'header': '**Title**: {title}\n**Severity**: {severity}\n\n',
            'sections': ['Description', 'Proof of Concept', 'Impact', 'Remediation']
        },
        'bugcrowd': {
            'header': '# Vulnerability Report\n\n',
            'sections': ['Summary', 'Technical Details', 'Reproduction Steps', 'Impact Assessment']
        },
        'generic': {
            'header': '# Vulnerability Report\n\n',
            'sections': ['Summary', 'Details', 'Proof of Concept', 'Impact', 'Recommendation']
        }
    }

    template = platform_templates.get(platform.lower(), platform_templates['generic'])

    # Vulnerability type specific content
    vuln_descriptions = {
        'IDOR': {
            'summary': 'Insecure Direct Object Reference allows unauthorized access to resources',
            'example_poc': '1. Login as User A (ID: 123)\n2. Change user_id parameter to 124\n3. Access User B\'s data without authorization',
            'impact': 'Unauthorized access to user data, privacy violation',
            'cvss_base': 7.5
        },
        'SSRF': {
            'summary': 'Server-Side Request Forgery allows internal network access',
            'example_poc': '1. Identify URL parameter\n2. Set URL to http://169.254.169.254/\n3. Access AWS metadata endpoint',
            'impact': 'Internal network enumeration, credential theft, potential RCE',
            'cvss_base': 9.0
        },
        'XSS': {
            'summary': 'Cross-Site Scripting allows arbitrary JavaScript execution',
            'example_poc': '1. Inject payload: <script>alert(document.cookie)</script>\n2. Payload reflects without sanitization\n3. Session hijacking possible',
            'impact': 'Session hijacking, credential theft, account takeover',
            'cvss_base': 7.0
        },
        'SQL_INJECTION': {
            'summary': 'SQL Injection allows database manipulation',
            'example_poc': '1. Inject payload: \' OR 1=1--\n2. Bypass authentication\n3. Extract database contents',
            'impact': 'Complete database compromise, data exfiltration',
            'cvss_base': 9.5
        }
    }

    vuln_info = vuln_descriptions.get(vuln_type.upper().replace(' ', '_'), vuln_descriptions['IDOR'])

    # Generate report
    report = f"""{template['header']}

## Vulnerability Type
{vuln_type}

## Severity
{severity} (CVSS Base: {vuln_info['cvss_base']})

## {template['sections'][0]}
{vuln_info['summary']}

The application fails to properly validate authorization for resource access, allowing authenticated users to access resources belonging to other users.

## {template['sections'][1]}
{vuln_info['example_poc']}

## {template['sections'][2]}
**Impact**: {severity}

{vuln_info['impact']}

**Affected Users**: All users
**Attack Complexity**: Low
**Privileges Required**: Authenticated user

## {template['sections'][3] if len(template['sections']) > 3 else 'Recommendation'}
Implement proper authorization checks:
1. Validate user ownership before resource access
2. Use indirect references (UUIDs instead of sequential IDs)
3. Implement access control lists (ACLs)
4. Add server-side validation for all requests

## Supporting Evidence
- Screenshots: [Attach here]
- HTTP Requests: [Attach here]
- Video PoC: [Optional]

## Timeline
- Discovered: [Date]
- Reported: [Date]
- Expected Response: Within 5 business days per platform SLA
"""

    return {
        'platform': platform,
        'vulnerability_type': vuln_type,
        'severity': severity,
        'report_markdown': report,
        'word_count': len(report.split()),
        'methodology': 'Professional vulnerability reporting framework',
        'template_source': f'templates/{platform.upper()}_TEMPLATE.md'
    }

def create_methodology_checklist(target_type: str) -> Dict[str, Any]:
    """
    Generate interactive testing methodology checklist

    Demonstrates systematic approach to security testing

    Args:
        target_type: Type of target (web_app, api, mobile, etc.)

    Returns:
        Comprehensive testing checklist
    """
    checklists = {
        'web_app': {
            'name': 'Web Application Testing',
            'phases': [
                {
                    'phase': 'Reconnaissance',
                    'tasks': [
                        'Subdomain enumeration (amass, subfinder)',
                        'Live host detection (httpx)',
                        'Technology fingerprinting (whatweb)',
                        'Wayback URL discovery',
                        'Shodan infrastructure search',
                        'JavaScript endpoint extraction'
                    ]
                },
                {
                    'phase': 'Discovery',
                    'tasks': [
                        'Directory brute-forcing (ffuf)',
                        'Parameter discovery',
                        'Hidden endpoint enumeration',
                        'File exposure checks (.git, .env, backup)',
                        '403 bypass attempts',
                        'Version-specific CVE scanning'
                    ]
                },
                {
                    'phase': 'Authentication',
                    'tasks': [
                        'Registration flow analysis',
                        'Password reset logic testing',
                        'Session management review',
                        'JWT token analysis',
                        'OAuth flow testing',
                        'MFA bypass attempts'
                    ]
                },
                {
                    'phase': 'Authorization',
                    'tasks': [
                        'IDOR testing (all resource IDs)',
                        'Privilege escalation attempts',
                        'Horizontal access control',
                        'Vertical access control',
                        'Path traversal testing',
                        'Missing function-level access control'
                    ]
                },
                {
                    'phase': 'Business Logic',
                    'tasks': [
                        'Price manipulation',
                        'Quantity/discount abuse',
                        'Race conditions',
                        'Workflow bypass',
                        'Referral system abuse',
                        'Coupon stacking'
                    ]
                },
                {
                    'phase': 'Input Validation',
                    'tasks': [
                        'XSS (reflected, stored, DOM)',
                        'SQL injection',
                        'Command injection',
                        'XXE (XML External Entity)',
                        'SSRF attempts',
                        'File upload validation'
                    ]
                }
            ]
        },
        'api': {
            'name': 'API Security Testing',
            'phases': [
                {
                    'phase': 'Discovery',
                    'tasks': [
                        'API endpoint enumeration',
                        'GraphQL introspection',
                        'Swagger/OpenAPI documentation',
                        'Version discovery (v1, v2, etc.)',
                        'Hidden method discovery (PUT, PATCH, DELETE)',
                        'Rate limiting identification'
                    ]
                },
                {
                    'phase': 'Authentication',
                    'tasks': [
                        'API key exposure',
                        'JWT token validation',
                        'OAuth flow testing',
                        'Bearer token security',
                        'Authentication bypass',
                        'Credential stuffing potential'
                    ]
                },
                {
                    'phase': 'Authorization',
                    'tasks': [
                        'BOLA (Broken Object Level Auth)',
                        'BFLA (Broken Function Level Auth)',
                        'Mass assignment',
                        'Excessive data exposure',
                        'Resource ID manipulation',
                        'Cross-tenant data access'
                    ]
                },
                {
                    'phase': 'Input Validation',
                    'tasks': [
                        'JSON/XML injection',
                        'Parameter pollution',
                        'Type confusion',
                        'Regex DoS',
                        'SQL/NoSQL injection',
                        'SSRF via URL parameters'
                    ]
                },
                {
                    'phase': 'Rate Limiting & Logic',
                    'tasks': [
                        'Rate limit bypass',
                        'Brute force protection',
                        'Race conditions',
                        'GraphQL query depth limits',
                        'Batch request abuse',
                        'Async operation manipulation'
                    ]
                }
            ]
        }
    }

    checklist = checklists.get(target_type, checklists['web_app'])

    # Calculate totals
    total_tasks = sum(len(phase['tasks']) for phase in checklist['phases'])

    return {
        'target_type': target_type,
        'checklist_name': checklist['name'],
        'total_phases': len(checklist['phases']),
        'total_tasks': total_tasks,
        'phases': checklist['phases'],
        'methodology_source': '2025 Master Strategy',
        'usage': 'Use this checklist to ensure comprehensive coverage during testing',
        'tracking': 'Mark tasks complete as you progress through testing'
    }
