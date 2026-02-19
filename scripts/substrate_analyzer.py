#!/usr/bin/env python3
"""
Substrate Boundary Analyzer - Exploit Prediction from Structural Analysis

Finds vulnerabilities by mapping where irreversible state changes
separate from validation constraints across trust boundaries.

Usage:
    python3 substrate_analyzer.py --target <url> --mode <static|dynamic>
    python3 substrate_analyzer.py --openapi spec.json
    python3 substrate_analyzer.py --code /path/to/codebase

Based on: methodology/advanced/SUBSTRATE_BOUNDARY_ANALYSIS.md
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from enum import Enum
import requests
from pathlib import Path


class OperationType(Enum):
    FINANCIAL = "financial"
    AUTHORIZATION = "authorization"
    DATA_MODIFICATION = "data"
    AUTHENTICATION = "authentication"
    COMMUNICATION = "communication"


class TrustLevel(Enum):
    UNTRUSTED_CLIENT = 0
    FRONTEND = 1
    BACKEND_API = 2
    DATABASE = 3
    INTERNAL_SERVICE = 4


@dataclass
class Parameter:
    name: str
    origin: TrustLevel
    validated: bool = False
    validation_point: Optional[str] = None
    data_type: str = "unknown"


@dataclass
class IrreversibleOperation:
    name: str
    endpoint: str
    method: str
    operation_type: OperationType
    parameters: List[Parameter] = field(default_factory=list)
    description: str = ""

    def __str__(self):
        return f"{self.method} {self.endpoint} - {self.name}"


@dataclass
class BoundaryGap:
    operation: IrreversibleOperation
    parameter: Parameter
    gap_type: str  # 'trust_boundary', 'time_gap', 'validation_missing'
    severity: str = "UNKNOWN"
    delta_s: float = 0.0  # Exploit potential

    def __str__(self):
        return f"[{self.severity}] {self.gap_type} in {self.operation.name} - param: {self.parameter.name}"


@dataclass
class VulnerabilityPrediction:
    gap: BoundaryGap
    severity: str
    impact: float
    cost_to_exploit: float
    confidence: float
    test_cases: List[Dict] = field(default_factory=list)
    cve_mapping: Optional[str] = None

    def __str__(self):
        return f"""
{'='*60}
VULNERABILITY PREDICTION
{'='*60}
Severity: {self.severity}
Operation: {self.gap.operation}
Gap Type: {self.gap.gap_type}
Parameter: {self.gap.parameter.name}

Impact (ΔS*): {self.impact:.2f}
Cost to Exploit: {self.cost_to_exploit:.2f}
Confidence: {self.confidence:.2f}

Predicted Vulnerability Class: {self.cve_mapping or 'Novel'}

Test Cases Generated: {len(self.test_cases)}
{'='*60}
"""


class SubstrateBoundaryAnalyzer:
    """
    Core analyzer implementing the substrate boundary framework
    """

    # Keywords for identifying irreversible operations
    FINANCIAL_KEYWORDS = [
        'charge', 'payment', 'pay', 'transfer', 'withdraw',
        'refund', 'credit', 'debit', 'invoice', 'purchase', 'buy'
    ]

    AUTHORIZATION_KEYWORDS = [
        'grant', 'revoke', 'promote', 'admin', 'permission',
        'role', 'access', 'privilege', 'authorize', 'allow', 'deny'
    ]

    DATA_KEYWORDS = [
        'delete', 'remove', 'purge', 'destroy', 'drop',
        'publish', 'send', 'notify', 'execute', 'create'
    ]

    AUTHENTICATION_KEYWORDS = [
        'login', 'authenticate', 'token', 'session',
        'reset', 'verify', 'signup', 'register', 'oauth'
    ]

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.operations: List[IrreversibleOperation] = []
        self.boundary_gaps: List[BoundaryGap] = []
        self.predictions: List[VulnerabilityPrediction] = []

    def log(self, message: str):
        if self.verbose:
            print(f"[*] {message}")

    def analyze_openapi_spec(self, spec_path: str):
        """
        Analyze OpenAPI/Swagger specification
        """
        self.log(f"Loading OpenAPI spec: {spec_path}")

        with open(spec_path, 'r') as f:
            spec = json.load(f)

        self.log("Identifying irreversible operations...")

        paths = spec.get('paths', {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.upper() in ['GET', 'OPTIONS', 'HEAD']:
                    continue  # Skip read-only operations

                operation_id = details.get('operationId', f"{method}_{path}")
                summary = details.get('summary', '')
                description = details.get('description', '')

                # Detect operation type
                op_type = self._classify_operation(operation_id, summary, description)

                if op_type:
                    operation = IrreversibleOperation(
                        name=operation_id,
                        endpoint=path,
                        method=method.upper(),
                        operation_type=op_type,
                        description=summary or description
                    )

                    # Extract parameters
                    params = details.get('parameters', [])
                    request_body = details.get('requestBody', {})

                    for param in params:
                        param_obj = Parameter(
                            name=param.get('name'),
                            origin=self._determine_origin(param.get('in')),
                            data_type=param.get('schema', {}).get('type', 'unknown')
                        )
                        operation.parameters.append(param_obj)

                    # Add request body parameters
                    if request_body:
                        content = request_body.get('content', {})
                        for content_type, schema_info in content.items():
                            schema = schema_info.get('schema', {})
                            properties = schema.get('properties', {})

                            for prop_name, prop_details in properties.items():
                                param_obj = Parameter(
                                    name=prop_name,
                                    origin=TrustLevel.UNTRUSTED_CLIENT,
                                    data_type=prop_details.get('type', 'unknown')
                                )
                                operation.parameters.append(param_obj)

                    self.operations.append(operation)
                    self.log(f"  Found: {operation}")

        self.log(f"Identified {len(self.operations)} irreversible operations")

    def _classify_operation(self, name: str, summary: str, description: str) -> Optional[OperationType]:
        """
        Classify operation based on keywords
        """
        text = f"{name} {summary} {description}".lower()

        if any(kw in text for kw in self.FINANCIAL_KEYWORDS):
            return OperationType.FINANCIAL

        if any(kw in text for kw in self.AUTHORIZATION_KEYWORDS):
            return OperationType.AUTHORIZATION

        if any(kw in text for kw in self.AUTHENTICATION_KEYWORDS):
            return OperationType.AUTHENTICATION

        if any(kw in text for kw in self.DATA_KEYWORDS):
            return OperationType.DATA_MODIFICATION

        return None

    def _determine_origin(self, param_location: str) -> TrustLevel:
        """
        Determine trust level based on parameter location
        """
        if param_location in ['query', 'path', 'header']:
            return TrustLevel.UNTRUSTED_CLIENT
        elif param_location == 'cookie':
            return TrustLevel.FRONTEND
        else:
            return TrustLevel.UNTRUSTED_CLIENT

    def detect_boundary_gaps(self):
        """
        Find separation between validation and execution
        """
        self.log("Detecting boundary gaps...")

        for operation in self.operations:
            for param in operation.parameters:
                # Gap 1: Client-controlled parameter with no validation
                if param.origin == TrustLevel.UNTRUSTED_CLIENT and not param.validated:
                    gap = BoundaryGap(
                        operation=operation,
                        parameter=param,
                        gap_type='trust_boundary_violation'
                    )
                    self.boundary_gaps.append(gap)
                    self.log(f"  Gap: {gap}")

                # Gap 2: Financial operations with client-controlled amounts
                if operation.operation_type == OperationType.FINANCIAL:
                    if param.name in ['amount', 'price', 'total', 'quantity', 'value']:
                        if param.origin == TrustLevel.UNTRUSTED_CLIENT:
                            gap = BoundaryGap(
                                operation=operation,
                                parameter=param,
                                gap_type='price_manipulation',
                                severity='CRITICAL'
                            )
                            self.boundary_gaps.append(gap)
                            self.log(f"  CRITICAL Gap: {gap}")

                # Gap 3: Authorization parameters from client
                if operation.operation_type == OperationType.AUTHORIZATION:
                    if param.name in ['role', 'admin', 'permission', 'privileges', 'user_id', 'id']:
                        if param.origin == TrustLevel.UNTRUSTED_CLIENT:
                            gap = BoundaryGap(
                                operation=operation,
                                parameter=param,
                                gap_type='privilege_escalation',
                                severity='CRITICAL'
                            )
                            self.boundary_gaps.append(gap)
                            self.log(f"  CRITICAL Gap: {gap}")

        self.log(f"Detected {len(self.boundary_gaps)} boundary gaps")

    def calculate_exploit_potential(self):
        """
        Calculate ΔS* for each gap - impact if exploited
        """
        self.log("Calculating exploit potential (ΔS*)...")

        for gap in self.boundary_gaps:
            impact = self._calculate_impact(gap)
            cost = self._calculate_exploitation_cost(gap)

            gap.delta_s = impact

            # Predict vulnerability
            if impact > cost * 10:  # High confidence
                confidence = min(impact / cost, 10.0)

                prediction = VulnerabilityPrediction(
                    gap=gap,
                    severity=self._determine_severity(impact),
                    impact=impact,
                    cost_to_exploit=cost,
                    confidence=confidence,
                    cve_mapping=self._map_to_cve_class(gap)
                )

                # Generate test cases
                prediction.test_cases = self._generate_test_cases(gap)

                self.predictions.append(prediction)
                self.log(f"  Prediction: {prediction.severity} - {gap.operation.name}")

    def _calculate_impact(self, gap: BoundaryGap) -> float:
        """
        Estimate impact of unauthorized execution
        """
        impact = 0.0

        # Financial operations
        if gap.operation.operation_type == OperationType.FINANCIAL:
            impact += 10.0  # Maximum financial impact

        # Authorization operations
        if gap.operation.operation_type == OperationType.AUTHORIZATION:
            impact += 10.0  # Full privilege escalation

        # Authentication operations
        if gap.operation.operation_type == OperationType.AUTHENTICATION:
            impact += 8.0  # Account takeover

        # Data operations
        if gap.operation.operation_type == OperationType.DATA_MODIFICATION:
            impact += 6.0  # Data loss/corruption

        # Specific gap types
        if gap.gap_type == 'price_manipulation':
            impact += 5.0

        if gap.gap_type == 'privilege_escalation':
            impact += 5.0

        return impact

    def _calculate_exploitation_cost(self, gap: BoundaryGap) -> float:
        """
        Estimate cost/difficulty to exploit
        """
        cost = 1.0  # Base cost

        # Client-controlled parameters are easy to manipulate
        if gap.parameter.origin == TrustLevel.UNTRUSTED_CLIENT:
            cost = 0.5  # Very low - just modify HTTP request

        # Trust boundary violations are easy
        if gap.gap_type == 'trust_boundary_violation':
            cost = 0.5

        return cost

    def _determine_severity(self, impact: float) -> str:
        """
        Map impact to CVSS-like severity
        """
        if impact >= 9.0:
            return "CRITICAL"
        elif impact >= 7.0:
            return "HIGH"
        elif impact >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"

    def _map_to_cve_class(self, gap: BoundaryGap) -> str:
        """
        Map structural gap to known CVE classes
        """
        if gap.gap_type == 'price_manipulation':
            return "CWE-472: External Control of Assumed-Immutable Web Parameter"

        if gap.gap_type == 'privilege_escalation':
            return "CWE-639: Authorization Bypass Through User-Controlled Key"

        if gap.gap_type == 'trust_boundary_violation':
            if gap.operation.operation_type == OperationType.FINANCIAL:
                return "CWE-472: Price Manipulation"
            elif gap.operation.operation_type == OperationType.AUTHORIZATION:
                return "CWE-284: Improper Access Control"

        return "CWE-707: Improper Neutralization"

    def _generate_test_cases(self, gap: BoundaryGap) -> List[Dict]:
        """
        Generate concrete test cases from structural prediction
        """
        test_cases = []

        # Price manipulation tests
        if gap.gap_type == 'price_manipulation':
            test_cases.extend([
                {
                    'type': 'parameter_tampering',
                    'parameter': gap.parameter.name,
                    'test_value': 0.01,
                    'description': 'Set price to $0.01'
                },
                {
                    'type': 'parameter_tampering',
                    'parameter': gap.parameter.name,
                    'test_value': -1,
                    'description': 'Set negative price'
                },
                {
                    'type': 'parameter_tampering',
                    'parameter': gap.parameter.name,
                    'test_value': 0,
                    'description': 'Set price to zero'
                }
            ])

        # Privilege escalation tests
        if gap.gap_type == 'privilege_escalation':
            test_cases.extend([
                {
                    'type': 'parameter_tampering',
                    'parameter': gap.parameter.name,
                    'test_value': 'admin',
                    'description': 'Set role to admin'
                },
                {
                    'type': 'parameter_tampering',
                    'parameter': gap.parameter.name,
                    'test_value': True,
                    'description': 'Set privilege flag to true'
                },
                {
                    'type': 'IDOR',
                    'parameter': gap.parameter.name,
                    'test_value': 1,
                    'description': 'Access admin user ID'
                }
            ])

        # Trust boundary tests
        if gap.gap_type == 'trust_boundary_violation':
            test_cases.extend([
                {
                    'type': 'parameter_tampering',
                    'parameter': gap.parameter.name,
                    'test_value': '../../../etc/passwd',
                    'description': 'Path traversal attempt'
                },
                {
                    'type': 'parameter_tampering',
                    'parameter': gap.parameter.name,
                    'test_value': '<script>alert(1)</script>',
                    'description': 'XSS attempt'
                },
                {
                    'type': 'parameter_tampering',
                    'parameter': gap.parameter.name,
                    'test_value': "' OR '1'='1",
                    'description': 'SQL injection attempt'
                }
            ])

        return test_cases

    def generate_report(self, output_file: Optional[str] = None):
        """
        Generate comprehensive analysis report
        """
        report = []
        report.append("="*80)
        report.append("SUBSTRATE BOUNDARY ANALYSIS REPORT")
        report.append("="*80)
        report.append("")

        report.append(f"Total Irreversible Operations: {len(self.operations)}")
        report.append(f"Boundary Gaps Detected: {len(self.boundary_gaps)}")
        report.append(f"Vulnerability Predictions: {len(self.predictions)}")
        report.append("")

        # Severity breakdown
        severity_counts = {}
        for pred in self.predictions:
            severity_counts[pred.severity] = severity_counts.get(pred.severity, 0) + 1

        report.append("Severity Distribution:")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = severity_counts.get(severity, 0)
            report.append(f"  {severity}: {count}")
        report.append("")

        # Detailed predictions
        report.append("="*80)
        report.append("VULNERABILITY PREDICTIONS")
        report.append("="*80)
        report.append("")

        for i, pred in enumerate(sorted(self.predictions, key=lambda p: p.impact, reverse=True), 1):
            report.append(f"\n{i}. {pred.severity} - {pred.gap.operation.name}")
            report.append("-" * 80)
            report.append(f"Endpoint: {pred.gap.operation.method} {pred.gap.operation.endpoint}")
            report.append(f"Operation Type: {pred.gap.operation.operation_type.value}")
            report.append(f"Gap Type: {pred.gap.gap_type}")
            report.append(f"Parameter: {pred.gap.parameter.name} (origin: {pred.gap.parameter.origin.name})")
            report.append(f"")
            report.append(f"Impact (ΔS*): {pred.impact:.2f}/10")
            report.append(f"Cost to Exploit: {pred.cost_to_exploit:.2f}/10")
            report.append(f"Confidence: {pred.confidence:.2f}")
            report.append(f"CVE Class: {pred.cve_mapping}")
            report.append(f"")
            report.append(f"Test Cases ({len(pred.test_cases)}):")
            for tc in pred.test_cases:
                report.append(f"  - {tc['type']}: {tc['description']}")
                report.append(f"    Parameter: {tc['parameter']} = {tc['test_value']}")
            report.append("")

        report.append("="*80)
        report.append("RECOMMENDED ACTIONS")
        report.append("="*80)
        report.append("")

        critical_count = severity_counts.get('CRITICAL', 0)
        if critical_count > 0:
            report.append(f"⚠️  {critical_count} CRITICAL predictions require immediate testing")
            report.append("")
            report.append("Priority test sequence:")
            for i, pred in enumerate([p for p in self.predictions if p.severity == 'CRITICAL'][:5], 1):
                report.append(f"{i}. Test {pred.gap.operation.method} {pred.gap.operation.endpoint}")
                report.append(f"   → {pred.gap.gap_type} on parameter '{pred.gap.parameter.name}'")

        report_text = "\n".join(report)

        if output_file:
            with open(output_file, 'w') as f:
                f.write(report_text)
            print(f"\n[+] Report saved to: {output_file}")

        print(report_text)

        return report_text


def main():
    parser = argparse.ArgumentParser(
        description="Substrate Boundary Analyzer - Predict exploits from structural analysis"
    )
    parser.add_argument('--openapi', help='Path to OpenAPI/Swagger JSON spec')
    parser.add_argument('--output', '-o', help='Output report file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if not args.openapi:
        parser.print_help()
        print("\n[!] Example usage:")
        print("  python3 substrate_analyzer.py --openapi api-spec.json")
        print("  python3 substrate_analyzer.py --openapi swagger.json --output report.txt")
        sys.exit(1)

    analyzer = SubstrateBoundaryAnalyzer(verbose=args.verbose)

    print("[+] Substrate Boundary Analyzer")
    print("[+] Finding exploits through structural analysis\n")

    # Step 1: Identify irreversible operations
    analyzer.analyze_openapi_spec(args.openapi)

    # Step 2: Detect boundary gaps
    analyzer.detect_boundary_gaps()

    # Step 3: Calculate exploit potential
    analyzer.calculate_exploit_potential()

    # Step 4: Generate report
    output_file = args.output or 'substrate_analysis_report.txt'
    analyzer.generate_report(output_file)

    print("\n[+] Analysis complete!")
    print(f"[+] Found {len(analyzer.predictions)} predicted vulnerabilities")

    critical = sum(1 for p in analyzer.predictions if p.severity == 'CRITICAL')
    if critical > 0:
        print(f"[!] {critical} CRITICAL predictions - test immediately!")


if __name__ == '__main__':
    main()
