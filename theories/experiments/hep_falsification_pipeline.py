#!/usr/bin/env python3
"""
HEP Anomaly Hunter: Falsification-First Pipeline
================================================

Purpose: Test substrate eigenmode predictions against CERN open data
Design: Adversarial, blind, falsifiable
Target: NA64 dark photon null results (might contain our signal)

Author: Substrate Theory Testing Group
Date: 2025-12-30
Status: Production-ready prototype
"""

import numpy as np
import json
from pathlib import Path
from dataclasses import dataclass
from typing import List, Tuple, Dict
from scipy import stats

# ============================================================================
# PHASE 0: SINGLE SOURCE OF TRUTH
# ============================================================================

@dataclass(frozen=True)
class MassWindow:
    """Immutable prediction contract - no modifications allowed"""
    name: str
    n_squared: int
    mass_mev: float
    tolerance_mev: float
    quantum_numbers: Tuple[int, int]  # (n, l)

    def contains(self, mass: float) -> bool:
        """Check if measured mass falls within prediction window"""
        return abs(mass - self.mass_mev) <= self.tolerance_mev

    def sigma_deviation(self, mass: float, resolution: float) -> float:
        """Return deviation in units of experimental resolution"""
        return abs(mass - self.mass_mev) / resolution


# Substrate eigenmode predictions (documented 2025-12-30)
# Source: /theories/PARTICLE_MASS_PREDICTIONS.md
PREDICTIONS = [
    MassWindow("eigen_2_0", 4, 2.044, 0.020, (2, 0)),       # CRITICAL TEST
    MassWindow("eigen_3_0", 9, 4.599, 0.050, (3, 0)),
    MassWindow("eigen_5_0", 25, 12.775, 0.200, (5, 0)),
    MassWindow("eigen_7_6", 55, 28.105, 0.500, (7, 6)),
    MassWindow("eigen_10_10", 110, 56.210, 1.000, (10, 10)),
    MassWindow("eigen_25_15", 327, 167.097, 3.000, (25, 15)),
]

# Known particles (for calibration and null hypothesis testing)
KNOWN_PARTICLES = {
    'electron': 0.511,
    'muon': 105.658,
    'pion0': 134.977,
    'pion_pm': 139.570,
}


# ============================================================================
# PHASE 1: NA64-SPECIFIC DATA EXTRACTION
# ============================================================================

class NA64Extractor:
    """
    Extract invariant mass spectrum from NA64 dark photon search data

    NA64 searched 1-200 MeV for dark photons coupling to electrons
    Their 'null result' might contain substrate eigenmode signals

    NA64 Papers:
    - Phys. Rev. Lett. 120, 231802 (2018)
    - Phys. Rev. D 97, 072002 (2018)

    Data: https://opendata.cern.ch/record/... (to be filled)
    """

    def __init__(self, data_path: str):
        self.data_path = Path(data_path)
        self.resolution_mev = 0.5  # NA64 calorimeter resolution

    def load_spectrum(self) -> np.ndarray:
        """
        Load missing mass spectrum from NA64 analysis

        Returns:
            Array of reconstructed masses in MeV
        """
        # TODO: Implement based on actual NA64 data format
        # Placeholder for development
        raise NotImplementedError(
            "NA64 data format needs to be determined from CERN Open Data"
        )

    def extract_ecal_deposits(self) -> np.ndarray:
        """
        Extract ECAL energy deposits (proxy for particle mass)

        NA64 uses:
        - 100 GeV electron beam
        - Active target for missing energy
        - ECAL for electromagnetic shower

        Missing mass: M² = (E_beam - E_ECAL)² - p_miss²
        """
        # TODO: Implement ROOT file reading
        # Expected branches: ECAL_energy, beam_energy, momentum_x/y/z
        pass

    def calculate_missing_mass(
        self,
        beam_energy: np.ndarray,
        ecal_energy: np.ndarray,
        momentum: np.ndarray
    ) -> np.ndarray:
        """
        Calculate missing mass from NA64 kinematics

        Formula: M_miss² = (E_beam - E_visible)² - |p_miss|²
        """
        E_miss = beam_energy - ecal_energy
        p_miss_sq = np.sum(momentum**2, axis=1)

        m_sq = E_miss**2 - p_miss_sq
        m_sq = np.where(m_sq < 0, 0, m_sq)  # Handle numerical errors

        return np.sqrt(m_sq) * 1000  # GeV → MeV


# ============================================================================
# PHASE 2: BLIND PEAK SCANNING
# ============================================================================

class BlindScanner:
    """
    Automated peak scanner - no human interpretation until after results

    Design Philosophy:
    1. Scan ALL predicted windows automatically
    2. Use objective significance thresholds
    3. No cherry-picking of "interesting" features
    4. Background estimated from sidebands (not simulation)
    """

    def __init__(self, spectrum: np.ndarray, resolution_mev: float = 0.5):
        self.masses = spectrum
        self.resolution = resolution_mev

        # Create histogram for fast lookups
        self.hist, self.bin_edges = np.histogram(
            spectrum,
            bins=np.arange(0, 200, 0.1)  # 100 keV bins
        )
        self.bin_centers = (self.bin_edges[1:] + self.bin_edges[:-1]) / 2

    def scan_window(self, window: MassWindow) -> Dict:
        """
        Count events in prediction window with sideband background

        Method:
        - Signal region: [M - δM, M + δM]
        - Left sideband: [M - 3δM, M - δM]
        - Right sideband: [M + δM, M + 3δM]
        - Background = average of sidebands
        """

        # Define regions
        lo = window.mass_mev - window.tolerance_mev
        hi = window.mass_mev + window.tolerance_mev

        # Signal region
        in_window = (self.masses >= lo) & (self.masses <= hi)
        n_signal = int(np.sum(in_window))

        # Background estimate from sidebands
        left_lo = window.mass_mev - 3 * window.tolerance_mev
        left_hi = lo
        right_lo = hi
        right_hi = window.mass_mev + 3 * window.tolerance_mev

        left_bg = np.sum((self.masses >= left_lo) & (self.masses < left_hi))
        right_bg = np.sum((self.masses > right_lo) & (self.masses <= right_hi))
        n_background = float((left_bg + right_bg) / 2)

        # Statistical significance
        if n_background > 0:
            # Li-Ma significance (proper Poisson statistics)
            significance = self._li_ma_significance(n_signal, n_background)
        else:
            significance = 0.0 if n_signal == 0 else float('inf')

        # Find peak position (if any)
        peak_mass = self._find_peak_in_window(lo, hi)

        return {
            'window_name': window.name,
            'predicted_mass_mev': window.mass_mev,
            'n_quantum': window.quantum_numbers,
            'n_events_observed': n_signal,
            'n_background_expected': n_background,
            'significance_sigma': float(significance),
            'peak_mass_mev': peak_mass,
            'resolution_mev': self.resolution,
            'search_range_mev': (lo, hi)
        }

    def _li_ma_significance(self, n_on: int, n_off: float) -> float:
        """
        Li & Ma (1983) significance for Poisson statistics
        More accurate than simple (S-B)/sqrt(B) for low counts
        """
        if n_on == 0:
            return 0.0

        alpha = 1.0  # On/off exposure ratio
        n_on = float(n_on)

        term1 = n_on * np.log((1 + alpha) * n_on / (alpha * (n_on + n_off)))
        term2 = n_off * np.log((1 + alpha) * n_off / (n_on + n_off))

        significance_sq = 2 * (term1 + term2)
        return np.sqrt(significance_sq) if significance_sq > 0 else 0.0

    def _find_peak_in_window(self, lo: float, hi: float) -> float:
        """Find highest bin in window (peak position)"""
        mask = (self.bin_centers >= lo) & (self.bin_centers <= hi)
        if not np.any(mask):
            return (lo + hi) / 2

        window_hist = self.hist[mask]
        window_bins = self.bin_centers[mask]

        if len(window_hist) == 0:
            return (lo + hi) / 2

        peak_idx = np.argmax(window_hist)
        return float(window_bins[peak_idx])

    def scan_all_predictions(self) -> Dict[str, Dict]:
        """Run blind scan on all predicted windows"""
        results = {}
        for pred in PREDICTIONS:
            results[pred.name] = self.scan_window(pred)
        return results


# ============================================================================
# PHASE 3: FALSIFICATION LOGIC
# ============================================================================

class FalsificationEngine:
    """
    Hard gates for theory validation/falsification

    No wiggle room, no "interesting trends", no post-hoc rationalization
    """

    # Significance thresholds (conservative)
    DISCOVERY_THRESHOLD = 5.0   # 5σ = discovery
    EVIDENCE_THRESHOLD = 3.0    # 3σ = evidence
    HINT_THRESHOLD = 2.0        # 2σ = hint (not significant)

    def __init__(self, results: Dict[str, Dict]):
        self.results = results

    def evaluate(self) -> Dict:
        """
        Apply falsification gates

        Returns verdict with supporting evidence
        """

        # Gate 1: Critical test (2.04 MeV must show signal)
        critical_result = self.results['eigen_2_0']
        critical_sigma = critical_result['significance_sigma']

        if critical_sigma > self.DISCOVERY_THRESHOLD:
            verdict = "VALIDATED"
            reason = f"Discovery at 2.04 MeV ({critical_sigma:.1f}σ)"

        elif critical_sigma > self.EVIDENCE_THRESHOLD:
            verdict = "STRONG_EVIDENCE"
            reason = f"Significant excess at 2.04 MeV ({critical_sigma:.1f}σ)"

        elif critical_sigma < 1.0:
            verdict = "FALSIFIED"
            reason = f"No signal at cleanest prediction (2.04 MeV: {critical_sigma:.1f}σ)"

        else:
            # Gate 2: Check pattern across multiple windows
            discoveries = sum(1 for r in self.results.values()
                            if r['significance_sigma'] > self.DISCOVERY_THRESHOLD)
            evidence = sum(1 for r in self.results.values()
                          if r['significance_sigma'] > self.EVIDENCE_THRESHOLD)

            if discoveries >= 2:
                verdict = "VALIDATED"
                reason = f"Multiple discoveries ({discoveries} at >5σ)"
            elif evidence >= 3:
                verdict = "STRONG_EVIDENCE"
                reason = f"Multiple excesses ({evidence} at >3σ)"
            elif evidence == 0:
                verdict = "FALSIFIED"
                reason = "No significant excesses at any predicted mass"
            else:
                verdict = "INCONCLUSIVE"
                reason = f"Weak excesses ({evidence} at >3σ), need more data"

        return {
            'verdict': verdict,
            'reason': reason,
            'critical_test_sigma': critical_sigma,
            'n_discoveries': sum(1 for r in self.results.values()
                               if r['significance_sigma'] > self.DISCOVERY_THRESHOLD),
            'n_evidence': sum(1 for r in self.results.values()
                            if r['significance_sigma'] > self.EVIDENCE_THRESHOLD),
            'n_hints': sum(1 for r in self.results.values()
                         if r['significance_sigma'] > self.HINT_THRESHOLD)
        }

    def generate_report(self) -> str:
        """Human-readable falsification report"""
        verdict_data = self.evaluate()

        report = f"""
SUBSTRATE EIGENMODE FALSIFICATION REPORT
=========================================
Date: 2025-12-30
Dataset: NA64 Dark Photon Search (placeholder)
Predictions: 6 mass windows (2.04 - 167 MeV)

VERDICT: {verdict_data['verdict']}
Reason: {verdict_data['reason']}

STATISTICAL SUMMARY:
- Discoveries (>5σ): {verdict_data['n_discoveries']}
- Evidence (>3σ): {verdict_data['n_evidence']}
- Hints (>2σ): {verdict_data['n_hints']}

DETAILED RESULTS:
"""

        for name, result in self.results.items():
            report += f"""
{name}:
  Predicted: {result['predicted_mass_mev']:.3f} MeV (n={result['n_quantum'][0]}, l={result['n_quantum'][1]})
  Observed: {result['n_events_observed']} events
  Background: {result['n_background_expected']:.1f} events
  Significance: {result['significance_sigma']:.2f}σ
  Peak: {result['peak_mass_mev']:.3f} MeV
"""

        report += f"""
FALSIFICATION CRITERIA:
✓ Pass: >5σ at 2.04 MeV OR >5σ at 2+ windows
✓ Evidence: >3σ at 2.04 MeV OR >3σ at 3+ windows
✗ Fail: <1σ at 2.04 MeV AND <3σ at all windows

NEXT STEPS:
"""
        if verdict_data['verdict'] == "VALIDATED":
            report += "- Write paper for immediate arXiv submission\n"
            report += "- Contact experimental groups for confirmation\n"
            report += "- Prepare for peer review\n"
        elif verdict_data['verdict'] == "FALSIFIED":
            report += "- Theory is wrong, accept results\n"
            report += "- Document failure for future reference\n"
            report += "- Refine framework based on what we learned\n"
        else:
            report += "- Need higher statistics or better resolution\n"
            report += "- Search additional datasets (LHC, Belle II)\n"
            report += "- Consider dedicated low-energy search\n"

        return report


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """
    Run complete falsification pipeline

    Usage:
        python hep_falsification_pipeline.py --data na64_spectrum.txt
    """
    import argparse

    parser = argparse.ArgumentParser(
        description="Test substrate eigenmode predictions against HEP data"
    )
    parser.add_argument(
        '--data',
        type=str,
        required=True,
        help='Path to mass spectrum file (text file, one mass per line in MeV)'
    )
    parser.add_argument(
        '--resolution',
        type=float,
        default=0.5,
        help='Experimental mass resolution in MeV (default: 0.5)'
    )
    parser.add_argument(
        '--output',
        type=str,
        default='falsification_results.json',
        help='Output JSON file for results'
    )

    args = parser.parse_args()

    # Load spectrum
    print(f"Loading spectrum from {args.data}...")
    spectrum = np.loadtxt(args.data)
    print(f"Loaded {len(spectrum)} events")

    # Run blind scan
    print("\nRunning blind scan on predicted windows...")
    scanner = BlindScanner(spectrum, args.resolution)
    results = scanner.scan_all_predictions()

    # Evaluate
    print("\nApplying falsification criteria...")
    evaluator = FalsificationEngine(results)
    report = evaluator.generate_report()

    # Output
    print(report)

    with open(args.output, 'w') as f:
        json.dump({
            'results': results,
            'verdict': evaluator.evaluate()
        }, f, indent=2)

    print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    main()
