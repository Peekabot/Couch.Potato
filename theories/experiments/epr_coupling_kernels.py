#!/usr/bin/env python3
"""
EPR Coupling Kernel Analysis - Complete Implementation
History-Based Quantum Mechanics Framework v1.0

This module implements coupling kernels for EPR-Bell experiments,
testing how different measures on inaccessible parameters affect
correlation functions and CHSH violation.
"""

import numpy as np
import matplotlib.pyplot as plt
from scipy.integrate import quad
import pandas as pd
from datetime import datetime
import json
import os


class EPRCouplingKernel:
    """
    Coupling kernel for EPR spin measurements.

    The kernel implements deterministic coupling:
    outcome = sign(a · σ(φ))

    where φ is inaccessible phase, and measure μ(φ) determines
    probability distribution.
    """

    def __init__(self, measure_type='quantum'):
        """
        Parameters:
        -----------
        measure_type : str
            'quantum' - uniform measure (Born rule)
            'peaked' - concentrated near 0, π
            'bimodal' - discrete at 0, π only
        """
        self.measure_type = measure_type

    def sample_phase(self):
        """Sample φ from measure μ(φ)"""
        if self.measure_type == 'quantum':
            # Uniform measure → Born rule
            return np.random.uniform(0, 2*np.pi)

        elif self.measure_type == 'peaked':
            # Gaussian peaks at 0 and π
            sigma = np.pi/8
            if np.random.rand() < 0.5:
                return np.random.normal(0, sigma) % (2*np.pi)
            else:
                return np.random.normal(np.pi, sigma) % (2*np.pi)

        elif self.measure_type == 'bimodal':
            # Discrete: 50% at 0, 50% at π
            return 0.0 if np.random.rand() < 0.5 else np.pi

        else:
            raise ValueError(f"Unknown measure type: {self.measure_type}")

    def spin_vector(self, phi):
        """
        Spin vector on Bloch sphere for phase φ
        σ(φ) = (cos φ, sin φ, 0) in x-y plane
        """
        return np.array([np.cos(phi), np.sin(phi), 0.0])

    def measure_spin(self, detector_axis, phi):
        """
        Measure spin along detector axis.
        Returns: +1 or -1
        """
        spin = self.spin_vector(phi)
        projection = np.dot(detector_axis, spin)
        return +1 if projection >= 0 else -1

    def correlation(self, a, b, n_samples=100000):
        """
        Compute correlation E(a,b) = <A(a)·B(b)>

        For EPR singlet with shared phase φ:
        - Alice measures along a, gets outcome based on φ
        - Bob measures along b, gets outcome based on φ+π (anti-correlation)

        Returns: correlation value
        """
        # Normalize detector axes
        a = a / np.linalg.norm(a)
        b = b / np.linalg.norm(b)

        correlation_sum = 0.0

        for _ in range(n_samples):
            # Sample shared phase from measure
            phi_A = self.sample_phase()
            phi_B = (phi_A + np.pi) % (2*np.pi)  # Singlet constraint

            # Measure outcomes
            outcome_A = self.measure_spin(a, phi_A)
            outcome_B = self.measure_spin(b, phi_B)

            # Accumulate product
            correlation_sum += outcome_A * outcome_B

        return correlation_sum / n_samples

    def probability_pp(self, a, b, n_samples=100000):
        """
        Probability of both detectors clicking +1: P(++|a,b)
        """
        a = a / np.linalg.norm(a)
        b = b / np.linalg.norm(b)

        count_pp = 0

        for _ in range(n_samples):
            phi_A = self.sample_phase()
            phi_B = (phi_A + np.pi) % (2*np.pi)

            outcome_A = self.measure_spin(a, phi_A)
            outcome_B = self.measure_spin(b, phi_B)

            if outcome_A == +1 and outcome_B == +1:
                count_pp += 1

        return count_pp / n_samples


class ComprehensiveEPRAnalysis:
    """Run complete EPR analysis suite"""

    def __init__(self, output_dir=None):
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if output_dir is None:
            self.output_dir = f"epr_results_{self.timestamp}"
        else:
            self.output_dir = output_dir

        os.makedirs(self.output_dir, exist_ok=True)

        print(f"\n{'='*60}")
        print(f"EPR Coupling Kernel Analysis")
        print(f"Timestamp: {self.timestamp}")
        print(f"Output: {self.output_dir}/")
        print(f"{'='*60}\n")

    def run_all(self):
        """Execute complete analysis suite"""

        results = {
            'metadata': {
                'timestamp': self.timestamp,
                'n_samples': 100000,
                'framework': 'History-based QM v1.0'
            }
        }

        print("Task 1: CHSH Comparison")
        results['chsh'] = self.chsh_comparison()

        print("\nTask 2: Correlation Functions")
        results['correlations'] = self.correlation_functions()

        print("\nTask 3: Sensitivity Analysis")
        results['sensitivity'] = self.sensitivity_analysis()

        print("\nTask 4: Probability Tables")
        results['probabilities'] = self.probability_tables()

        print("\nTask 5: Measure Densities")
        self.plot_measure_densities()

        # Save all results
        results_file = f"{self.output_dir}/all_results.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)

        print(f"\n✓ All results saved to {self.output_dir}/")
        print(f"✓ JSON data: {results_file}")

        return results

    def chsh_comparison(self):
        """Compare CHSH for quantum, peaked, bimodal measures"""

        # Standard CHSH settings
        settings = {
            'a': np.array([1, 0, 0]),
            'a_prime': np.array([0, 1, 0]),
            'b': np.array([1, 1, 0]) / np.sqrt(2),
            'b_prime': np.array([1, -1, 0]) / np.sqrt(2)
        }

        measures = ['quantum', 'peaked', 'bimodal']
        results = []

        print("-" * 60)

        for measure in measures:
            kernel = EPRCouplingKernel(measure)

            # Compute correlations
            E_ab = kernel.correlation(settings['a'], settings['b'])
            E_ab_prime = kernel.correlation(settings['a'], settings['b_prime'])
            E_a_prime_b = kernel.correlation(settings['a_prime'], settings['b'])
            E_a_prime_b_prime = kernel.correlation(settings['a_prime'], settings['b_prime'])

            # CHSH parameter (take absolute value per convention)
            S = abs(E_ab + E_ab_prime + E_a_prime_b - E_a_prime_b_prime)
            S_err = 2.0 / np.sqrt(100000)  # Statistical error

            # Deviation from quantum bound
            quantum_bound = 2 * np.sqrt(2)
            deviation = S - quantum_bound

            result = {
                'measure': measure,
                'E_ab': float(E_ab),
                'E_ab_prime': float(E_ab_prime),
                'E_a_prime_b': float(E_a_prime_b),
                'E_a_prime_b_prime': float(E_a_prime_b_prime),
                'S': float(S),
                'S_err': float(S_err),
                'quantum_bound': float(quantum_bound),
                'deviation': float(deviation),
                'deviation_sigma': float(deviation / S_err)
            }
            results.append(result)

            print(f"{measure.upper():10s}: S = {S:.4f} ± {S_err:.4f}")
            print(f"             Deviation from quantum: {deviation:+.4f} ({deviation/S_err:+.1f}σ)")

        # Save table
        df = pd.DataFrame(results)
        csv_file = f"{self.output_dir}/table1_chsh_comparison.csv"
        df.to_csv(csv_file, index=False, float_format='%.6f')
        print(f"✓ Saved: {csv_file}")

        return results

    def correlation_functions(self):
        """Generate E(θ) for all measures"""

        angles = np.linspace(0, np.pi, 40)
        measures = ['quantum', 'peaked', 'bimodal']

        fig, axes = plt.subplots(1, 3, figsize=(16, 5))

        correlations = {}

        for idx, measure in enumerate(measures):
            kernel = EPRCouplingKernel(measure)
            corr_vals = []
            corr_errs = []

            for theta in angles:
                a = np.array([1, 0, 0])
                b = np.array([np.cos(theta), np.sin(theta), 0])
                E = kernel.correlation(a, b, n_samples=50000)
                E_err = 2.0 / np.sqrt(50000)

                corr_vals.append(E)
                corr_errs.append(E_err)

            corr_vals = np.array(corr_vals)
            corr_errs = np.array(corr_errs)
            correlations[measure] = corr_vals.tolist()

            ax = axes[idx]
            ax.errorbar(angles, corr_vals, yerr=corr_errs,
                       fmt='o', markersize=4, capsize=3,
                       label='Simulated', alpha=0.7)
            ax.plot(angles, -np.cos(angles), 'r--', linewidth=2,
                   label='Quantum prediction')
            ax.set_xlabel('Angle θ (radians)', fontsize=11)
            ax.set_ylabel('E(a,b)', fontsize=11)
            ax.set_title(f'{measure.capitalize()} Measure', fontsize=12, fontweight='bold')
            ax.legend(fontsize=9)
            ax.grid(True, alpha=0.3)
            ax.set_xlim([0, np.pi])
            ax.set_ylim([-1.1, 1.1])

        plt.tight_layout()

        png_file = f"{self.output_dir}/fig1_correlations.png"
        pdf_file = f"{self.output_dir}/fig1_correlations.pdf"
        plt.savefig(png_file, dpi=150, bbox_inches='tight')
        plt.savefig(pdf_file, dpi=300, bbox_inches='tight')
        plt.close()

        print(f"✓ Saved: {png_file}")
        print(f"✓ Saved: {pdf_file}")

        # Save data
        npz_file = f"{self.output_dir}/correlation_data.npz"
        np.savez(npz_file, angles=angles, **correlations)

        return correlations

    def sensitivity_analysis(self):
        """CHSH sensitivity to measure deviation from uniform"""

        p_range = np.linspace(0, 1, 25)
        S_vals = []

        print("-" * 60)

        for p in p_range:
            # Mixed measure: p*peaked + (1-p)*uniform
            class MixedKernel(EPRCouplingKernel):
                def __init__(self, p_peak):
                    self.p_peak = p_peak
                    super().__init__('mixed')

                def sample_phase(self):
                    if np.random.rand() < self.p_peak:
                        # Peaked component
                        sigma = np.pi/8
                        if np.random.rand() < 0.5:
                            return np.random.normal(0, sigma) % (2*np.pi)
                        else:
                            return np.random.normal(np.pi, sigma) % (2*np.pi)
                    else:
                        # Uniform component
                        return np.random.uniform(0, 2*np.pi)

            kernel = MixedKernel(p)

            # CHSH settings
            a = np.array([1, 0, 0])
            ap = np.array([0, 1, 0])
            b = np.array([1, 1, 0]) / np.sqrt(2)
            bp = np.array([1, -1, 0]) / np.sqrt(2)

            # Compute CHSH
            E_ab = kernel.correlation(a, b, n_samples=30000)
            E_abp = kernel.correlation(a, bp, n_samples=30000)
            E_apb = kernel.correlation(ap, b, n_samples=30000)
            E_apbp = kernel.correlation(ap, bp, n_samples=30000)

            S = abs(E_ab + E_abp + E_apb - E_apbp)
            S_vals.append(S)

            if abs(p - round(p, 1)) < 0.01:
                print(f"p = {p:.1f}: S = {S:.4f}")

        S_vals = np.array(S_vals)

        # Plot
        fig, ax = plt.subplots(figsize=(10, 7))

        ax.plot(p_range, S_vals, 'b-', linewidth=2.5, label='History framework')
        ax.axhline(2*np.sqrt(2), color='r', linestyle='--', linewidth=2,
                  label=f'Quantum bound ({2*np.sqrt(2):.3f})')
        ax.axhline(2.0, color='g', linestyle='--', linewidth=2,
                  label='Classical bound (2.000)')

        # Experimental precision band
        ax.fill_between(p_range,
                       2*np.sqrt(2) - 0.003,
                       2*np.sqrt(2) + 0.003,
                       alpha=0.2, color='orange',
                       label='Current exp. precision (±0.003)')

        ax.set_xlabel('Non-uniformity parameter p', fontsize=12)
        ax.set_ylabel('CHSH parameter S', fontsize=12)
        ax.set_title('Bell Violation vs Measure Deviation\n(Sensitivity Analysis)',
                    fontsize=13, fontweight='bold')
        ax.legend(fontsize=10, loc='upper right')
        ax.grid(True, alpha=0.3)
        ax.set_xlim([0, 1])
        ax.set_ylim([1.9, 2.9])

        png_file = f"{self.output_dir}/fig2_sensitivity.png"
        pdf_file = f"{self.output_dir}/fig2_sensitivity.pdf"
        plt.savefig(png_file, dpi=150, bbox_inches='tight')
        plt.savefig(pdf_file, dpi=300, bbox_inches='tight')
        plt.close()

        print(f"✓ Saved: {png_file}")
        print(f"✓ Saved: {pdf_file}")

        # Save data
        npz_file = f"{self.output_dir}/sensitivity_data.npz"
        np.savez(npz_file, p_range=p_range, S_vals=S_vals)

        return {'p_range': p_range.tolist(), 'S_vals': S_vals.tolist()}

    def probability_tables(self):
        """P(++|θ) for different angles and measures"""

        angles = [0, 30, 45, 60, 90, 120, 135, 150, 180]
        angles_rad = [a * np.pi/180 for a in angles]
        measures = ['quantum', 'peaked', 'bimodal']

        results = []

        print("-" * 60)
        print(f"{'Measure':<10} {'θ':<6} {'P(++)':<10} {'Quantum':<10} {'Deviation':<12}")
        print("-" * 60)

        for measure in measures:
            kernel = EPRCouplingKernel(measure)

            for theta_deg, theta_rad in zip(angles, angles_rad):
                a = np.array([1, 0, 0])
                b = np.array([np.cos(theta_rad), np.sin(theta_rad), 0])

                Ppp = kernel.probability_pp(a, b, n_samples=50000)

                # Quantum prediction: P(++) = (1 - cos(θ))/4
                quantum_Ppp = (1 - np.cos(theta_rad)) / 4
                deviation = Ppp - quantum_Ppp

                results.append({
                    'measure': measure,
                    'angle_deg': theta_deg,
                    'angle_rad': theta_rad,
                    'P_pp': float(Ppp),
                    'quantum_P_pp': float(quantum_Ppp),
                    'deviation': float(deviation)
                })

                print(f"{measure:<10} {theta_deg:3d}°   {Ppp:.5f}    {quantum_Ppp:.5f}    {deviation:+.6f}")

        print("-" * 60)

        # Save table
        df = pd.DataFrame(results)
        csv_file = f"{self.output_dir}/table2_probabilities.csv"
        df.to_csv(csv_file, index=False, float_format='%.6f')
        print(f"✓ Saved: {csv_file}")

        return results

    def plot_measure_densities(self):
        """Visualize measure densities μ(φ)"""

        phi = np.linspace(0, 2*np.pi, 1000)

        # Quantum (uniform)
        mu_quantum = np.ones_like(phi) / (2*np.pi)

        # Peaked (Gaussian mixture)
        sigma = np.pi/8
        mu_peaked = (np.exp(-(phi)**2 / (2*sigma**2)) +
                     np.exp(-(phi - np.pi)**2 / (2*sigma**2)) +
                     np.exp(-(phi - 2*np.pi)**2 / (2*sigma**2)))
        # Use trapezoid (trapz deprecated in numpy 2.x)
        from scipy.integrate import trapezoid
        mu_peaked /= trapezoid(mu_peaked, phi)

        # Bimodal (delta functions approximated)
        mu_bimodal = np.zeros_like(phi)
        mu_bimodal[np.argmin(np.abs(phi - 0))] = 1000
        mu_bimodal[np.argmin(np.abs(phi - np.pi))] = 1000

        fig, axes = plt.subplots(1, 3, figsize=(16, 5))

        # Quantum
        axes[0].fill_between(phi, mu_quantum, alpha=0.3, color='blue')
        axes[0].plot(phi, mu_quantum, 'b-', linewidth=2)
        axes[0].set_title('Quantum Measure\n(Uniform → Born rule)', fontweight='bold')
        axes[0].set_xlabel('Phase φ (radians)')
        axes[0].set_ylabel('μ(φ)')
        axes[0].grid(True, alpha=0.3)

        # Peaked
        axes[1].fill_between(phi, mu_peaked, alpha=0.3, color='orange')
        axes[1].plot(phi, mu_peaked, 'orange', linewidth=2)
        axes[1].set_title('Peaked Measure\n(Concentrated at 0, π)', fontweight='bold')
        axes[1].set_xlabel('Phase φ (radians)')
        axes[1].grid(True, alpha=0.3)

        # Bimodal
        axes[2].stem([0, np.pi], [0.5, 0.5], basefmt=' ', linefmt='r-', markerfmt='ro')
        axes[2].set_title('Bimodal Measure\n(Discrete: δ(0) + δ(π))', fontweight='bold')
        axes[2].set_xlabel('Phase φ (radians)')
        axes[2].set_ylim([0, 0.6])
        axes[2].grid(True, alpha=0.3)

        for ax in axes:
            ax.set_xlim([0, 2*np.pi])
            ax.set_xticks([0, np.pi/2, np.pi, 3*np.pi/2, 2*np.pi])
            ax.set_xticklabels(['0', 'π/2', 'π', '3π/2', '2π'])

        plt.tight_layout()

        png_file = f"{self.output_dir}/fig3_measures.png"
        pdf_file = f"{self.output_dir}/fig3_measures.pdf"
        plt.savefig(png_file, dpi=150, bbox_inches='tight')
        plt.savefig(pdf_file, dpi=300, bbox_inches='tight')
        plt.close()

        print(f"✓ Saved: {png_file}")
        print(f"✓ Saved: {pdf_file}")


def main():
    """Run complete EPR analysis"""
    analysis = ComprehensiveEPRAnalysis()
    results = analysis.run_all()

    print("\n" + "="*60)
    print("ANALYSIS COMPLETE")
    print("="*60)
    print(f"\nResults directory: {analysis.output_dir}/")
    print("\nGenerated files:")
    print("  - table1_chsh_comparison.csv")
    print("  - table2_probabilities.csv")
    print("  - fig1_correlations.png/pdf")
    print("  - fig2_sensitivity.png/pdf")
    print("  - fig3_measures.png/pdf")
    print("  - all_results.json")
    print("  - *.npz data files")
    print("\n✓ Ready for paper inclusion")


if __name__ == "__main__":
    main()
