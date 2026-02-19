#!/usr/bin/env python3
"""
Particle Mass φ-Ratio Analysis
==============================

Tests whether particle mass ratios show clustering near Fibonacci (golden ratio φ) powers.

Hypothesis: If substrate eigenmodes follow Fibonacci-Zeno structure, particle mass
ratios should preferentially appear near φ^n for integer n.

Null Hypothesis: Mass ratios are randomly distributed (no φ-clustering).

Statistical Test:
1. Calculate all pairwise mass ratios from PDG data
2. Measure distance to nearest φ^n value
3. Compare to random shuffling (Monte Carlo)
4. Calculate p-value for significance

Falsification:
- If p > 0.05: No evidence for φ-spacing (Fibonacci mechanism wrong)
- If p < 0.05: Evidence for φ-spacing (supports framework)

Author: Substrate Theory Testing Group
Date: 2026-01-02
Status: Critical falsification test
"""

import math
from dataclasses import dataclass
from typing import List, Tuple, Dict
import random

# ============================================================================
# CONSTANTS
# ============================================================================

phi = (1 + math.sqrt(5)) / 2  # Golden ratio ≈ 1.618

# Fibonacci powers to test (φ^n for n = -5 to +10)
PHI_POWERS = {n: phi**n for n in range(-5, 11)}

# ============================================================================
# PARTICLE DATA (from PDG 2024)
# ============================================================================

@dataclass
class Particle:
    """Particle with mass in MeV"""
    name: str
    mass_MeV: float
    category: str  # 'lepton', 'quark', 'meson', 'baryon', 'boson'

# Standard Model fundamental particles
PARTICLES = [
    # Leptons
    Particle("electron", 0.511, "lepton"),
    Particle("muon", 105.66, "lepton"),
    Particle("tau", 1776.86, "lepton"),

    # Quarks (constituent masses, not current masses)
    Particle("up", 2.2, "quark"),
    Particle("down", 4.7, "quark"),
    Particle("strange", 95, "quark"),
    Particle("charm", 1275, "quark"),
    Particle("bottom", 4180, "quark"),
    Particle("top", 173100, "quark"),

    # Bosons
    Particle("W", 80377, "boson"),
    Particle("Z", 91188, "boson"),
    Particle("Higgs", 125100, "boson"),

    # Light mesons
    Particle("π0", 134.98, "meson"),
    Particle("π±", 139.57, "meson"),
    Particle("η", 547.86, "meson"),
    Particle("η'", 957.78, "meson"),
    Particle("K0", 497.61, "meson"),
    Particle("K±", 493.67, "meson"),

    # Heavy mesons
    Particle("D0", 1864.84, "meson"),
    Particle("D±", 1869.65, "meson"),
    Particle("Ds", 1968.35, "meson"),
    Particle("B0", 5279.65, "meson"),
    Particle("B±", 5279.34, "meson"),
    Particle("Bs", 5366.88, "meson"),
    Particle("ηc", 2983.9, "meson"),
    Particle("J/ψ", 3096.90, "meson"),
    Particle("Υ", 9460.30, "meson"),

    # Baryons
    Particle("proton", 938.27, "baryon"),
    Particle("neutron", 939.57, "baryon"),
    Particle("Λ", 1115.68, "baryon"),
    Particle("Σ+", 1189.37, "baryon"),
    Particle("Σ0", 1192.64, "baryon"),
    Particle("Σ-", 1197.45, "baryon"),
    Particle("Ξ0", 1314.86, "baryon"),
    Particle("Ξ-", 1321.71, "baryon"),
    Particle("Δ", 1232, "baryon"),
    Particle("Ω", 1672.45, "baryon"),
    Particle("Λc", 2286.46, "baryon"),
    Particle("Λb", 5619.60, "baryon"),
]

# ============================================================================
# ANALYSIS FUNCTIONS
# ============================================================================

def calculate_all_ratios(particles: List[Particle]) -> List[Tuple[str, str, float]]:
    """
    Calculate all pairwise mass ratios (larger/smaller).

    Returns list of (particle1, particle2, ratio) tuples.
    """
    ratios = []

    for i, p1 in enumerate(particles):
        for j, p2 in enumerate(particles):
            if i >= j:  # Avoid duplicates and self-ratios
                continue

            # Always take larger/smaller
            if p1.mass_MeV > p2.mass_MeV:
                ratio = p1.mass_MeV / p2.mass_MeV
                ratios.append((p1.name, p2.name, ratio))
            else:
                ratio = p2.mass_MeV / p1.mass_MeV
                ratios.append((p2.name, p1.name, ratio))

    return ratios


def find_nearest_phi_power(ratio: float, phi_powers: Dict[int, float]) -> Tuple[int, float, float]:
    """
    Find nearest φ^n to given ratio.

    Returns: (n, φ^n, distance)
    """
    min_distance = float('inf')
    best_n = 0
    best_phi_n = 1.0

    for n, phi_n in phi_powers.items():
        # Use log-scale distance (ratios are multiplicative)
        distance = abs(math.log(ratio) - math.log(phi_n))

        if distance < min_distance:
            min_distance = distance
            best_n = n
            best_phi_n = phi_n

    return best_n, best_phi_n, min_distance


def calculate_clustering_metric(ratios: List[float], phi_powers: Dict[int, float]) -> float:
    """
    Calculate how much ratios cluster near φ^n values.

    Metric: Mean log-distance to nearest φ^n.
    Lower = more clustering.
    """
    distances = []

    for ratio in ratios:
        _, _, distance = find_nearest_phi_power(ratio, phi_powers)
        distances.append(distance)

    return sum(distances) / len(distances) if distances else 0.0


def monte_carlo_test(masses: List[float], n_trials: int = 10000) -> List[float]:
    """
    Monte Carlo test: shuffle masses randomly and measure clustering.

    Returns list of clustering metrics for random shufflings.
    """
    random_metrics = []

    for trial in range(n_trials):
        # Shuffle masses
        shuffled = masses.copy()
        random.shuffle(shuffled)

        # Calculate ratios
        ratios = []
        for i in range(len(shuffled)):
            for j in range(i + 1, len(shuffled)):
                if shuffled[i] > shuffled[j]:
                    ratios.append(shuffled[i] / shuffled[j])
                else:
                    ratios.append(shuffled[j] / shuffled[i])

        # Calculate clustering metric
        metric = calculate_clustering_metric(ratios, PHI_POWERS)
        random_metrics.append(metric)

    return random_metrics


def calculate_p_value(observed: float, random_distribution: List[float]) -> float:
    """
    Calculate p-value: fraction of random trials with equal or better clustering.
    """
    better_or_equal = sum(1 for r in random_distribution if r <= observed)
    return better_or_equal / len(random_distribution)


# ============================================================================
# MAIN ANALYSIS
# ============================================================================

def main():
    print("="*80)
    print("PARTICLE MASS φ-RATIO ANALYSIS")
    print("="*80)
    print()
    print(f"Testing {len(PARTICLES)} particles from PDG")
    print(f"Golden ratio φ = {phi:.6f}")
    print()

    # Calculate all ratios
    print("Calculating all pairwise mass ratios...")
    ratio_data = calculate_all_ratios(PARTICLES)
    ratios = [r[2] for r in ratio_data]

    print(f"  Total ratios: {len(ratios)}")
    print(f"  Min ratio: {min(ratios):.2f}")
    print(f"  Max ratio: {max(ratios):.2e}")
    print()

    # Find φ^n matches
    print("Finding nearest φ^n for each ratio...")
    print()

    # Group by φ^n
    phi_matches = {}
    for particle1, particle2, ratio in ratio_data:
        n, phi_n, distance = find_nearest_phi_power(ratio, PHI_POWERS)

        if n not in phi_matches:
            phi_matches[n] = []

        phi_matches[n].append({
            'particles': f"{particle1}/{particle2}",
            'ratio': ratio,
            'phi_n': phi_n,
            'distance': distance
        })

    # Print best matches (distance < 0.1 in log space)
    print("Strong φ^n candidates (log-distance < 0.1):")
    print("-" * 80)

    strong_matches = []
    for n in sorted(phi_matches.keys()):
        matches = phi_matches[n]
        close_matches = [m for m in matches if m['distance'] < 0.1]

        if close_matches:
            print(f"\nφ^{n} = {phi**n:.4f}:")
            for match in sorted(close_matches, key=lambda x: x['distance'])[:5]:
                print(f"  {match['particles']:30s}  ratio={match['ratio']:8.4f}  "
                      f"(φ^{n}={match['phi_n']:.4f}, Δ={match['distance']:.4f})")
                strong_matches.append(match)

    print()
    print(f"Total strong matches: {len(strong_matches)}")
    print()

    # Calculate clustering metric
    print("="*80)
    print("STATISTICAL SIGNIFICANCE TEST")
    print("="*80)
    print()

    observed_metric = calculate_clustering_metric(ratios, PHI_POWERS)
    print(f"Observed clustering metric: {observed_metric:.4f}")
    print("  (lower = more clustering near φ^n)")
    print()

    # Monte Carlo test
    print("Running Monte Carlo test (10,000 random shufflings)...")
    masses = [p.mass_MeV for p in PARTICLES]
    random_metrics = monte_carlo_test(masses, n_trials=10000)

    mean_random = sum(random_metrics) / len(random_metrics)
    std_random = math.sqrt(sum((x - mean_random)**2 for x in random_metrics) / len(random_metrics))

    print(f"  Random mean: {mean_random:.4f}")
    print(f"  Random std:  {std_random:.4f}")
    print()

    # Calculate p-value
    p_value = calculate_p_value(observed_metric, random_metrics)

    print(f"p-value: {p_value:.4f}")
    print()

    # Interpretation
    print("="*80)
    print("INTERPRETATION")
    print("="*80)
    print()

    if p_value < 0.001:
        verdict = "EXTREMELY STRONG evidence for φ-clustering"
        conclusion = "✓ Fibonacci-Zeno mechanism STRONGLY SUPPORTED"
    elif p_value < 0.01:
        verdict = "STRONG evidence for φ-clustering"
        conclusion = "✓ Fibonacci-Zeno mechanism supported"
    elif p_value < 0.05:
        verdict = "MODERATE evidence for φ-clustering"
        conclusion = "✓ Fibonacci-Zeno mechanism weakly supported"
    else:
        verdict = "NO significant evidence for φ-clustering"
        conclusion = "✗ Fibonacci-Zeno mass spacing FALSIFIED"

    print(f"Result: {verdict}")
    print(f"p = {p_value:.4f} {'<' if p_value < 0.05 else '>'} 0.05")
    print()
    print(f"CONCLUSION: {conclusion}")
    print()

    if p_value < 0.05:
        print("Next steps:")
        print("  1. Examine specific φ^n matches for physical interpretation")
        print("  2. Test if matches correspond to eigenmode predictions")
        print("  3. Look for pattern in particle types (leptons, mesons, etc.)")
        print("  4. Check if ratios match (n₁² + l₁)/(n₂² + l₂) formula")
    else:
        print("Implications:")
        print("  ✗ Particle masses do NOT show Fibonacci spacing")
        print("  ✗ Either eigenmode formula is wrong, or φ-mechanism doesn't apply")
        print("  ✗ May need to revise tachyonic-Fibonacci connection")
        print("  ✓ Honest negative result (good epistemology)")

    print()
    print("="*80)
    print("ANALYSIS COMPLETE")
    print("="*80)
    print()

    # Save detailed results
    print("Saving detailed results to particle_mass_phi_results.txt...")

    with open("theories/experiments/particle_mass_phi_results.txt", "w") as f:
        f.write("PARTICLE MASS φ-RATIO ANALYSIS - DETAILED RESULTS\n")
        f.write("="*80 + "\n\n")
        f.write(f"Date: 2026-01-02\n")
        f.write(f"Particles analyzed: {len(PARTICLES)}\n")
        f.write(f"Total ratios: {len(ratios)}\n")
        f.write(f"p-value: {p_value:.6f}\n")
        f.write(f"Verdict: {verdict}\n\n")

        f.write("ALL RATIOS WITH NEAREST φ^n:\n")
        f.write("-"*80 + "\n")
        f.write(f"{'Particle 1':<20} {'Particle 2':<20} {'Ratio':>10} {'φ^n':>6} {'Distance':>10}\n")
        f.write("-"*80 + "\n")

        for p1, p2, ratio in sorted(ratio_data, key=lambda x: x[2]):
            n, phi_n, distance = find_nearest_phi_power(ratio, PHI_POWERS)
            f.write(f"{p1:<20} {p2:<20} {ratio:>10.4f} φ^{n:>2} {distance:>10.4f}\n")

    print("Results saved.")
    print()


if __name__ == "__main__":
    random.seed(42)  # Reproducible results
    main()
