#!/usr/bin/env python3
"""
Tachyonic Eigenmode Cosmological Bounds
=========================================

Extension of substrate eigenmode theory to imaginary radial quantum numbers.

If substrate eigenmodes allow n = iκ (imaginary n), then:
    m² = (n² + l_ico)² × m_e²
       = ((iκ)² + l_ico)² × m_e²
       = (-κ² + l_ico)² × m_e²

For -κ² + l_ico < 0: m² < 0 (tachyonic solution)

This script calculates:
1. Lowest tachyonic eigenmode masses
2. Cosmological constraints (BBN, CMB, stellar cooling)
3. Early universe structure formation implications
4. Vacuum stability analysis

Author: Substrate Theory Testing Group
Date: 2025-12-30
Status: Speculative extension - testing mathematical consistency
"""

import math
from dataclasses import dataclass
from typing import Dict, List, Optional

# ============================================================================
# PHYSICAL CONSTANTS
# ============================================================================

c = 2.998e8          # m/s (speed of light)
hbar = 1.055e-34     # J·s
m_e_MeV = 0.511      # MeV/c² (electron mass)
MeV = 1.602e-13      # J
alpha = 1/137.036    # Fine structure constant

# Cosmological parameters
T_BBN_MeV = 0.1      # BBN temperature
T_recomb_MeV = 0.26e-6  # Recombination (~0.26 eV)
M_Pl_GeV = 1.22e19   # Planck mass (GeV)

# Observable constraints
N_eff_allowed = 0.17  # Allowed deviation in N_eff


# ============================================================================
# TACHYONIC EIGENMODE SPECTRUM
# ============================================================================

@dataclass
class TachyonicMode:
    """Tachyonic substrate eigenmode with m² < 0"""
    name: str
    kappa: float  # Imaginary quantum number (n = iκ)
    l: int        # Angular momentum quantum number

    # Derived properties
    m_squared: float = None  # Negative (MeV²)
    mass_imaginary: float = None  # Imaginary mass (iM where M is real MeV)

    # Vacuum properties
    lifetime_s: float = None
    decay_width_MeV: float = None
    tunneling_rate_per_s: float = None

    def __post_init__(self):
        """Calculate tachyonic properties"""

        # For eigenmode formula m = (n² + l) × m_e with n = iκ:
        # m = ((iκ)² + l) × m_e = (-κ² + l) × m_e
        # So m² = (-κ² + l)² × m_e² is WRONG (always positive)
        #
        # Correct interpretation for tachyon:
        # m² = (-κ² + l) × m_e²  (not squared!)
        #
        # This gives m² < 0 when κ² > l

        quantum_number = -self.kappa**2 + self.l
        self.m_squared = quantum_number * m_e_MeV**2  # Linear, not squared

        # For tachyons: m² < 0 → m = i|m|
        if self.m_squared < 0:
            self.mass_imaginary = math.sqrt(abs(self.m_squared))
        else:
            self.mass_imaginary = None  # Not actually tachyonic

        # Vacuum decay properties
        self._calculate_vacuum_decay()

    def _calculate_vacuum_decay(self):
        """
        Tachyonic field causes vacuum instability

        Growth rate: Γ ~ |m|c (exponential growth)
        Tunneling rate: Γ_tunnel ~ exp(-S_E) where S_E is Euclidean action

        For substrate tachyon:
        - If part of allowed spectrum → rapid decay to stable configuration
        - Lifetime ~ 1/(|m|c)
        """

        if self.mass_imaginary is None:
            return

        # Decay width (energy units)
        # For tachyon: Γ ~ |m|c (natural timescale)
        # Suppressed by substrate coupling ~ α²
        self.decay_width_MeV = alpha**2 * self.mass_imaginary

        # Lifetime
        self.lifetime_s = hbar / (self.decay_width_MeV * MeV)

        # Tunneling/growth rate
        self.tunneling_rate_per_s = 1 / self.lifetime_s


# ============================================================================
# TACHYONIC SPECTRUM FROM SUBSTRATE GEOMETRY
# ============================================================================

def generate_tachyonic_spectrum(max_kappa: int = 3) -> List[TachyonicMode]:
    """
    Generate tachyonic eigenmodes for substrate

    Condition for tachyon: -κ² + l < 0 → κ² > l

    Lowest modes:
    - κ=1, l=0: -1² + 0 = -1 (tachyonic)
    - κ=2, l=0: -4² + 0 = -4 (tachyonic)
    - κ=1, l=1: -1² + 1 = 0 (marginal, not tachyonic)
    """

    modes = []

    for kappa in range(1, max_kappa + 1):
        for l in [0, 1, 6, 10, 15]:  # Representative l values from icosahedral

            quantum_number = -kappa**2 + l

            if quantum_number < 0:  # Tachyonic condition
                mode = TachyonicMode(
                    name=f"tachyon_k{kappa}_l{l}",
                    kappa=kappa,
                    l=l
                )
                modes.append(mode)

    return modes


# ============================================================================
# COSMOLOGICAL CONSTRAINTS ON TACHYONS
# ============================================================================

class TachyonCosmology:
    """Cosmological bounds on tachyonic substrate modes"""

    def __init__(self, modes: List[TachyonicMode]):
        self.modes = modes

    def vacuum_stability_check(self) -> Dict:
        """
        Are tachyonic modes consistent with stable vacuum?

        Two possibilities:
        1. Tachyons indicate vacuum instability → universe unstable (BAD)
        2. Tachyons decay rapidly → mark phase boundaries (OK)

        If lifetime << t_universe → safe (already decayed)
        If lifetime ~ t_universe → dangerous (ongoing decay)
        """

        t_universe_s = 4.3e17  # ~13.8 billion years in seconds

        results = {}

        for mode in self.modes:

            # Is tachyon stable on cosmological timescales?
            stable_on_cosmic_time = mode.lifetime_s > t_universe_s

            # Decay temperature (when Γ = H)
            Gamma_GeV = mode.tunneling_rate_per_s * hbar / (1.602e-10)
            T_decay_GeV = math.sqrt(Gamma_GeV * M_Pl_GeV)
            T_decay_MeV = T_decay_GeV * 1000

            results[mode.name] = {
                'm_squared_MeV2': mode.m_squared,
                'imaginary_mass_MeV': mode.mass_imaginary,
                'lifetime_s': mode.lifetime_s,
                'decay_temperature_MeV': T_decay_MeV,
                'stable_to_present': stable_on_cosmic_time,
                'verdict': 'UNSTABLE VACUUM' if stable_on_cosmic_time else 'DECAYED EARLY'
            }

        return results

    def BBN_constraint(self) -> Dict:
        """
        Do tachyons violate BBN?

        If tachyon decays before BBN (T_decay > 0.1 MeV):
        - Decays to photons → contributes to radiation density
        - If ΔN_eff > 0.17 → VIOLATION

        If tachyon decays during BBN:
        - Energy injection → can dissociate light elements
        - DANGEROUS
        """

        results = {}
        total_delta_N_eff = 0

        for mode in self.modes:

            # Decay temperature
            Gamma_GeV = mode.tunneling_rate_per_s * hbar / (1.602e-10)
            T_decay_MeV = math.sqrt(Gamma_GeV * M_Pl_GeV) * 1000

            # Does it decay before BBN?
            decays_before_BBN = T_decay_MeV > T_BBN_MeV

            if not decays_before_BBN:
                # Present during BBN or decays during
                # Contributes to N_eff (very rough estimate)
                # Each relativistic degree of freedom: ΔN_eff ~ 0.4
                delta_N = 0.4
                total_delta_N_eff += delta_N

                results[mode.name] = {
                    'present_at_BBN': True,
                    'decay_temp_MeV': T_decay_MeV,
                    'delta_N_eff': delta_N,
                    'status': 'CONTRIBUTES TO RADIATION'
                }
            else:
                results[mode.name] = {
                    'present_at_BBN': False,
                    'decay_temp_MeV': T_decay_MeV,
                    'status': 'DECAYED BEFORE BBN'
                }

        violates = total_delta_N_eff > N_eff_allowed

        return {
            'individual_modes': results,
            'total_delta_N_eff': total_delta_N_eff,
            'allowed': N_eff_allowed,
            'VIOLATES_BBN': violates,
            'verdict': 'FALSIFIED' if violates else 'SAFE'
        }

    def structure_formation_enhancement(self) -> Dict:
        """
        Can tachyons explain early structure formation?

        Observation: Galaxies form "too early" (by z~10)

        Tachyonic mechanism:
        1. Density perturbations create tachyonic modes
        2. Exponential growth: exp(Γt) where Γ ~ |m|c
        3. Substrate reorganizes superluminally
        4. Matter follows substrate → structure forms faster

        Prediction: Growth rate enhanced by exp(|m|ct / ℏ)
        """

        results = {}

        # Time from recombination to z~10 structure
        t_structure_formation_s = 5e14  # ~500 million years

        for mode in self.modes:

            # Growth factor
            exponent = mode.tunneling_rate_per_s * t_structure_formation_s

            # For numerical stability, cap at 700
            if exponent > 700:
                growth_factor = float('inf')
            else:
                growth_factor = math.exp(exponent)

            # Enhancement over standard (matter-dominated) growth
            # Standard: a(t) ∝ t^(2/3) → growth ~10x from z=1000 to z=10
            standard_growth = 10
            enhancement = growth_factor / standard_growth if growth_factor != float('inf') else float('inf')

            results[mode.name] = {
                'imaginary_mass_MeV': mode.mass_imaginary,
                'growth_rate_per_s': mode.tunneling_rate_per_s,
                'growth_factor': growth_factor,
                'enhancement_over_standard': enhancement,
                'explains_early_galaxies': enhancement > 1
            }

        return results


# ============================================================================
# DARK FLOW AND SUPERLUMINAL SUBSTRATE
# ============================================================================

class DarkFlowAnalysis:
    """
    Connection between tachyonic substrate and observed dark flow

    Observation: Galaxies show bulk flow extending beyond expected range

    Standard explanation: Gravitational pull from distant structures
    Problem: Should only affect matter within light cone

    Tachyonic substrate explanation:
    - Great Attractor creates tidal stress
    - Substrate reorganizes superluminally via tachyonic phase velocity
    - Galaxies follow substrate configuration, not just gravitational field
    - Flow can extend beyond light cone
    """

    def __init__(self, tachyon_mass_imaginary_MeV: float):
        self.tachyon_mass = tachyon_mass_imaginary_MeV

    def substrate_reorganization_speed(self) -> float:
        """
        Phase velocity of substrate reorganization

        For tachyon: v_phase can exceed c

        Estimate: v_phase ~ c × (1 + |m|²c²/E²)
        where E is characteristic energy scale
        """

        # Characteristic energy scale (cosmological Hubble)
        H_0_GeV = 1.4e-42  # Hubble constant in GeV
        E_cosmic_MeV = H_0_GeV * 1000

        # Phase velocity enhancement
        enhancement = 1 + (self.tachyon_mass * c)**2 / (E_cosmic_MeV * MeV * c**2)**2

        v_phase = c * math.sqrt(abs(enhancement))

        return v_phase

    def dark_flow_extent_Mpc(self, time_since_perturbation_Gyr: float) -> float:
        """
        How far can substrate reorganization propagate?

        If v > c, substrate can affect regions beyond light cone
        """

        v = self.substrate_reorganization_speed()

        # Convert time to meters
        Gyr_to_s = 3.15e16
        time_s = time_since_perturbation_Gyr * Gyr_to_s

        # Distance traveled
        distance_m = v * time_s

        # Convert to Mpc
        Mpc_to_m = 3.086e22
        distance_Mpc = distance_m / Mpc_to_m

        return distance_Mpc


# ============================================================================
# MAIN ANALYSIS
# ============================================================================

def run_tachyon_analysis():
    """Run complete tachyonic eigenmode analysis"""

    print("="*80)
    print("TACHYONIC SUBSTRATE EIGENMODE ANALYSIS")
    print("="*80)
    print()
    print("Testing mathematical extension: n → iκ (imaginary radial quantum number)")
    print("Condition for tachyon: -κ² + l < 0 → m² < 0")
    print()

    # Generate spectrum
    print("TACHYONIC EIGENMODE SPECTRUM")
    print("-" * 80)

    modes = generate_tachyonic_spectrum(max_kappa=3)

    print(f"\nFound {len(modes)} candidate tachyonic modes:")

    actual_tachyons = [m for m in modes if m.mass_imaginary is not None]

    for mode in actual_tachyons:
        print(f"\n{mode.name}:")
        print(f"  κ = {mode.kappa}, l = {mode.l}")
        print(f"  m² = {mode.m_squared:.3f} MeV² (NEGATIVE)")
        print(f"  m = i × {mode.mass_imaginary:.3f} MeV (imaginary)")
        print(f"  Lifetime: {mode.lifetime_s:.2e} s")
        print(f"  Decay width: {mode.decay_width_MeV:.2e} MeV")

    if len(actual_tachyons) == 0:
        print("\n⚠️  NO ACTUAL TACHYONS FOUND")
        print("   All modes have m² ≥ 0")
        print("   Substrate naturally excludes tachyonic solutions")
        return False

    modes = actual_tachyons  # Continue only with true tachyons

    # Cosmological constraints
    print("\n" + "="*80)
    print("COSMOLOGICAL CONSTRAINTS")
    print("="*80)

    cosmo = TachyonCosmology(modes)

    # Vacuum stability
    print("\n1. VACUUM STABILITY")
    print("-" * 80)
    vacuum_results = cosmo.vacuum_stability_check()

    unstable = []
    for name, result in vacuum_results.items():
        print(f"\n{name}:")
        print(f"  Lifetime: {result['lifetime_s']:.2e} s")
        print(f"  Decay temperature: {result['decay_temperature_MeV']:.2e} MeV")
        print(f"  Status: {result['verdict']}")

        if result['stable_to_present']:
            unstable.append(name)

    if unstable:
        print(f"\n❌ VACUUM UNSTABLE: {unstable}")
        print("   Tachyons persist to present → universe should have decayed")
        print("   THEORY FALSIFIED")
        return False
    else:
        print("\n✓ All tachyons decay early (before present)")
        print("  → Consistent with stable vacuum")

    # BBN
    print("\n" + "="*80)
    print("2. BIG BANG NUCLEOSYNTHESIS")
    print("-" * 80)

    bbn_results = cosmo.BBN_constraint()

    print(f"\nTotal ΔN_eff: {bbn_results['total_delta_N_eff']:.3f}")
    print(f"Allowed: {bbn_results['allowed']:.3f}")
    print(f"Verdict: {bbn_results['verdict']}")

    if bbn_results['VIOLATES_BBN']:
        print("\n❌ BBN CONSTRAINT VIOLATED")
        print("   Tachyons contribute too much to radiation density")
        return False
    else:
        print("\n✓ Passes BBN constraint")

    # Structure formation
    print("\n" + "="*80)
    print("3. EARLY STRUCTURE FORMATION")
    print("-" * 80)

    structure_results = cosmo.structure_formation_enhancement()

    print("\nCan tachyons explain 'too early' galaxy formation?")
    for name, result in structure_results.items():
        print(f"\n{name}:")
        print(f"  Growth enhancement: {result['enhancement_over_standard']:.2e}×")
        print(f"  Explains early galaxies: {result['explains_early_galaxies']}")

    # Dark flow
    print("\n" + "="*80)
    print("4. DARK FLOW IMPLICATIONS")
    print("-" * 80)

    # Use lightest tachyon for estimate
    lightest_mode = min(modes, key=lambda m: m.mass_imaginary)

    dark_flow = DarkFlowAnalysis(lightest_mode.mass_imaginary)
    v_phase = dark_flow.substrate_reorganization_speed()
    extent_Mpc = dark_flow.dark_flow_extent_Mpc(time_since_perturbation_Gyr=1)

    print(f"\nLightest tachyon: {lightest_mode.name}")
    print(f"  Imaginary mass: i × {lightest_mode.mass_imaginary:.3f} MeV")
    print(f"  Substrate phase velocity: {v_phase/c:.2e} × c")
    print(f"  Dark flow extent (1 Gyr): {extent_Mpc:.2f} Mpc")

    if v_phase > c:
        print("\n⚡ SUPERLUMINAL SUBSTRATE REORGANIZATION")
        print("   Phase velocity exceeds c (not group velocity)")
        print("   Could explain dark flow beyond light cone")

    # Summary
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)

    print("\nTachyonic substrate eigenmodes:")
    print(f"  • {len(modes)} modes with m² < 0")
    print(f"  • All decay before present (stable vacuum)")
    print(f"  • Pass BBN constraints (ΔN_eff < 0.17)")
    print(f"  • Could enhance early structure formation")
    print(f"  • Could explain dark flow (superluminal substrate phase velocity)")

    print("\nKey predictions:")
    print("  1. No persistent tachyons (all decayed by z~1000)")
    print("  2. CMB anomalies from tachyon decay (cold spot, non-Gaussianity)")
    print("  3. Enhanced structure formation at high z")
    print("  4. Dark flow extends beyond light cone")

    print("\nFalsification criteria:")
    print("  ❌ If stable tachyon detected → vacuum should be unstable")
    print("  ❌ If ΔN_eff > 0.17 measured → BBN violation")
    print("  ✓ If CMB perfectly Gaussian → no tachyon decay signature")
    print("  ✓ If dark flow confined to light cone → no superluminal substrate")

    return True


if __name__ == "__main__":
    print("\nWARNING: This is a speculative mathematical extension.")
    print("Tachyonic modes (m² < 0) may or may not be physically realizable.")
    print("This calculation tests cosmological consistency only.\n")

    viable = run_tachyon_analysis()

    if viable:
        print("\n" + "="*80)
        print("✓ TACHYONIC SUBSTRATE IS COSMOLOGICALLY VIABLE")
        print("="*80)
        print("\nInterpretation:")
        print("  • Tachyons = substrate instability markers (not persistent particles)")
        print("  • Decay rapidly → leave cosmological imprint")
        print("  • Could explain: early galaxies, dark flow, CMB anomalies")
        print("\nNext steps:")
        print("  1. Search CMB for non-Gaussian signatures")
        print("  2. Analyze dark flow extent vs light cone")
        print("  3. Check high-z galaxy formation rates")
    else:
        print("\n" + "="*80)
        print("❌ TACHYONIC SUBSTRATE COSMOLOGICALLY FORBIDDEN")
        print("="*80)
        print("\nTachyonic modes violate observational constraints.")
        print("If substrate theory correct → must explain why m² < 0 forbidden.")
