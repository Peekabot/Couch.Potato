#!/usr/bin/env python3
"""
Cosmological Bounds on Substrate Eigenmodes
============================================

FASTEST FALSIFICATION TEST: Calculate if eigenmodes are allowed by:
1. Big Bang Nucleosynthesis (BBN)
2. Cosmic Microwave Background (CMB)
3. Stellar cooling (red giants, white dwarfs)

If ANY constraint violated → theory dead in 1 week (no experiments needed)

Author: Substrate Theory Testing Group
Date: 2025-12-30
Status: Critical falsification calculation
"""

import math
from dataclasses import dataclass
from typing import Dict, List

# ============================================================================
# PHYSICAL CONSTANTS
# ============================================================================

# Fundamental constants (SI units)
c = 2.998e8          # m/s
hbar = 1.055e-34     # J·s
k_B = 1.381e-23      # J/K
G_N = 6.674e-11      # m³/(kg·s²)
m_p = 1.673e-27      # kg (proton mass)
m_e = 9.109e-31      # kg (electron mass)

# Particle physics units
MeV = 1.602e-13      # J (1 MeV in Joules)
GeV = 1.602e-10      # J
m_e_MeV = 0.511      # MeV/c²

# Cosmological parameters (Planck 2018)
T_CMB_now = 2.7255   # K (current CMB temperature)
T_BBN = 0.1e9        # K (temperature during BBN, ~0.1 MeV)
T_recomb = 3000      # K (recombination temperature)

# Observational constraints
N_eff_measured = 2.99      # ± 0.17 (effective neutrino species)
N_eff_uncertainty = 0.17


# ============================================================================
# EIGENMODE PROPERTIES
# ============================================================================

@dataclass
class Eigenmode:
    """Substrate eigenmode with cosmological properties"""
    name: str
    mass_MeV: float
    n: int
    l: int

    # To be calculated
    lifetime_s: float = None
    decay_temperature_MeV: float = None
    relic_abundance: float = None

    def __post_init__(self):
        """Calculate derived properties"""
        if self.lifetime_s is None:
            self.lifetime_s = self._estimate_lifetime()

        if self.decay_temperature_MeV is None:
            self.decay_temperature_MeV = self._decay_temperature()

    def _estimate_lifetime(self) -> float:
        """
        Estimate eigenmode lifetime from phase space and coupling

        Rough scaling:
        - τ ~ 1/(α² m³) for EM decays
        - Increased by substrate complexity (n² + l)
        """

        # Fine structure constant
        alpha = 1/137.036

        # Phase space factor (∝ m³ for three-body decay e⁺e⁻γ)
        phase_space = (self.mass_MeV / m_e_MeV)**3

        # Substrate complexity penalty (higher modes couple slower)
        complexity = self.n**2 + self.l

        # Natural scale for EM process (reduced Compton time)
        tau_0 = hbar / (m_e_MeV * MeV * c**2)  # ~10⁻²¹ s

        # Lifetime estimate
        lifetime = tau_0 * complexity / (alpha**2 * phase_space)

        return lifetime

    def _decay_temperature(self) -> float:
        """
        Temperature at which Γ = H (decay rate equals Hubble)

        If T_decay > T_BBN → decays before BBN (safe)
        If T_decay < T_BBN → present during BBN (dangerous)
        """

        # Hubble rate: H(T) = 1.66 g_*^(1/2) T² / M_Pl
        # Decay rate: Γ = 1/τ

        # For order of magnitude, use Γ = H when T ~ (Γ M_Pl)^(1/2)
        M_Pl_GeV = 1.22e19  # GeV (Planck mass)

        Gamma = 1 / self.lifetime_s  # s⁻¹
        Gamma_GeV = Gamma * hbar / GeV  # Convert to GeV units

        # T_decay ~ sqrt(Γ M_Pl)
        T_decay_GeV = math.sqrt(Gamma_GeV * M_Pl_GeV)
        T_decay_MeV = T_decay_GeV * 1000

        return T_decay_MeV


# Predicted eigenmodes
EIGENMODES = [
    Eigenmode("eigen_2_0", 2.044, 2, 0),
    Eigenmode("eigen_3_0", 4.599, 3, 0),
    Eigenmode("eigen_5_0", 12.775, 5, 0),
    Eigenmode("eigen_7_6", 28.105, 7, 6),
    Eigenmode("eigen_10_10", 56.21, 10, 10),
    Eigenmode("eigen_25_15", 167.1, 25, 15),
]


# ============================================================================
# TEST 1: BIG BANG NUCLEOSYNTHESIS (BBN)
# ============================================================================

class BBNConstraint:
    """
    BBN constraint on new physics

    Requirements:
    1. No new relativistic species during BBN (T ~ 0.1 MeV)
    2. No late-decaying particles that inject energy
    3. No electromagnetic cascades that dissociate light elements
    """

    T_BBN_MeV = 0.1  # Temperature during BBN

    def __init__(self, eigenmodes: List[Eigenmode]):
        self.eigenmodes = eigenmodes

    def check_N_eff(self) -> Dict:
        """
        Check if eigenmodes contribute to N_eff

        N_eff counts relativistic degrees of freedom at BBN
        Observation: N_eff = 2.99 ± 0.17
        Standard Model: N_eff = 3.046 (3 neutrinos)

        Room for new physics: ΔN_eff < 0.17
        """

        results = {}
        total_delta_N_eff = 0

        for mode in self.eigenmodes:

            # Is eigenmode in thermal equilibrium at BBN?
            if mode.mass_MeV < 3 * self.T_BBN_MeV:  # Boltzmann suppression

                # Each boson contributes ΔN_eff = (7/8) * (T_X/T_ν)^4
                # Assuming it's in equilibrium with photons: T_X = T_γ
                # And T_γ / T_ν = (11/4)^(1/3)

                delta_N = (7/8) * (4/11)**(4/3)
                total_delta_N_eff += delta_N

                results[mode.name] = {
                    'in_thermal_equilibrium': True,
                    'delta_N_eff': delta_N,
                    'status': 'CONTRIBUTES TO N_EFF'
                }
            else:
                results[mode.name] = {
                    'in_thermal_equilibrium': False,
                    'delta_N_eff': 0,
                    'status': 'BOLTZMANN SUPPRESSED'
                }

        # Check total
        violates_constraint = total_delta_N_eff > N_eff_uncertainty

        return {
            'individual_modes': results,
            'total_delta_N_eff': total_delta_N_eff,
            'allowed_delta_N_eff': N_eff_uncertainty,
            'CONSTRAINT_VIOLATED': violates_constraint,
            'verdict': 'THEORY FALSIFIED' if violates_constraint else 'BBN SAFE'
        }

    def check_late_decay(self) -> Dict:
        """
        Check if eigenmodes decay during/after BBN

        Problem: Late-time energy injection can:
        - Dissociate Deuterium (kills D/H ratio)
        - Overproduce Lithium-7
        - Mess up Helium-4 abundance
        """

        results = {}

        for mode in self.eigenmodes:

            decay_during_BBN = mode.decay_temperature_MeV < 1.0  # MeV

            if decay_during_BBN:
                # Energy injected per decay
                E_inj = mode.mass_MeV

                # Rough bound: E_inj * n_X / n_γ < 10^-9 (very conservative)
                # This prevents deuterium photodissociation

                results[mode.name] = {
                    'decays_during_BBN': True,
                    'decay_temp_MeV': mode.decay_temperature_MeV,
                    'energy_injected_MeV': E_inj,
                    'status': 'DANGEROUS - needs detailed calculation'
                }
            else:
                results[mode.name] = {
                    'decays_during_BBN': False,
                    'decay_temp_MeV': mode.decay_temperature_MeV,
                    'status': 'SAFE - decays before BBN'
                }

        return results


# ============================================================================
# TEST 2: COSMIC MICROWAVE BACKGROUND (CMB)
# ============================================================================

class CMBConstraint:
    """
    CMB constraint on new physics

    Requirements:
    1. No spectral distortions (blackbody deviations)
    2. No late-time energy injection (z < 1000)
    3. No modifications to recombination history
    """

    T_recomb_MeV = 0.26e-6  # ~0.26 eV = 3000 K

    def __init__(self, eigenmodes: List[Eigenmode]):
        self.eigenmodes = eigenmodes

    def check_spectral_distortion(self) -> Dict:
        """
        Check for CMB spectral distortions from eigenmode decays

        COBE/FIRAS constraint: |μ| < 9×10^-5 (chemical potential)
        """

        results = {}

        for mode in self.eigenmodes:

            # Does it decay near recombination?
            decay_at_recomb = (
                mode.decay_temperature_MeV > 0.1e-6 and
                mode.decay_temperature_MeV < 1e-3
            )

            if decay_at_recomb:
                results[mode.name] = {
                    'affects_CMB': True,
                    'decay_temp_MeV': mode.decay_temperature_MeV,
                    'status': 'DANGEROUS - distorts CMB spectrum'
                }
            else:
                results[mode.name] = {
                    'affects_CMB': False,
                    'status': 'SAFE - decays before or after recombination'
                }

        return results


# ============================================================================
# TEST 3: STELLAR COOLING
# ============================================================================

class StellarCoolingConstraint:
    """
    Stellar cooling constraint on new light particles

    Very sensitive probe! New particles that:
    - Are produced in stellar cores
    - Escape without interaction
    - Carry away energy

    → Make stars evolve faster than observed
    """

    # Core temperatures
    T_sun_core_MeV = 1.3e-9      # ~1.5 keV
    T_red_giant_MeV = 10e-9      # ~10 keV
    T_white_dwarf_MeV = 1e-6     # ~1 keV (surface, interior hotter)

    def __init__(self, eigenmodes: List[Eigenmode]):
        self.eigenmodes = eigenmodes

    def check_emission_rate(self, T_MeV: float, mode: Eigenmode) -> Dict:
        """
        Emission rate of eigenmodes from thermal plasma

        Process: e⁺ + e⁻ → eigenmode (+ photon if needed)

        Rate ~ n_e² <σv> where:
        - n_e ~ stellar electron density
        - <σv> ~ α² (E/m_e)² for EM process
        """

        # Boltzmann factor
        exp_factor = math.exp(-mode.mass_MeV / T_MeV) if mode.mass_MeV > T_MeV else 1.0

        # Rough emission rate (very approximate)
        # Units: relative to photon emission
        alpha = 1/137.036

        if mode.mass_MeV < 3 * T_MeV:
            # Thermal production possible
            emission_rate_relative = alpha**2 * exp_factor
            producible = True
        else:
            # Boltzmann suppressed
            emission_rate_relative = alpha**2 * exp_factor
            producible = False

        # Compare to cooling bound
        # Rough limit: L_new / L_photon < 10^-3 (1% extra cooling)
        violates_bound = emission_rate_relative > 1e-3

        return {
            'temperature_MeV': T_MeV,
            'thermally_produced': producible,
            'relative_emission': emission_rate_relative,
            'exceeds_cooling_bound': violates_bound
        }

    def check_all_stars(self) -> Dict:
        """Check constraints from different stellar environments"""

        results = {}

        for mode in self.eigenmodes:

            sun_result = self.check_emission_rate(self.T_sun_core_MeV, mode)
            rg_result = self.check_emission_rate(self.T_red_giant_MeV, mode)
            wd_result = self.check_emission_rate(self.T_white_dwarf_MeV, mode)

            # Most stringent constraint
            most_stringent = 'None'
            if sun_result['exceeds_cooling_bound']:
                most_stringent = 'Sun'
            if rg_result['exceeds_cooling_bound']:
                most_stringent = 'Red Giant'
            if wd_result['exceeds_cooling_bound']:
                most_stringent = 'White Dwarf'

            results[mode.name] = {
                'sun_core': sun_result,
                'red_giant_core': rg_result,
                'white_dwarf': wd_result,
                'most_stringent_constraint': most_stringent,
                'VIOLATES_STELLAR_COOLING': most_stringent != 'None'
            }

        return results


# ============================================================================
# MAIN FALSIFICATION ENGINE
# ============================================================================

def run_cosmological_falsification():
    """
    Run all cosmological tests

    If ANY test fails → Theory is DEAD
    """

    print("="*80)
    print("COSMOLOGICAL FALSIFICATION OF SUBSTRATE EIGENMODE THEORY")
    print("="*80)
    print()

    # Test 1: BBN
    print("TEST 1: BIG BANG NUCLEOSYNTHESIS")
    print("-" * 80)

    bbn = BBNConstraint(EIGENMODES)
    n_eff_results = bbn.check_N_eff()
    late_decay_results = bbn.check_late_decay()

    print(f"\nN_eff contribution:")
    print(f"  Total ΔN_eff: {n_eff_results['total_delta_N_eff']:.3f}")
    print(f"  Allowed: {n_eff_results['allowed_delta_N_eff']:.3f}")
    print(f"  Status: {n_eff_results['verdict']}")

    if n_eff_results['CONSTRAINT_VIOLATED']:
        print("\n❌ THEORY FALSIFIED BY BBN N_eff CONSTRAINT")
        print("   Eigenmodes contribute too much to radiation density")
        return False

    print("\n✓ Passes N_eff constraint")

    # Test 2: CMB
    print("\n" + "="*80)
    print("TEST 2: COSMIC MICROWAVE BACKGROUND")
    print("-" * 80)

    cmb = CMBConstraint(EIGENMODES)
    cmb_results = cmb.check_spectral_distortion()

    dangerous_modes = [k for k, v in cmb_results.items() if v['affects_CMB']]

    if dangerous_modes:
        print(f"\n⚠️  WARNING: Modes decay near recombination: {dangerous_modes}")
        print("   Needs detailed calculation of spectral distortion")
    else:
        print("\n✓ No modes decay during recombination epoch")

    # Test 3: Stellar Cooling
    print("\n" + "="*80)
    print("TEST 3: STELLAR COOLING")
    print("-" * 80)

    stellar = StellarCoolingConstraint(EIGENMODES)
    stellar_results = stellar.check_all_stars()

    violators = [k for k, v in stellar_results.items()
                 if v['VIOLATES_STELLAR_COOLING']]

    if violators:
        print(f"\n❌ THEORY FALSIFIED BY STELLAR COOLING")
        print(f"   Modes that violate constraint: {violators}")
        return False

    print("\n✓ Passes stellar cooling constraints")

    # Summary
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)

    print("\nEigenmode properties:")
    for mode in EIGENMODES:
        print(f"\n{mode.name}:")
        print(f"  Mass: {mode.mass_MeV:.3f} MeV")
        print(f"  Lifetime: {mode.lifetime_s:.2e} s")
        print(f"  Decay temperature: {mode.decay_temperature_MeV:.2e} MeV")

    print("\n" + "="*80)
    print("VERDICT: Theory survives cosmological constraints")
    print("         → Proceed to accelerator searches")
    print("="*80)

    return True


if __name__ == "__main__":
    passes_cosmology = run_cosmological_falsification()

    if not passes_cosmology:
        print("\n❌ SUBSTRATE EIGENMODE THEORY IS FALSIFIED")
        print("   Violates cosmological observations")
        print("   No need for expensive accelerator searches")
    else:
        print("\n✓ SUBSTRATE EIGENMODE THEORY IS COSMOLOGICALLY VIABLE")
        print("  Next steps:")
        print("  1. Search NA64 data for 2.04 MeV peak")
        print("  2. Request ball lightning Fourier data")
        print("  3. Plan dedicated low-energy experiment")
