#!/usr/bin/env python3
"""
Hybrid Steel: Complete Characterization Simulation
==================================================

Simulates what different material science techniques should observe
in hybrid wootz-Damascus steel.

Tests:
1. TEM (Transmission Electron Microscopy) - nanostructure imaging
2. Raman Spectroscopy - CNT signature
3. XRD (X-Ray Diffraction) - Fe₃C nanowire detection
4. Mechanical Testing - strength, toughness
5. SEM/EDS - composition mapping
6. Thermal Analysis - phase transitions

Predictions for:
- Pure wootz (baseline)
- Pure Damascus (baseline)
- Hybrid (novel)
- Failed hybrid (edge cases)

Author: Substrate Theory Testing Group
Date: 2026-01-02
Status: Complete simulation suite
"""

import math
from dataclasses import dataclass
from typing import Dict, List, Tuple
from enum import Enum

# ============================================================================
# MATERIAL TYPES
# ============================================================================

class SteelType(Enum):
    PURE_WOOTZ = "wootz"
    PURE_DAMASCUS = "damascus"
    HYBRID = "hybrid"
    FAILED_HYBRID_NO_V = "hybrid_no_vanadium"
    FAILED_HYBRID_FAST_COOL = "hybrid_fast_cool"
    FAILED_HYBRID_FEW_CYCLES = "hybrid_few_cycles"

# ============================================================================
# CHARACTERIZATION TECHNIQUES
# ============================================================================

@dataclass
class TEMResults:
    """Transmission Electron Microscopy results"""

    cnts_observed: bool
    cnt_diameter_nm: Tuple[float, float]  # (min, max)
    cnt_location: str
    cnt_density_per_um2: float

    nanowires_observed: bool
    nanowire_diameter_nm: Tuple[float, float]
    nanowire_location: str
    nanowire_spacing_um: float

    def summary(self) -> str:
        lines = ["TEM IMAGING:"]

        if self.cnts_observed:
            lines.append(f"  ✓ CNTs detected")
            lines.append(f"    Diameter: {self.cnt_diameter_nm[0]:.1f}-{self.cnt_diameter_nm[1]:.1f} nm")
            lines.append(f"    Location: {self.cnt_location}")
            lines.append(f"    Density: {self.cnt_density_per_um2:.1f} per μm²")
        else:
            lines.append(f"  ✗ No CNTs detected")

        if self.nanowires_observed:
            lines.append(f"  ✓ Fe₃C nanowires detected")
            lines.append(f"    Diameter: {self.nanowire_diameter_nm[0]:.1f}-{self.nanowire_diameter_nm[1]:.1f} nm")
            lines.append(f"    Location: {self.nanowire_location}")
            lines.append(f"    Spacing: {self.nanowire_spacing_um:.1f} μm")
        else:
            lines.append(f"  ✗ No nanowires detected")

        return "\n".join(lines)


@dataclass
class RamanResults:
    """Raman spectroscopy for CNT detection"""

    G_peak_cm1: float  # ~1580 cm⁻¹ (graphitic C-C stretch)
    D_peak_cm1: float  # ~1350 cm⁻¹ (defects)
    G_to_D_ratio: float  # Quality indicator
    RBM_peaks: List[float]  # Radial breathing modes (CNT specific)

    cnts_present: bool
    cnt_quality: str  # "high", "medium", "low", "none"

    def summary(self) -> str:
        lines = ["RAMAN SPECTROSCOPY:"]

        if self.cnts_present:
            lines.append(f"  ✓ CNT signature detected")
            lines.append(f"    G peak: {self.G_peak_cm1:.1f} cm⁻¹")
            lines.append(f"    D peak: {self.D_peak_cm1:.1f} cm⁻¹")
            lines.append(f"    G/D ratio: {self.G_to_D_ratio:.2f} (quality: {self.cnt_quality})")
            if self.RBM_peaks:
                lines.append(f"    RBM peaks: {', '.join(f'{p:.0f}' for p in self.RBM_peaks)} cm⁻¹")
        else:
            lines.append(f"  ✗ No CNT signature")
            lines.append(f"    (No G or D peaks characteristic of CNTs)")

        return "\n".join(lines)


@dataclass
class XRDResults:
    """X-Ray Diffraction for Fe₃C detection"""

    cementite_peaks: List[float]  # 2θ angles for Fe₃C
    peak_intensity: float  # Relative intensity
    nanowire_present: bool
    grain_size_nm: float  # From Scherrer equation

    def summary(self) -> str:
        lines = ["X-RAY DIFFRACTION:"]

        if self.nanowire_present:
            lines.append(f"  ✓ Fe₃C (cementite) detected")
            lines.append(f"    Characteristic 2θ peaks: {', '.join(f'{p:.1f}°' for p in self.cementite_peaks)}")
            lines.append(f"    Peak intensity: {self.peak_intensity:.2f} (relative)")
            lines.append(f"    Grain size: {self.grain_size_nm:.1f} nm (Scherrer)")
        else:
            lines.append(f"  ✗ No Fe₃C nanowires detected")
            lines.append(f"    (Cementite peaks absent or weak)")

        return "\n".join(lines)


@dataclass
class MechanicalResults:
    """Mechanical testing results"""

    hardness_HRC: float  # Rockwell C hardness
    tensile_strength_MPa: float
    yield_strength_MPa: float
    toughness_J: float  # Impact energy (Charpy)
    elongation_percent: float

    def summary(self) -> str:
        lines = ["MECHANICAL PROPERTIES:"]
        lines.append(f"  Hardness: {self.hardness_HRC:.1f} HRC")
        lines.append(f"  Tensile strength: {self.tensile_strength_MPa:.0f} MPa")
        lines.append(f"  Yield strength: {self.yield_strength_MPa:.0f} MPa")
        lines.append(f"  Toughness (Charpy): {self.toughness_J:.1f} J")
        lines.append(f"  Elongation: {self.elongation_percent:.1f}%")

        return "\n".join(lines)


@dataclass
class SEMEDSResults:
    """Scanning Electron Microscopy + Energy Dispersive Spectroscopy"""

    vanadium_ppm: float
    molybdenum_ppm: float
    carbon_percent: float
    v_segregation_observed: bool
    layer_boundaries_visible: bool

    def summary(self) -> str:
        lines = ["SEM/EDS COMPOSITION:"]
        lines.append(f"  Carbon: {self.carbon_percent:.2f}%")
        lines.append(f"  Vanadium: {self.vanadium_ppm:.0f} ppm")
        lines.append(f"  Molybdenum: {self.molybdenum_ppm:.0f} ppm")

        if self.v_segregation_observed:
            lines.append(f"  ✓ V/Mo segregation bands visible")
        else:
            lines.append(f"  ✗ No segregation bands")

        if self.layer_boundaries_visible:
            lines.append(f"  ✓ Layer boundaries from welding visible")
        else:
            lines.append(f"  ✗ Layer boundaries homogenized")

        return "\n".join(lines)


# ============================================================================
# SIMULATION ENGINE
# ============================================================================

class MaterialSimulator:
    """Simulates characterization results for different steel types"""

    @staticmethod
    def simulate_tem(steel_type: SteelType, v_ppm: float, cycles: int,
                     cool_hours: float) -> TEMResults:
        """Simulate TEM imaging results"""

        # CNT formation logic
        cnts_form = cycles >= 10  # Need sufficient cycling
        cnt_density = min(50, cycles * 2) if cnts_form else 0

        # Nanowire formation logic
        nanowires_form = (v_ppm > 100) and (cool_hours > 24)

        if steel_type == SteelType.PURE_WOOTZ:
            return TEMResults(
                cnts_observed=False,
                cnt_diameter_nm=(0, 0),
                cnt_location="N/A",
                cnt_density_per_um2=0,
                nanowires_observed=True,
                nanowire_diameter_nm=(10, 100),
                nanowire_location="Dendrite bands",
                nanowire_spacing_um=50
            )

        elif steel_type == SteelType.PURE_DAMASCUS:
            return TEMResults(
                cnts_observed=True,
                cnt_diameter_nm=(10, 50),
                cnt_location="Layer interfaces",
                cnt_density_per_um2=30,
                nanowires_observed=False,
                nanowire_diameter_nm=(0, 0),
                nanowire_location="N/A",
                nanowire_spacing_um=0
            )

        elif steel_type == SteelType.HYBRID:
            return TEMResults(
                cnts_observed=cnts_form,
                cnt_diameter_nm=(10, 50) if cnts_form else (0, 0),
                cnt_location="Layer interfaces" if cnts_form else "N/A",
                cnt_density_per_um2=cnt_density,
                nanowires_observed=nanowires_form,
                nanowire_diameter_nm=(10, 100) if nanowires_form else (0, 0),
                nanowire_location="Dendrite bands" if nanowires_form else "N/A",
                nanowire_spacing_um=50 if nanowires_form else 0
            )

        elif steel_type == SteelType.FAILED_HYBRID_NO_V:
            return TEMResults(
                cnts_observed=True,
                cnt_diameter_nm=(10, 50),
                cnt_location="Layer interfaces",
                cnt_density_per_um2=30,
                nanowires_observed=False,  # No V → no nanowires
                nanowire_diameter_nm=(0, 0),
                nanowire_location="N/A",
                nanowire_spacing_um=0
            )

        elif steel_type == SteelType.FAILED_HYBRID_FAST_COOL:
            return TEMResults(
                cnts_observed=True,
                cnt_diameter_nm=(10, 50),
                cnt_location="Layer interfaces",
                cnt_density_per_um2=30,
                nanowires_observed=False,  # Fast cool → no segregation
                nanowire_diameter_nm=(0, 0),
                nanowire_location="N/A",
                nanowire_spacing_um=0
            )

        elif steel_type == SteelType.FAILED_HYBRID_FEW_CYCLES:
            return TEMResults(
                cnts_observed=False,  # Few cycles → no CNTs
                cnt_diameter_nm=(0, 0),
                cnt_location="N/A",
                cnt_density_per_um2=0,
                nanowires_observed=True,
                nanowire_diameter_nm=(10, 100),
                nanowire_location="Dendrite bands",
                nanowire_spacing_um=50
            )

        return TEMResults(False, (0,0), "N/A", 0, False, (0,0), "N/A", 0)

    @staticmethod
    def simulate_raman(steel_type: SteelType, cycles: int) -> RamanResults:
        """Simulate Raman spectroscopy"""

        cnts_present = cycles >= 10

        if cnts_present:
            # CNT-characteristic peaks
            g_peak = 1582  # G peak (graphitic)
            d_peak = 1350  # D peak (defects)
            g_d_ratio = 1.5 + (cycles / 30)  # Better with more cycles
            rbm = [180, 220, 260]  # Radial breathing modes (CNT-specific)

            if g_d_ratio > 2.0:
                quality = "high"
            elif g_d_ratio > 1.2:
                quality = "medium"
            else:
                quality = "low"

            return RamanResults(g_peak, d_peak, g_d_ratio, rbm, True, quality)
        else:
            return RamanResults(0, 0, 0, [], False, "none")

    @staticmethod
    def simulate_xrd(steel_type: SteelType, v_ppm: float,
                     cool_hours: float) -> XRDResults:
        """Simulate X-Ray Diffraction"""

        nanowires_present = (v_ppm > 100) and (cool_hours > 24)

        if nanowires_present:
            # Fe₃C characteristic 2θ peaks
            peaks = [37.7, 39.8, 42.9, 43.7, 44.6]  # Cementite peaks
            intensity = min(1.0, (v_ppm / 300) * (cool_hours / 72))
            grain_size = 50  # nm (from nanowire diameter)

            return XRDResults(peaks, intensity, True, grain_size)
        else:
            return XRDResults([], 0, False, 0)

    @staticmethod
    def simulate_mechanical(steel_type: SteelType, cnts: bool,
                           nanowires: bool) -> MechanicalResults:
        """Simulate mechanical properties"""

        # Baseline steel
        base_hardness = 50  # HRC
        base_tensile = 1200  # MPa
        base_yield = 900  # MPa
        base_toughness = 20  # J
        base_elongation = 8  # %

        # CNT contribution (toughness, elongation)
        if cnts:
            toughness_mult = 1.4
            elongation_mult = 1.3
        else:
            toughness_mult = 1.0
            elongation_mult = 1.0

        # Nanowire contribution (hardness, strength)
        if nanowires:
            hardness_add = 8
            strength_mult = 1.3
        else:
            hardness_add = 0
            strength_mult = 1.0

        # Synergy bonus if both
        if cnts and nanowires:
            synergy = 1.1
        else:
            synergy = 1.0

        return MechanicalResults(
            hardness_HRC=base_hardness + hardness_add,
            tensile_strength_MPa=base_tensile * strength_mult * synergy,
            yield_strength_MPa=base_yield * strength_mult * synergy,
            toughness_J=base_toughness * toughness_mult * synergy,
            elongation_percent=base_elongation * elongation_mult
        )

    @staticmethod
    def simulate_sem_eds(steel_type: SteelType, v_ppm: float, mo_ppm: float,
                        cool_hours: float) -> SEMEDSResults:
        """Simulate SEM/EDS composition mapping"""

        v_segregation = (v_ppm > 100) and (cool_hours > 24)
        layers_visible = steel_type != SteelType.PURE_WOOTZ

        return SEMEDSResults(
            vanadium_ppm=v_ppm,
            molybdenum_ppm=mo_ppm,
            carbon_percent=1.5,
            v_segregation_observed=v_segregation,
            layer_boundaries_visible=layers_visible
        )


# ============================================================================
# COMPREHENSIVE TEST SUITE
# ============================================================================

def run_full_characterization(steel_type: SteelType, v_ppm: float = 300,
                              mo_ppm: float = 100, cycles: int = 15,
                              cool_hours: float = 72):
    """Run complete characterization suite"""

    sim = MaterialSimulator()

    # All techniques
    tem = sim.simulate_tem(steel_type, v_ppm, cycles, cool_hours)
    raman = sim.simulate_raman(steel_type, cycles)
    xrd = sim.simulate_xrd(steel_type, v_ppm, cool_hours)
    mech = sim.simulate_mechanical(steel_type, tem.cnts_observed, tem.nanowires_observed)
    sem = sim.simulate_sem_eds(steel_type, v_ppm, mo_ppm, cool_hours)

    return {
        'tem': tem,
        'raman': raman,
        'xrd': xrd,
        'mechanical': mech,
        'sem_eds': sem
    }


def compare_all_variants():
    """Compare all steel variants"""

    print("="*80)
    print("HYBRID STEEL: COMPLETE CHARACTERIZATION SIMULATION")
    print("="*80)
    print()

    # Test all variants
    variants = [
        ("Pure Wootz (Baseline)", SteelType.PURE_WOOTZ, 300, 100, 0, 72),
        ("Pure Damascus (Baseline)", SteelType.PURE_DAMASCUS, 0, 0, 15, 1),
        ("Hybrid (Predicted Success)", SteelType.HYBRID, 300, 100, 15, 72),
        ("Failed: No Vanadium", SteelType.FAILED_HYBRID_NO_V, 0, 0, 15, 72),
        ("Failed: Fast Cooling", SteelType.FAILED_HYBRID_FAST_COOL, 300, 100, 15, 1),
        ("Failed: Few Cycles", SteelType.FAILED_HYBRID_FEW_CYCLES, 300, 100, 3, 72),
    ]

    for name, steel_type, v, mo, cyc, cool in variants:
        print("="*80)
        print(f"{name}")
        print("="*80)
        print(f"Parameters: V={v} ppm, Mo={mo} ppm, Cycles={cyc}, Cool={cool}h")
        print()

        results = run_full_characterization(steel_type, v, mo, cyc, cool)

        print(results['tem'].summary())
        print()
        print(results['raman'].summary())
        print()
        print(results['xrd'].summary())
        print()
        print(results['mechanical'].summary())
        print()
        print(results['sem_eds'].summary())
        print()

    # Summary comparison
    print("="*80)
    print("COMPARISON SUMMARY")
    print("="*80)
    print()

    print("Expected nanostructures:")
    print(f"{'Variant':<30} {'CNTs':<10} {'Nanowires':<15}")
    print("-" * 80)

    for name, steel_type, v, mo, cyc, cool in variants:
        results = run_full_characterization(steel_type, v, mo, cyc, cool)
        cnts = "✓" if results['tem'].cnts_observed else "✗"
        nanowires = "✓" if results['tem'].nanowires_observed else "✗"
        print(f"{name:<30} {cnts:<10} {nanowires:<15}")

    print()
    print("="*80)
    print("VALIDATION PROTOCOL")
    print("="*80)
    print()
    print("To validate hybrid prediction experimentally:")
    print()
    print("1. MATERIAL PREPARATION")
    print("   - Source: V/Mo-doped high-carbon steel (300 ppm V, 100 ppm Mo, 1.5% C)")
    print("   - Process: 15 pattern-welding cycles, 72h slow final cooling")
    print()
    print("2. TEM ANALYSIS (Critical)")
    print("   - Sample at BOTH layer interfaces AND dendrite bands")
    print("   - Expected: CNTs at interfaces (10-50 nm) + nanowires in bands (10-100 nm)")
    print("   - Spatial separation: 10 μm vs 50 μm spacing")
    print()
    print("3. RAMAN SPECTROSCOPY")
    print("   - Look for G peak (~1582 cm⁻¹) and D peak (~1350 cm⁻¹)")
    print("   - RBM peaks (180-260 cm⁻¹) confirm CNTs")
    print("   - G/D ratio > 1.5 indicates quality CNTs")
    print()
    print("4. X-RAY DIFFRACTION")
    print("   - Fe₃C peaks at 2θ: 37.7°, 39.8°, 42.9°, 43.7°, 44.6°")
    print("   - Strong peaks confirm nanowire presence")
    print("   - Scherrer analysis gives grain size ~50 nm")
    print()
    print("5. MECHANICAL TESTING")
    print("   - Hardness: Expect ~58 HRC (vs 50 baseline)")
    print("   - Tensile strength: ~1700 MPa (vs 1200 baseline)")
    print("   - Toughness: ~30 J (vs 20 baseline)")
    print("   - Hybrid should exceed BOTH wootz and Damascus individually")
    print()
    print("6. SEM/EDS MAPPING")
    print("   - V/Mo segregation bands (dendrites)")
    print("   - Layer boundaries visible (welding)")
    print("   - Confirm both features present")
    print()


if __name__ == "__main__":
    compare_all_variants()
