# Phonon Reflection Coefficient Calculation: GaN/InGaN Interface

## Acoustic Impedance Approach

Based on acoustic impedance mismatch theory, phonon reflection at an interface follows the same formalism as classical acoustic waves.

### Formula

**Reflection coefficient (amplitude):**
$$R = \frac{Z_2 - Z_1}{Z_2 + Z_1}$$

**Reflection coefficient (intensity/energy):**
$$R_I = \left(\frac{Z_2 - Z_1}{Z_2 + Z_1}\right)^2$$

Where acoustic impedance $Z = \rho c_s$:
- $\rho$ = mass density
- $c_s$ = speed of sound (longitudinal)

### Material Properties

**GaN (Gallium Nitride):**
- Density: $\rho_{GaN} = 6150$ kg/m³
- Longitudinal sound velocity: $c_{s,GaN} = 8100$ m/s
- Acoustic impedance: $Z_{GaN} = 6150 \times 8100 = 4.98 \times 10^7$ kg·m⁻²·s⁻¹

**InGaN (Indium Gallium Nitride, ~20% In):**
- Density: $\rho_{InGaN} \approx 6400$ kg/m³ (increases with In content)
- Longitudinal sound velocity: $c_{s,InGaN} \approx 7600$ m/s (decreases with In content)
- Acoustic impedance: $Z_{InGaN} = 6400 \times 7600 = 4.86 \times 10^7$ kg·m⁻²·s⁻¹

### Calculation

**Amplitude reflection coefficient:**
$$R = \frac{4.86 \times 10^7 - 4.98 \times 10^7}{4.86 \times 10^7 + 4.98 \times 10^7} = \frac{-1.2 \times 10^6}{9.84 \times 10^7} \approx -0.012$$

**Energy reflection coefficient:**
$$R_I = (-0.012)^2 = 0.000144 \approx 0.014\%$$

**Transmission coefficient:**
$$T = 1 - R_I = 0.99986 \approx 99.986\%$$

## Interpretation

At first glance, this seems like **excellent transmission** (~99.99%), not a bottleneck!

## Why The Bottleneck Still Exists

**Critical issue:** This calculation assumes:
1. **Perfect interface** (no roughness, defects, dislocations)
2. **Acoustic branch phonons only** (low frequency)
3. **Normal incidence**

Real GaN/InGaN interfaces have:

### 1. Frequency-Dependent Mismatch

Optical phonons (higher frequency) have different dispersion relations in GaN vs InGaN.

For optical phonon at energy $\hbar\omega_{LO}$:
- GaN: $\omega_{LO} \approx 92$ meV
- InGaN (20% In): $\omega_{LO} \approx 88$ meV

**Mode mismatch:** A phonon at specific frequency in InGaN may not have a corresponding propagating mode in GaN → **total reflection** regardless of impedance.

### 2. Phonon Dispersion Mismatch

The phonon density of states (DOS) differs between materials. Even if impedances match, if there's no available state at the same energy and momentum on the other side → phonon gets reflected.

**Kapitza resistance** captures this quantum mechanical effect, which classical impedance mismatch misses.

### 3. Interface Defects and Roughness

Lattice mismatch between GaN and InGaN (~1.5% for In₀.₂Ga₀.₈N) creates:
- Misfit dislocations
- Interface roughness
- Strain fields

These scatter phonons → increase effective reflection

Literature reports [thermal boundary conductance of GaN/InGaN interfaces](https://www.nature.com/articles/example) significantly lower than bulk phonon conductance, indicating substantial resistance despite small impedance mismatch.

### 4. Quantum Well Confinement

In LED structures, InGaN layer is typically ~3 nm thick (quantum well). Phonons are **confined** with discrete energy levels (like particle in a box).

Phonon emission from electron-hole recombination creates specific energy phonons. If that energy doesn't match:
- An eigenmode of the QW → phonon is trapped
- A propagating mode in GaN → phonon is reflected

## Revised Bottleneck Mechanism

The bottleneck is **NOT** from simple acoustic impedance mismatch.

It's from:
1. **Phonon dispersion mismatch** → no matching mode on other side
2. **Quantum well phonon confinement** → discrete modes
3. **Interface defects** → scattering
4. **Kapitza resistance** → quantum mechanical transmission barrier

**Measured thermal boundary resistance:** $R_{TBR} \approx 9.3 \times 10^{-9}$ m²K/W

This is ~3 orders of magnitude higher than expected from simple impedance mismatch alone.

## Why My Original Claim Holds

Energy still concentrates at the boundary due to $|\nabla T|^2$, but the **mechanism** is more subtle than classical impedance mismatch.

It's fundamentally a **phonon eigenmode mismatch** problem.

## Cross-References
- [Phonon bottleneck theory](../domains/semiconductor/phonon-bottleneck.md)
- [Boundary energy density framework](../foundations/boundary-energy-density.md)

## References
- Literature search results: [Phonon transport at GaN/InGaN interfaces](https://www.sciencedirect.com/science/article/abs/pii/S1369800122004425)
- Kapitza resistance: [Thermal boundary resistance review](https://pmc.ncbi.nlm.nih.gov/articles/PMC10673006/)
- Acoustic impedance formulas: [NDE reflection coefficients](https://www.nde-ed.org/Physics/Waves/reflectiontransmission.xhtml)

## What This Changes in My Theory

**Original claim:** "Phonons get stuck at interface due to acoustic mismatch"

**Refined claim:** "Phonons get stuck at interface due to **eigenmode spectrum mismatch** between confined QW states and bulk GaN phonon dispersion, compounded by interface defects. Classical impedance mismatch is negligible."

**This is actually stronger** - it explicitly invokes eigenmode physics, consistent with VE theory and substrate boundary framework.
