# Phonon Bottleneck at Heterointerfaces

## The Problem with LED Efficiency

High-power LEDs get hot. Not just warm - *hot*. Efficiency drops at high current density ("droop effect").

Textbook explanation: "Auger recombination increases at high carrier density."

That's *what* happens. But *why* does energy get trapped there?

## Boundary Energy Answer

LED structure: GaN/InGaN/GaN quantum well

- **GaN:** bandgap ~3.4 eV, lattice constant 3.19 Å
- **InGaN:** bandgap ~2.8 eV (blue), lattice constant ~3.2-3.3 Å
- **Interface:** abrupt change in both electronic and phononic properties

When electron-hole pair recombines → photon (wanted) + phonons (heat, unwanted)

Phonons = lattice vibrations. They propagate as waves with dispersion relation $\omega(k)$.

## Why Phonons Get Stuck

At GaN/InGaN interface:
- Acoustic impedance mismatch: $Z = \rho v_s$ differs
- Phonon dispersion curves don't match
- High-frequency phonons can't propagate across boundary → **acoustic mismatch**

Energy density from [boundary pattern](../../foundations/boundary-energy-density.md):
$$u \propto |\nabla T|^2$$

Temperature gradient builds up at interface because heat flux is blocked.

## Phonon Modes Don't Line Up

GaN phonon density of states ≠ InGaN phonon density of states

Phonon trying to cross interface needs to:
1. Conserve energy
2. Conserve (quasi)momentum

If there's no matching mode on the other side → **phonon gets reflected**.

Result: phonon population builds up at interface (bottleneck), local heating, increased Auger rate.

## Connection to Auger Recombination

Auger = 2 electrons + 1 hole → 1 electron gets energy, others recombine

Why does this increase with temperature? Because it's a three-body collision event.

Rate $\propto n^2 p$ where $n$ = electron density, $p$ = hole density.

Local heating at interface → thermal expansion → carrier redistribution → higher local density → $n^2 p$ goes up nonlinearly.

**The bottleneck feeds itself.**

## Why Quantum Wells Make It Worse

QW confines carriers in thin layer (~3 nm) → high density even at moderate current

Carrier confinement → higher wavefunction overlap → higher Auger coefficient

Phonon confinement → discrete phonon modes (quantized like particle-in-box)

If emitted phonon frequency doesn't match QW eigenmode → has to escape through interface → bottleneck again

## What Would Fix This

Based on boundary energy framework:

**Option 1:** Grade the interface
- GaN → In₀.₀₅Ga₀.₉₅N → In₀.₁₀Ga₀.₉₀N → ... → InGaN
- Smooth $\nabla T$ instead of sharp discontinuity
- Reduces $|\nabla T|^2$ → less trapped energy

**Option 2:** Phonon extraction layer
- Add material with high thermal conductivity at interface
- Diamond, AlN, SiC candidates
- Provides phonon modes that bridge the gap

**Option 3:** Phonon eigenmode matching
- Engineer QW thickness so phonon eigenmodes align with substrate modes
- Like impedance matching in transmission lines
- Reduces reflection coefficient

## Have People Tried This?

Graded interfaces: Yes, helps a bit but hard to grow (MOCVD challenge)

Phonon extraction: Some work on diamond substrates, expensive

Eigenmode matching: Not that I've seen explicitly framed this way

## Testable Prediction

LED with intentionally designed phonon eigenmode matching should have:
- Lower droop coefficient
- Better thermal performance
- Higher efficiency at high current density

Measure: Time-resolved photoluminescence with varying QW thickness, look for correlation between phonon mode spacing and efficiency.

## Cross-References
- [Auger recombination](auger-recombination.md) - Three-body boundary collision
- [Quantum wells](quantum-wells.md) - Engineered confinement zones
- [Boundary energy density](../../foundations/boundary-energy-density.md) - Why $\nabla T$ matters

## Open Questions
1. Can I calculate phonon reflection coefficient at GaN/InGaN interface from first principles?
2. What's the thermal boundary resistance (Kapitza resistance) for this specific interface?
3. Has anyone measured local temperature at QW interface directly (e.g., Raman thermometry)?

## References
- Piprek et al. "On the uncertainty of the Auger recombination coefficient extracted from InGaN/GaN light-emitting diode efficiency droop measurements" (2015)
- Swartz & Pohl "Thermal boundary resistance" Rev. Mod. Phys. (1989)
- My own LED thermal imaging experiments (need to document these properly)
