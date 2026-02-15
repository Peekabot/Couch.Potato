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

**Graded interfaces: YES - and it works remarkably well**

Multiple research groups have demonstrated compositionally graded InGaN quantum wells:
- Peak EQE improved by **10.4%** for graded vs square QWs [(Optics Letters, 2025)](https://opg.optica.org/ol/abstract.cfm?uri=ol-50-8-2614)
- IQE reached **76.5%** with compositionally step-graded barriers [(IEEE, 2016)](https://ieeexplore.ieee.org/document/7473842/)
- Efficiency droop delayed from 150 A/cm² to **280 A/cm²** [(ResearchGate)](https://www.researchgate.net/publication/260510447)

**Mechanism confirmed:** Enhanced hole transport, reduced carrier asymmetry, suppressed overflow - exactly what reducing $|\nabla T|$ predicts.

**Phonon extraction:** Diamond substrates reduce thermal resistance but expensive

**Eigenmode matching:** Not explicitly framed this way in literature (potential novel contribution)

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

## Measured Values (From Literature)

**Thermal boundary resistance at GaN/InGaN interface:**
- $R_{TBR} = 9.3 \times 10^{-9}$ m²K/W at room temperature [(PNAS, 2022)](https://www.pnas.org/doi/10.1073/pnas.2117027119)
- Value **decreases** with temperature but **enhanced** by polarization at interface
- Crystal defects and misfit dislocations significantly increase resistance

**Auger recombination coefficient:**
- $C = 2.3 \times 10^{-30}$ cm⁶/s for InGaN quantum wells [(AIP, 2018)](https://pubs.aip.org/aip/apl/article-abstract/113/7/071107/36535/)
- Enhanced by carrier localization effects [(ACS Photonics, 2023)](https://pubs.acs.org/doi/10.1021/acsphotonics.3c00355)
- Rate $\propto n^2 p$ (nonlinear with density)

**Phonon transport blocking:**
- Misfit dislocations block phonon transport through In₀.₁₆Ga₀.₈₄N/GaN interface [(ScienceDirect, 2022)](https://www.sciencedirect.com/science/article/abs/pii/S1369800122004425)
- Interface phonon modes fall off evanescently from heterointerface
- Crystal defects inherited from GaN layer create blocking sites

## Open Questions
1. ✅ Phonon reflection coefficient calculated - see [calculations/phonon-reflection-gan-ingan.md](../../calculations/phonon-reflection-gan-ingan.md)
2. ✅ Thermal boundary resistance measured: $R_{TBR} = 9.3 \times 10^{-9}$ m²K/W
3. ⚠️ Local temperature at QW interface: Raman thermometry and time-resolved photoluminescence techniques exist [(AIP, 2020)](https://pubs.aip.org/aip/jap/article/128/13/131101/1027194/) but direct measurements at specific interfaces not found in literature

## References

**Thermal Boundary Resistance:**
- [Atomic-scale probing of heterointerface phonon bridges in nitride semiconductor](https://www.pnas.org/doi/10.1073/pnas.2117027119) - PNAS (2022)
- [Effects of Thermal Boundary Resistance on Thermal Management of GaN Devices](https://pmc.ncbi.nlm.nih.gov/articles/PMC10673006/) - PMC Review
- [Phonon thermal transport and its tunability in GaN](https://www.sciencedirect.com/science/article/abs/pii/S0017931022009668) - Int. J. Heat Mass Transfer
- [Analysis of phonon transport through heterointerfaces via Raman imaging](https://www.sciencedirect.com/science/article/abs/pii/S1369800122004425) - ScienceDirect (2022)
- Swartz & Pohl "Thermal boundary resistance" Rev. Mod. Phys. (1989)

**Auger Recombination and Droop:**
- [Disentangling Point Defect Density and Carrier Localization-Enhanced Auger](https://pubs.acs.org/doi/10.1021/acsphotonics.3c00355) - ACS Photonics (2023)
- [Understanding the impact of Auger recombination on InGaN LED efficiency](https://www.semiconductor-today.com/news_items/2023/aug/ucc-100823.shtml) - Semiconductor Today
- [Auger recombination in AlGaN quantum wells for UV LEDs](https://pubs.aip.org/aip/apl/article-abstract/113/7/071107/36535/) - Appl. Phys. Lett. (2018)
- Piprek et al. "On the uncertainty of the Auger recombination coefficient" (2015)

**Graded Interface Solutions:**
- [Luminous efficiency improved by n-side graded quantum wells](https://opg.optica.org/ol/abstract.cfm?uri=ol-50-8-2614) - Optics Letters (2025)
- [Efficiency Enhancement Using Compositionally Step Graded Barrier](https://ieeexplore.ieee.org/document/7473842/) - IEEE (2016)
- [Efficiency Droop Improvement by Graded-Composition MQWs](https://www.researchgate.net/publication/260510447) - ResearchGate

**Measurement Techniques:**
- [Thermoreflectance and Raman thermometry for nanostructures](https://pubs.aip.org/aip/jap/article/128/13/131101/1027194/) - J. Appl. Phys. (2020)
- [Time-resolved photoluminescence model for InGaN/GaN MQWs](https://www.nature.com/articles/srep45082) - Scientific Reports

**Personal Experimental Data:**
- LED thermal imaging experiments (to be documented)
