# Substrate Boundary Energy Theory

> **Core Hypothesis:** Energy storage and extraction in physical systems occurs preferentially at discontinuities, following the general form $u \propto (\nabla \phi)^2$ across all field types.

## Theory Map

### Foundations
- [Boundary Energy Density Framework](foundations/boundary-energy-density.md) - Mathematical formalization
- [Dimensional Analysis](foundations/dimensional-analysis.md) - Why the gradient-squared form is universal

### Domain-Specific Phenomena

**Semiconductor Physics**
- [Phonon Bottleneck at Heterointerfaces](domains/semiconductor/phonon-bottleneck.md)
- [Auger Recombination as Boundary Collision](domains/semiconductor/auger-recombination.md)
- [Quantum Wells as Engineered Boundaries](domains/semiconductor/quantum-wells.md)
- [LED Droop Effect](domains/semiconductor/droop-effect.md)

**Electrostatics & Quantum Storage**
- [Electret Charge Trapping](domains/electrostatics/electrets.md)
- [Quantum Phonograph Concept](domains/electrostatics/quantum-phonograph.md)
- [Ferroelectric Domain Walls](domains/electrostatics/ferroelectric-ram.md)

**Metallurgy & Material Science**
- [Damascus Steel Carbide Boundaries](domains/metallurgy/damascus-steel.md)

**Geometry & Eigenmodes**
- [Vector Equilibrium as Eigenmode Substrate](domains/geometry/vector-equilibrium-eigenmodes.md)

**Thermodynamics**
- [Pulse Jet Water Heater](domains/thermodynamics/pulse-jet-heater.md)

### Cross-Domain Integration
- [Substrate Boundary Framework](cross-domain/substrate-boundary-framework.md) - Unified theory
- [Pattern Recognition Across Fields](cross-domain/pattern-recognition.md)

### Testable Predictions
- [Pulse Jet 98% Efficiency Claim](predictions/pulse-jet-heater.md)
- [Quantum Phonograph Signal Recovery](predictions/phonograph-recovery.md)
- [Damascus Nucleation Control](predictions/damascus-nucleation.md)

### Verification Status
- [Experimental Data](verification/README.md)
- [Open Questions](../../issues) - Track using GitHub Issues

---

## Quick Reference: Energy Density Forms

| Field Type | Energy Density | Gradient Form |
|------------|---------------|---------------|
| Electric | $u = \frac{1}{2}\varepsilon_0 E^2$ | $\mathbf{E} = -\nabla V$ |
| Magnetic | $u = \frac{1}{2\mu_0} B^2$ | $\nabla \times \mathbf{B} = \mu_0 \mathbf{J}$ |
| Acoustic | $u = \frac{1}{2}\rho v^2$ | $v \propto \nabla p$ |
| Elastic | $u = \frac{1}{2}K\varepsilon^2$ | $\varepsilon = \frac{\partial u}{\partial x}$ |

**Pattern:** All scale as $(\text{spatial derivative})^2$

---

## Navigation
- 📚 [Browse by domain](domains/)
- 🔬 [View predictions](predictions/)
- ✅ [Check verification status](verification/)
- 📖 [Read references](references/bibliography.md)

## Contribution Guidelines
See [WORKFLOW.md](WORKFLOW.md) for how to add/update theories using git.
