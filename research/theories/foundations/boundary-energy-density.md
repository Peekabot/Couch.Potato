# The Boundary Energy Pattern

## What I Keep Seeing

Every time I dig into how energy actually gets stored or extracted in real systems, the same pattern shows up:

$$u \propto (\nabla \phi)^2$$

Energy density scales with the *square* of how fast something changes in space. Not the field itself - the *gradient*.

## Working Through the Math

### Electric fields
Started with the basic formula from undergrad:
$$u_E = \frac{1}{2}\varepsilon_0 E^2$$

But $\mathbf{E} = -\nabla V$, so really:
$$u_E = \frac{1}{2}\varepsilon_0 |\nabla V|^2$$

**What this actually means:** Energy piles up where voltage changes fast. At interfaces. At charged layers. Anywhere there's a discontinuity.

### Magnetic fields
Same deal with magnetics:
$$u_M = \frac{1}{2\mu_0} B^2$$

Maxwell says $\nabla \times \mathbf{B} = \mu_0 \mathbf{J}$ - magnetic field relates to current gradients.

Energy concentrates at material boundaries (ferromagnetic/paramagnetic interfaces), domain walls, current sheets.

### Sound waves
Even acoustic energy follows this:
$$u_A = \frac{1}{2}\rho v^2$$

Where particle velocity connects to pressure gradient:
$$\rho \frac{\partial v}{\partial t} = -\nabla p$$

Energy builds up at impedance mismatches. Water/air interface. Density discontinuities. My pulse jet heater exploits exactly this.

### Mechanical strain
And elastic energy in solids:
$$u_S = \frac{1}{2}K\varepsilon^2$$

Strain is just displacement gradient: $\varepsilon = \frac{\partial u}{\partial x}$

Energy gets trapped at grain boundaries, phase interfaces, dislocation cores. Damascus steel works because of this.

## Why Always Squared?

Had to convince myself this isn't confirmation bias. It's actually forced by:

1. **Dimensional analysis:** Energy density is $[J/m^3]$, requires squared field quantities
2. **Lagrangian mechanics:** KE terms are always quadratic in velocities (time derivatives)
3. **Field theory:** PE terms are quadratic in spatial derivatives
4. **Symmetry:** Energy has to be positive → even powers only

## The Engineering Insight

If energy concentrates where $|\nabla \phi|$ is large, then to maximize efficiency:
- Make boundaries **sharp** → large gradient
- Maximize **interface area** → more boundary
- Tune the **discontinuity** → optimize mismatch

This explains:
- Why LEDs use quantum wells (sharp band discontinuities)
- Why capacitors want thin dielectrics (large $\nabla V$)
- Why Damascus has nanoscale carbide layers (boundary density)
- Why resonant cavities work (impedance mismatches)

## Cross-References
- [Semiconductor phonon bottleneck](../domains/semiconductor/phonon-bottleneck.md)
- [Electret charge storage](../domains/electrostatics/electrets.md)
- [Damascus steel boundaries](../domains/metallurgy/damascus-steel.md)

## Open Questions
1. Can we quantify "boundary sharpness" universally across field types?
2. Is there an upper limit to $|\nabla \phi|$ before quantum/atomic effects dominate?
3. How does boundary curvature affect energy density?

## References
- Jackson, J.D. "Classical Electrodynamics" (1999) - Ch. 1.11
- Landau & Lifshitz "Theory of Elasticity" (1986) - Ch. 1
- Ashcroft & Mermin "Solid State Physics" (1976) - Ch. 17
