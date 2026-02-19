# VE Cavity Eigenfrequency Calculation

## VE Geometry

**Cuboctahedron (Vector Equilibrium) vertices:**

12 vertices at positions (normalized to unit sphere):
- $(±1/\sqrt{2}, ±1/\sqrt{2}, 0)$ - 4 vertices
- $(±1/\sqrt{2}, 0, ±1/\sqrt{2})$ - 4 vertices
- $(0, ±1/\sqrt{2}, ±1/\sqrt{2})$ - 4 vertices

**Key property:** Distance from origin to vertex = edge length = $1$

## Spherical Harmonic Connection

For spherical harmonics $Y_l^m(\theta, \phi)$, specific combinations at $l=5$ create 12-fold symmetric patterns.

**Relevant modes:** $l=5$ has $2l+1 = 11$ values of $m$ from $-5$ to $+5$

Literature indicates that **icosahedral symmetry** (related to VE) appears in:
- $Y_5^0$ combined with specific $m$ values
- Creates 12 equivalent maxima/minima

**This needs explicit calculation** - flagged for numerical verification.

## Acoustic Cavity Eigenfrequencies

For spherical cavity of radius $R$ with sound speed $c$:

### Wave Equation

$$\nabla^2 p + k^2 p = 0$$

Where $k = \omega/c = 2\pi f/c$

### Boundary Conditions

Rigid walls: $\frac{\partial p}{\partial r}\bigg|_{r=R} = 0$

### Solutions

$$p_{lm}(r, \theta, \phi) = j_l(k_{ln}r) Y_l^m(\theta, \phi)$$

Where $j_l$ is spherical Bessel function of first kind.

### Eigenfrequencies

$$f_{ln} = \frac{z_{ln} c}{2\pi R}$$

Where $z_{ln}$ are zeros of $j_l'(z) = 0$ (derivative)

## For $l=5$ (VE-Relevant Mode)

**First few zeros of $j_5'(z)$:**
- $z_{5,1} \approx 8.58$
- $z_{5,2} \approx 11.97$
- $z_{5,3} \approx 15.24$

### Eigenfrequencies

$$f_{5,1} = \frac{8.58 \cdot c}{2\pi R} \approx \frac{1.37c}{R}$$

$$f_{5,2} \approx \frac{1.91c}{R}$$

$$f_{5,3} \approx \frac{2.43c}{R}$$

## Numerical Examples

### Acoustic cavity in air
- $c = 340$ m/s
- $R = 0.01$ m (1 cm radius)

$$f_{5,1} = \frac{1.37 \times 340}{0.01} = 46.6 \text{ kHz}$$

### GaN phonon cavity
- $c_s = 8100$ m/s (longitudinal sound)
- $R = 3 \times 10^{-9}$ m (3 nm QW radius equivalent)

$$f_{5,1} = \frac{1.37 \times 8100}{3 \times 10^{-9}} = 3.7 \text{ THz}$$

**This is in the optical phonon range!** (GaN LO phonon ~92 meV ≈ 22 THz)

## VE-Specific Prediction

**If VE substrate is real:**

Phononic crystal with VE unit cell should show **bandgap centered at** $f_{5,1}$

**Why?** VE focal points create maximum scattering for $l=5$ mode

### Testable Design

**VE phononic crystal:**
- Unit cell = cuboctahedron
- Material A at vertices (high density)
- Material B in bulk (low density)
- Lattice constant $a$ chosen so:

$$f_{\text{gap}} = \frac{c_{\text{avg}}}{2a}$$

**Prediction:** Bandgap will align with $l=5$ eigenmode spectrum

## Cymatics Experiment

**Practical VE validation:**

1. **Setup:** Spherical water droplet on vibrating plate
2. **Drive frequency:** Sweep from 10-100 kHz
3. **Observe:** Standing wave pattern on surface
4. **Measure:** Nodal point positions

**Expected at $f_{5,1}$:**
- 12 nodal points form VE geometry
- Vertices equidistant from center
- Edge length = radius

**This is cheapest direct test of VE substrate hypothesis**

## Connection to FCC Phonons

FCC lattice has VE coordination.

**Phonon dispersion** in FCC should reflect VE eigenmode spectrum.

From literature (GaN, copper, etc.):
- Acoustic branches: low frequency
- Optical branches: high frequency
- Bandgaps at specific k-points

**Question:** Do these frequencies match VE cavity modes?

**Need to compare:**
- Measured phonon dispersion for FCC metal (e.g., Al, Cu)
- Calculated VE eigenfrequencies with $a$ = lattice constant
- Look for correspondence

## Edge Length Determines Everything

**Key insight:** VE edge length $a$ sets the scale

For unit sphere VE:
- Edge length = $\sqrt{2}$ (exact geometry)
- But **physical** edge length depends on system

**Examples:**
- FCC crystal: $a$ = lattice constant (~4 Å for metals)
- Quantum well: $a$ = well width (~3 nm)
- Cymatics: $a$ = droplet diameter (~mm)
- Damascus: $a$ = grain size (~μm)

**Universal prediction:**
$$f_{\text{focal}} \propto \frac{c}{a}$$

Systems with same $a$ and $c$ will have same focal frequency.

## What This Explains

### LED Phonon Bottleneck
- InGaN QW: $a \sim 3$ nm
- If QW width ≠ VE focal wavelength → mismatch
- Phonons trapped (can't escape to GaN substrate)
- **Solution:** Tune QW width to match $\lambda_{5,1}/2$

### Damascus Pattern Formation
- Grain size: $a \sim 1$-10 μm
- Thermal cycling creates standing waves
- Carbon segregates to VE focal points
- Cementite precipitates at nodes

### FCC Crystal Stability
- Atoms settle at VE vertices
- Energy minimum at focal points
- Lattice constant = VE edge length for minimum energy
- **This is why FCC is common - it's the VE solution**

## Calculations Still Needed

1. ✅ Eigenfrequencies for $l=5$: Done (approximate)
2. ❌ Exact spherical harmonic superposition giving 12 VE nodes
3. ❌ Comparison to measured FCC phonon dispersion
4. ❌ Quantum mechanical version (Schrödinger in VE potential)
5. ❌ EM version (Maxwell in VE cavity)

## Testable Predictions Summary

| System | $a$ | $c$ | $f_{5,1}$ predicted | Measurement |
|--------|-----|-----|---------------------|-------------|
| Acoustic cavity (air) | 1 cm | 340 m/s | 46.6 kHz | TBD (cymatics) |
| GaN QW | 3 nm | 8100 m/s | 3.7 THz | Compare to phonon spectrum |
| Water droplet | 1 mm | 1480 m/s | 2.0 MHz | Ultrasound imaging |
| FCC copper | 3.6 Å | 4760 m/s | 18 THz | Compare to measured phonons |

## Open Questions

1. **Does $l=5$ actually give 12 nodes in VE configuration?** (Needs numerical verification)
2. **How does this relate to icosahedral group theory?** (VE has icosahedral symmetry subset)
3. **Can we measure VE focal energy concentration directly?** (Acoustic intensity at cavity center)
4. **Do real FCC phonon dispersions match VE predictions?** (Need literature comparison)

## Cross-References
- [VE substrate focal energy theory](../speculative/ve-substrate-focal-energy.md)
- [VE eigenmode geometry](../domains/geometry/vector-equilibrium-eigenmodes.md)
- [Phonon bottleneck](../domains/semiconductor/phonon-bottleneck.md)

## References

**Spherical Bessel Functions:**
- Abramowitz & Stegun "Handbook of Mathematical Functions" Ch. 10
- Zeros of $j_l'(z)$ tabulated

**Acoustic Cavities:**
- Morse & Ingard "Theoretical Acoustics" (1968) - Ch. 7

**FCC Phonon Dispersions:**
- Ashcroft & Mermin "Solid State Physics" - Ch. 22
- Experimental data: Brockhouse et al. for various FCC metals

**Spherical Harmonics and Symmetry:**
- Need to locate icosahedral group decomposition

---

**Status:** Framework established, numerical verification pending, cymatics experiment proposed as direct test.
