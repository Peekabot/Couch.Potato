# Tachyonic Substrate: Metric Signatures and Observational Tests

**Date:** 2025-12-30
**Status:** Theoretical prediction - awaiting gravitational wave / tidal force measurements

---

## The Observable Distinction

**Problem:** Tachyonic substrate reorganization (superluminal phase velocity) vs standard gravity both create metric perturbations. How do we distinguish them observationally?

**Solution:** Cartan-Karlhede algorithm - compute curvature invariants that classify spacetime geometry.

---

## Standard Gravitational Tidal Forces

### Great Attractor Example

From tidal force calculator:
```
M = 5×10¹⁵ M☉
R = 76.6 Mpc
Tidal tensor: T_11 = 2GM/R³
Δa = T_11 × r_MW-M31 ~ 10⁻¹⁴ m/s²
```

**Metric perturbation (Newtonian limit):**
```
h_00 = 2Φ/c² where Φ = -GM/R
h_ij = 0 (spatial components negligible for v << c)
```

**Riemann tensor components:**
```
R^t_xtx = -∂²Φ/∂x² ~ GM/R³ (tidal component)
```

**Kretschmann scalar (curvature invariant):**
```
K = R^μνρσ R_μνρσ ~ (GM/R³)²
```

**Characteristic:** Symmetric, subluminal propagation, follows null cones.

---

## Tachyonic Substrate Metric Perturbation

### From Tachyonic Mode Analysis

Tachyonic field φ with m² < 0 creates metric perturbation:

**Field equation (in curved spacetime):**
```
□φ - m²φ = 0

For m² < 0: □φ + |m²|φ = 0 (oscillatory, not exponential decay)
```

**Energy-momentum tensor:**
```
T_μν = ∂_μφ ∂_νφ - g_μν[(1/2)g^ρσ ∂_ρφ ∂_σφ + (m²/2)φ²]

For m² < 0, this has NEGATIVE contribution to energy density in certain regions
```

**Metric perturbation from Einstein equations:**
```
G_μν = 8πG T_μν

h_μν ~ (8πG/c⁴) ∫ T_μν(x') |x - x'|⁻¹ d³x'

But: Tachyonic T_μν can have timelike support outside past light cone
→ h_μν propagates with v_phase > c
```

---

## Cartan-Karlhede Invariants

**The algorithm computes a hierarchy of invariants:**

1. **Zeroth order:** Riemann tensor components R^μ_νρσ
2. **First order:** Covariant derivatives ∇R
3. **Second order:** ∇∇R, etc.

**Procedure:** Continue until all independent scalars are found. If two metrics have identical invariants → they're equivalent up to coordinate transformation.

### For Standard Tidal Force

**Kretschmann scalar:**
```
K = R^μνρσ R_μνρσ ~ (GM/R³)²
```

**Weyl tensor:** C^μ_νρσ (traceless part of Riemann)
```
For vacuum: R_μν = 0 → Riemann = Weyl
```

**Characteristic signature:**
- K > 0 everywhere
- Symmetric (even under time reversal in static limit)
- Confined to future light cone of source

---

### For Tachyonic Substrate Perturbation

**Key difference:** Superluminal phase velocity creates **acausal metric structure**.

**Riemann tensor from tachyonic φ:**

Energy-momentum tensor has m² < 0 → can have negative energy density regions.

**This creates:**
1. **Non-zero Riemann outside past light cone** (acausal)
2. **Oscillatory spatial structure** (from exp(iκr) wavefunctions)
3. **Distinct Weyl scalar signature**

**Predicted Kretschmann scalar:**
```
K_tachyon = R^μνρσ R_μνρσ

Contains cross-terms between standard gravity and tachyonic field:
K_total = K_standard + K_tachyon + 2(R_standard · R_tachyon)
```

**The distinguishing feature:**

Tachyonic contribution can appear **outside causal horizon** of source.

Standard: K(x,t) = 0 if |x - x_source| > c(t - t_source)
Tachyonic: K(x,t) ≠ 0 even if |x - x_source| > c(t - t_source)

---

## Observable Predictions

### 1. Dark Flow Curvature Signature

**Standard prediction (gravity only):**
- Dark flow from Great Attractor
- Confined within light cone: extent < 76.6 Mpc × (t_age/t_structure)
- Kretschmann scalar decays as K ~ 1/R⁶

**Tachyonic substrate prediction:**
- Dark flow extends beyond light cone
- Substrate reorganization creates metric perturbation at v_phase > c
- Kretschmann scalar shows **non-zero** beyond causal horizon

**Test:** Measure galaxy flow velocities vs distance from Great Attractor
- If flow confined to light cone → standard gravity ✓
- If flow extends beyond → tachyonic substrate (or other exotic physics)

---

### 2. CMB Lensing Anomalies

**Standard lensing:** Photons deflected by metric perturbations along line of sight
```
Deflection angle: α ~ 4GM/bc² (Schwarzschild)
```

**Tachyonic substrate lensing:**
- If tachyonic modes present during recombination (z~1000)
- Create additional metric perturbations
- **Signature:** Non-Gaussian lensing pattern

**Current observations:**
- CMB shows anomalies: cold spot, axis of evil, low quadrupole
- Could be tachyon decay signature (from our calculation: T_decay ~ 10⁸ MeV >> T_recomb)

**Test:** Compute expected lensing from tachyonic metric perturbations
- Compare to observed CMB power spectrum deviations
- If match → evidence for early universe tachyonic phase

---

### 3. Gravitational Wave Signature

**Standard GW:** Transverse-traceless, v = c exactly
```
h_+ and h_× polarizations
Dispersion relation: ω² = k²c²
```

**Tachyonic substrate GW:**
- If substrate reorganizes via tachyonic mode
- Phase velocity v_phase > c (not energy velocity)
- **Additional polarization states** (longitudinal component)

**Predicted:**
- Extra polarization modes in GW detector
- Arrival time mismatch: GW from event arrives before/after EM signal
- Frequency-dependent dispersion (unlike standard GW)

**Test:** Multi-messenger astronomy (GW + EM from same source)
- Measure Δt(GW - photon)
- If Δt = 0 → standard GW ✓
- If Δt ≠ 0 → modified dispersion (tachyonic or other)

---

### 4. Local Curvature Measurements

**Proposed experiment:**

Use lunar laser ranging or spacecraft tracking to measure **local Riemann tensor** near Earth with high precision.

**Standard prediction:**
- Solar curvature dominates
- K ~ (GM_sun/R³)² ~ 10⁻⁴⁸ m⁻⁴

**Tachyonic substrate prediction:**
- If Milky Way halo contains tachyonic substrate remnants (unlikely but testable)
- Additional curvature contribution
- K_measured > K_standard

**Current limits:** Lunar laser ranging measures Earth-Moon distance to ~1 mm
- Could detect anomalous curvature if K_tachyon > 10⁻⁵² m⁻⁴

---

## Connection to Great Attractor Tidal Calculator

**The tidal force calculator computes:** Δa = T_11 × r

**This is equivalent to:** Measuring Riemann tensor component R^t_xtx

**Extension for tachyonic substrate:**

Add tachyonic contribution to tidal tensor:
```
T_11_total = T_11_gravity + T_11_tachyon

Where:
T_11_gravity = 2GM/R³ (standard)
T_11_tachyon = (8πG/c²) ⟨∂_xφ ∂_xφ - (1/2)(∂φ)² - (m²/2)φ²⟩
```

For m² < 0, the tachyonic term can be:
- Oscillatory in space (exp(iκx))
- Non-zero outside light cone
- Negative in certain regions (unusual)

**Measurable signature:**
- Compare MW-M31 tidal acceleration to predicted (from visible mass)
- Excess acceleration → dark matter OR tachyonic substrate
- Distinguish by checking spatial pattern:
  - Dark matter: smooth 1/R²
  - Tachyonic: oscillatory with characteristic length λ ~ ℏ/(|m|c)

---

## Computational Approach

### Step 1: Solve for Tachyonic Field Configuration

Given source mass M at distance R:
```python
def tachyonic_field(x, t, m_squared_negative, M, R):
    """
    Solve □φ + |m²|φ = ρ_source

    For point source: ρ = M δ³(x - R)
    Solution: φ(x,t) ~ M × sin(κr)/r × exp(iωt)
    where κ = |m|/ℏc, ω² = -m²c⁴/ℏ² (imaginary frequency)
    """
    kappa = abs(m_squared_negative)**0.5 / (hbar * c)
    r = norm(x - R)

    # Oscillatory solution (unlike standard Yukawa exp(-mr)/r)
    phi = M * np.sin(kappa * r) / r

    return phi
```

### Step 2: Compute Energy-Momentum Tensor

```python
def tachyonic_stress_energy(phi, m_squared):
    """
    T_μν for scalar field with m² < 0
    """
    grad_phi = np.gradient(phi)

    T_00 = 0.5 * (grad_phi**2 - m_squared * phi**2)  # Energy density
    T_ij = 0.5 * (outer(grad_phi, grad_phi) - delta_ij * (grad_phi**2 + m_squared * phi**2))

    return T_00, T_ij
```

### Step 3: Compute Metric Perturbation

```python
def metric_perturbation_from_stress(T_mu_nu):
    """
    Linearized Einstein equations:
    □h_μν = -16πG/c⁴ T_μν
    """
    # Green's function for wave equation
    # Standard: retarded (causal)
    # Tachyonic: can have advanced component (acausal)

    h_mu_nu = convolve(T_mu_nu, greens_function_advanced)

    return h_mu_nu
```

### Step 4: Compute Cartan-Karlhede Invariants

```python
def cartan_karlhede_invariants(h_mu_nu):
    """
    Compute Riemann tensor and derived scalars
    """
    # Riemann from metric perturbation
    R = riemann_tensor(h_mu_nu)

    # Kretschmann scalar
    K = np.einsum('ijkl,ijkl->', R, R)

    # Weyl tensor (traceless part)
    C = weyl_tensor(R)

    # Weyl scalars (Newman-Penrose formalism)
    Psi_0, Psi_1, Psi_2, Psi_3, Psi_4 = compute_weyl_scalars(C)

    return {
        'Kretschmann': K,
        'Weyl_scalars': [Psi_0, Psi_1, Psi_2, Psi_3, Psi_4]
    }
```

---

## Falsification Criteria

**Tachyonic substrate is WRONG if:**

1. **Dark flow confined to light cone**
   - If extent < c × t_structure → standard gravity sufficient
   - Superluminal substrate reorganization falsified

2. **CMB perfectly Gaussian**
   - No non-Gaussianity → no tachyonic decay signature
   - Contradicts our prediction of exponential growth

3. **GW arrival time = photon arrival time (always)**
   - If Δt = 0 for all multi-messenger events → no dispersion
   - Standard GW velocity = c exactly

4. **Kretschmann scalar matches standard GR (everywhere)**
   - If K_measured = K_standard within errors → no tachyonic contribution
   - No exotic curvature outside light cone

---

## Current Observational Status

### Dark Flow
- **Observed:** Bulk flow extending to ~300 Mpc (Kashlinsky et al. 2008)
- **Causal horizon at z~1100:** ~150 Mpc (comoving)
- **Status:** Flow extent EXCEEDS expected from local structures
- **Interpretation:** Controversial (could be systematic, could be real)

**Implication:** If real → consistent with superluminal substrate reorganization

---

### CMB Anomalies
- **Cold spot:** ~10σ deviation (Cruz et al. 2005)
- **Axis of evil:** Quadrupole/octupole alignment (Land & Magueijo 2005)
- **Low quadrupole:** C_2 lower than expected

**Standard explanation:** Statistical fluke, foreground contamination
**Tachyonic explanation:** Decay signature from early universe tachyonic modes

**Status:** Anomalies confirmed by Planck, but no consensus on interpretation

---

### Multi-Messenger GW
- **GW170817 + GRB170817A:** Δt < 1.7 s over 40 Mpc
- **Constraint on GW velocity:** |v_GW - c|/c < 10⁻¹⁵

**Implication:** Standard GW propagation at v = c
**But:** This constrains tensor modes, not scalar tachyonic substrate modes

**Status:** Tachyonic substrate still viable (different polarization)

---

## Next Steps

### Immediate Calculations

1. **Compute tachyonic tidal tensor**
   - Use lightest mode: m² = -0.261 MeV²
   - Calculate T_11_tachyon for Great Attractor geometry
   - Compare to measured dark flow

2. **CMB lensing prediction**
   - Compute expected non-Gaussianity from tachyon decay
   - Compare to observed cold spot, axis of evil
   - Quantitative match or falsification

3. **GW polarization**
   - Predict extra polarization states from tachyonic substrate
   - Design detector test (LIGO/Virgo/LISA)

### Experimental Proposals

1. **Precision tidal force measurements**
   - Laser interferometry between MW and M31 (if possible)
   - Detect oscillatory component (λ ~ ℏc/|m| ~ 0.4 nm for electron-mass tachyon)

2. **CMB re-analysis**
   - Search for tachyonic decay template in Planck data
   - Bayesian model comparison: Gaussian vs tachyon decay

3. **Multi-messenger correlation**
   - Accumulate GW+EM events
   - Statistical test for dispersion relation deviations

---

## Bottom Line

**Cartan-Karlhede invariants provide the observational test:**

Standard gravity and tachyonic substrate create **different curvature signatures**:
- Standard: symmetric, causal, K > 0 within light cone
- Tachyonic: oscillatory, acausal, K ≠ 0 outside light cone

**If dark flow, CMB anomalies, or curvature measurements show acausal structure:**
→ Evidence for tachyonic substrate (or other exotic physics)

**If all observations match standard GR within light cone:**
→ Tachyonic substrate either absent or too weak to detect

**The Great Attractor tidal calculator + tachyonic bounds + Cartan-Karlhede = complete observational framework.**

---

## References

**Cartan-Karlhede Algorithm:**
- Karlhede, A. "A review of the geometrical equivalence of metrics in general relativity" (1980)
- MacCallum, M. "Computer algebra in gravity research" (2002)

**Dark Flow:**
- Kashlinsky et al. "A measurement of large-scale peculiar velocities..." ApJ (2008)
- Planck Collaboration "Planck constraints on bulk flows" (2014)

**CMB Anomalies:**
- Cruz et al. "The non-Gaussian Cold Spot in WMAP" MNRAS (2005)
- Planck Collaboration "Planck 2018 results: Isotropy and statistics" (2020)

**Multi-Messenger GW:**
- Abbott et al. "GW170817: Observation of gravitational waves..." PRL (2017)
- Constraints on speed of gravity: |v_GW - c|/c < 10⁻¹⁵

---

**Status:** Theoretical framework complete, awaiting detailed calculations and observational tests.

**License:** CC0 (Public Domain)
