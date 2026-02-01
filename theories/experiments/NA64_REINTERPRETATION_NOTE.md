# Reinterpretation Note: NA64 Limits Do Not Constrain Fully Visible Low-Mass States

**Date:** 2025-12-30
**Authors:** Substrate Theory Testing Group
**Status:** Draft for comment

---

## Abstract

We show that existing NA64 exclusion limits for dark photons in the 1-200 MeV mass range do not constrain fully visible, multi-lepton final states arising from substrate eigenmode production. The NA64 selection optimizes for missing energy signatures and explicitly vetoes events with multiple charged tracks. We calculate acceptance ε ≈ 0 for eigenmode-like signals and identify this as uncovered parameter space requiring dedicated searches.

---

## 1. Introduction

The NA64 experiment [1,2] has published stringent exclusion limits on dark photon production in the mass range 1-200 MeV using a 100 GeV electron beam. These limits constrain scenarios where dark photons:
1. Carry away missing energy
2. Decay invisibly or escape the detector
3. Produce single electromagnetic showers

However, alternative low-mass states with different decay topologies may evade these selections entirely.

---

## 2. Signal Topology Comparison

### NA64 Dark Photon Signal:
- **Production:** e⁻ + N → e⁻ + N + A'
- **Decay:** A' → invisible OR escapes
- **Signature:** Missing energy E_miss > 10 GeV
- **Selection:** Single EM shower + nothing else

### Substrate Eigenmode Signal:
- **Production:** e⁻ + N → e⁻ + N + eigenmode
- **Decay:** eigenmode → 2e⁺ + 2e⁻ (prompt)
- **Signature:** Fully visible 4-lepton final state
- **Energy:** Soft spectrum (E_lepton ~ MeV scale)

**Key difference:** Dark photons are invisible. Eigenmodes are maximally visible.

---

## 3. Acceptance Calculation

We calculate NA64 acceptance for six predicted eigenmode masses: 2.04, 4.6, 12.8, 28, 56, 167 MeV.

### Cut Flow:

| Cut | Requirement | Eigenmode Topology | Result |
|-----|-------------|-------------------|--------|
| **Trigger** | Single shower E > 50 GeV | All daughters < 1 GeV | ε = 0 |
| **Veto** | No charged particles | 4 charged leptons | ε = 0 |
| **Missing Energy** | E_miss > 10 GeV | E_miss ≈ 0 (visible) | ε = 0 |
| **Multiplicity** | N_shower ≤ 2 | N_shower = 4 | ε = 0 |

**Result:** ε_total = 0 for all eigenmode masses.

**Conclusion:** NA64's selection is blind to this topology.

---

## 4. Why Existing Limits Do Not Apply

NA64's published exclusion curves show:

σ(A' production) × BR(A' → invisible) < σ_limit(m_A')

This statement is **model-dependent** and assumes:
1. Missing energy signature
2. Single-shower topology
3. Invisible or escaping final state

For fully visible, multi-lepton eigenmodes:

σ(eigenmode) × ε_NA64 < σ_obs

But ε_NA64 ≈ 0, so this inequality is **vacuous**.

**No limit is set.**

---

## 5. What This Means

NA64's null result tells us:

✓ "No dark photons coupling to electrons with E_miss > 10 GeV in 1-200 MeV range"

NA64's null result does NOT tell us:

✗ "No low-mass states exist in 1-200 MeV range"
✗ "All electromagnetic production mechanisms excluded"
✗ "Multi-lepton final states ruled out"

---

## 6. Required Search Parameters

To test substrate eigenmode hypothesis, a search must:

1. **Lower trigger threshold** to O(MeV) scale
   → Capture soft leptons

2. **Remove charged particle veto**
   → Allow 4-lepton topology

3. **Accept high multiplicity**
   → Do not reject multi-shower events

4. **No missing energy requirement**
   → Target fully visible decays

5. **Optimize for vertex reconstruction**
   → Identify e⁺e⁻e⁺e⁻ from common origin

**This is a fundamentally different search from NA64.**

---

## 7. Existing Experiments That Could Constrain

### Potentially sensitive experiments:

| Experiment | Why Sensitive | Status |
|------------|---------------|--------|
| **Bubble chambers** | Visual, no trigger bias | Archives (SLAC, CERN) |
| **Pair spectrometer data** | Low-mass e⁺e⁻ pairs | 1960s-1980s, unpublished |
| **Low-energy positron beams** | Direct eigenmode production | Modern, reanalysis possible |
| **Belle II** (ISR mode) | Clean e⁺e⁻ environment | 2019-present data |

### Explicitly insensitive:

- **NA64:** Vetoes multi-lepton (this note)
- **LHC:** Trigger thresholds too high
- **Dark matter direct detection:** Wrong signature

---

## 8. Cosmological Constraints

Even if accelerators haven't searched, cosmology might constrain eigenmodes through:

1. **Big Bang Nucleosynthesis:** Extra relativistic species (ΔN_eff)
2. **CMB spectral distortions:** Late-time decays
3. **Stellar cooling:** Emission from cores

We calculate these constraints separately (see `cosmological_falsification.py`).

**Preliminary result:** Eigenmodes with m < 50 MeV and τ < 10⁻¹⁵ s are cosmologically safe.

---

## 9. Proposed Search Strategy

### Phase 1: Archive Mining
- Digitize bubble chamber photographs (SLAC, CERN, Fermilab)
- Reanalyze pair spectrometer data (1970s fixed-target experiments)
- **Cost:** $10k (scanning + student labor)
- **Timeline:** 6 months

### Phase 2: Existing Data Reanalysis
- Request Belle II ISR photon + missing mass data
- Check NA64 pre-selection event counts (before missing E cut)
- **Cost:** $0 (data exists)
- **Timeline:** 3 months (pending collaboration)

### Phase 3: Dedicated Low-Energy Search
- e⁺e⁻ collider at √s = 2-200 MeV
- Or positron beam dump with 4-lepton trigger
- **Cost:** $100k-500k (depends on facility)
- **Timeline:** 2 years

---

## 10. Predictions for Validation

If substrate eigenmode theory is correct, a properly designed search should find peaks at:

| Mass (MeV) | n | l | Branching Ratio | Expected Rate |
|------------|---|---|-----------------|---------------|
| 2.044 | 2 | 0 | → 2e⁺2e⁻: ~100% | TBD |
| 4.599 | 3 | 0 | → 2e⁺2e⁻: ~100% | TBD |
| 12.775 | 5 | 0 | → 2e⁺2e⁻: ~90% | TBD |
| 28.105 | 7 | 6 | → 2e⁺2e⁻: ~80% | TBD |
| 56.210 | 10 | 10 | → 2e⁺2e⁻: ~70% | TBD |
| 167.097 | 25 | 15 | → 2e⁺2e⁻: ~50% | TBD |

**Falsification criteria:**
- If NO peaks found → Substrate theory wrong
- If peaks found at WRONG masses → Theory parameters need adjustment
- If peaks found at RIGHT masses → Substrate theory validated

---

## 11. Conclusions

1. **NA64 limits do not constrain substrate eigenmodes** (ε ≈ 0)

2. **This is not a criticism of NA64** - their experiment was optimized for dark photons, and they excluded that model

3. **The 1-200 MeV range remains uncovered** for fully visible, multi-lepton final states

4. **Dedicated searches are needed** with different selection criteria

5. **Existing archives may already contain the signal** (bubble chambers, pair spectrometers)

---

## References

[1] NA64 Collaboration, "Search for a hypothetical 16.7 MeV gauge boson and dark photons in the NA64 experiment at CERN," Phys. Rev. Lett. 120, 231802 (2018)

[2] NA64 Collaboration, "Search for vector mediator of Dark Matter production in invisible decay mode," Phys. Rev. D 97, 072002 (2018)

[3] This work, "Substrate Eigenmode Particle Mass Predictions," github.com/Peekabot/Couch.Potato/theories/PARTICLE_MASS_PREDICTIONS.md (2025)

[4] This work, "NA64 Acceptance Calculation," github.com/Peekabot/Couch.Potato/theories/experiments/na64_acceptance_proof.py (2025)

---

## Contact

For questions or collaboration on dedicated searches:
GitHub: github.com/Peekabot/Couch.Potato
Issues: github.com/Peekabot/Couch.Potato/issues

---

## Appendix: Acceptance Code

Full calculation available at:
`theories/experiments/na64_acceptance_proof.py`

Run with: `python3 na64_acceptance_proof.py`

Results:
```
ALL eigenmodes have ε = 0 in NA64
→ NA64's exclusion limits DO NOT constrain this hypothesis
→ Not because NA64 looked and found nothing
→ But because NA64's cuts are blind to this topology
```

---

**Revision History:**
- 2025-12-30: Initial draft
- Status: Ready for community review

---

**License:** CC0 (Public Domain) - Use freely, cite appropriately
