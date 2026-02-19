# Software Detective Quantum Efficiency (DQE)

**Core claim:** Passive bot filtering can be built as a multi-stage boundary filter where each stage applies a timing-frequency threshold. Bots self-select out — no explicit classification needed.

---

## Origin

DQE in medical imaging (X-ray, PET) measures how well each detector stage preserves signal-to-noise ratio. A scintillator converts gamma photons → optical photons. A photomultiplier converts optical photons → electrons. An energy gate converts electrons → accepted counts. Each stage has a transfer function. The chain multiplies them:

```
DQE_total = DQE_stage1 × DQE_stage2 × ... × DQE_n
```

The key insight: the system doesn't classify the photon as "real" or "noise" at any single stage. Each stage applies a frequency/energy window, and photons outside that window attenuate progressively. Real signal percolates through. Noise does not.

---

## The Network Traffic Equivalent

Each stage in an HTTP session has a timing signature. The "field" is inter-request timing. The "boundary" is the threshold between human-plausible and bot-generated timing distributions.

```
Request timestamps → [Stage 1] → [Stage 2] → [Stage 3] → Accept/Reject
```

| Stage | Timescale | Human center freq | Bot signature |
|-------|-----------|-------------------|---------------|
| Inter-request timing | 1–30 sec | ~0.1–0.5 Hz | Regular (single freq spike) or near-zero |
| Page interaction | 100–2000 ms | ~1–5 Hz | Too precise or absent |
| Session bursts | 1–10 min | ~0.01–0.05 Hz | No burst structure |

A human session has noise across all three bands — irregular, overlapping, with variance. A bot session is either too regular (single dominant frequency) or too fast (sub-100ms intervals outside the human band entirely).

---

## Connection to Substrate Boundary Framework

This is `u ∝ (∇φ)²` applied to time:

- The "field" φ is inter-arrival time
- The "gradient" ∇φ is the deviation from expected human timing distribution
- "Energy concentration" at the boundary is bot signal — high gradient from the human norm
- The percolation threshold τ_c is the minimum number of stages a session must pass to be accepted

Below τ_c: session is rejected as bot (boundary is sharp, not gradual)
Above τ_c: session is accepted (timing percolates through all stages)

This is why the filter can be sharp without explicit classification. The threshold behavior is structural, not rule-based.

---

## The Transfer Function

For each stage, define a Gaussian band-pass centered on the expected human timing frequency:

```
H(f) = exp(-0.5 × ((f - f_human) / σ)²)
```

Stage SNR:
```
SNR_stage = Σ P(f) × H(f) / noise_floor
```

A session passes the stage if `SNR_stage > 1.0`. The product of stage SNRs determines overall traffic quality.

---

## Falsification Criteria

| Prediction | Falsified if |
|------------|-------------|
| Bots cluster at distinct frequencies | Bot timing is indistinguishable from human Poisson noise |
| Multi-stage filtering outperforms single-stage | Combined stage DQE ≤ best single stage |
| CDN jitter destroys signal at >σ_CDN threshold | Signal survives CDN jitter larger than human variance |
| Percolation threshold is sharp | Accept/reject rate is gradual across timing space |

**The CDN problem is the primary falsification risk.** If CDN jitter σ_CDN ≥ human timing variance σ_human, the filter cannot distinguish between a bot-behind-CDN and a human. The PoC script tests this directly.

---

## What Would Give It Teeth

The framework has operational teeth if:

1. **The CDN noise floor is measurable and bounded** — CDN-introduced jitter has a characteristic distribution (mostly Gaussian, ~10–50ms) that is smaller than human inter-request variance (~hundreds of ms to seconds). If true, the filter survives.

2. **Bots have a characteristic frequency signature** — automation frameworks (Selenium, Puppeteer, Playwright) have default timing behavior that clusters in predictable bands. This is empirically testable.

3. **The multi-stage product is better than any single stage** — this is the DQE property and is testable with synthetic data.

---

## Current Status

- Framework: stated
- Synthetic test: see `scripts/software_dqe.py`
- Empirical validation: pending (requires real bot/human session data)
- Qiskit QFT variant: planned (classical FFT baseline first)

---

## References

- Barrett & Myers (2004). *Foundations of Image Science*. Wiley. (DQE theory)
- Yao & Doretto (2010). Boosting for transfer learning with multiple sources. (multi-stage SNR)
- Puppeteer default timing: 100ms click delay, 0ms inter-action delay (empirically observed)
- CDN latency distributions: Cloudflare reports median added jitter ~5–15ms (P99 ~50ms)
