# CRT Phosphor Radiation Energy Extraction Test

## Hypothesis

CRT phosphor screens are pre-optimized substrate boundary structures that may extract DC voltage from ionizing radiation (gammas) via focal energy concentration at phosphor/metal backing interface.

**Prediction:** Am-241 gamma radiation incident on CRT phosphor will generate measurable DC voltage (1-10 mV) if boundary energy concentration effect is real.

**Falsification:** No signal above thermal noise floor (~100 μV) indicates boundary effect doesn't work for gammas, or CRT phosphors not optimized for DC extraction.

## Background

**CRT Phosphor Structure:**
- Phosphor grains: ZnS, Y₂O₃, or similar (5-20 μm diameter)
- Metal backing: Aluminum film (~100 nm thick)
- Interface: Sharp discontinuity = substrate boundary
- Industrial optimization: 50+ years of R&D for X-ray → photon conversion

**Am-241 Emission:**
- Alpha: 5.5 MeV (blocked by Al foil)
- Gamma: 60 keV (penetrates, absorbed by phosphor)
- Activity: ~1 μCi in typical smoke detector
- Flux at 1 cm: ~10⁴ γ/s

**Expected Signal (if boundary effect real):**
- Absorbed gammas: ~1000/s (10% absorption)
- Electron cascade: ~60 e⁻ per gamma
- Total current: ~10 fA
- If boundaries concentrate: 1-10 mV DC voltage
- Thermal noise floor: ~100 μV

## Materials Required

### Essential
1. **CRT monitor or TV** (dead/broken OK)
   - Size: Any (larger = more signal)
   - Type: Color or monochrome
   - Source: E-waste, Craigslist, curb

2. **Am-241 source** (from ionization smoke detector)
   - Activity: 0.9-1.0 μCi typical
   - Alternative: Check radioactive source suppliers

3. **Aluminum foil** (blocks alphas, passes gammas)
   - Thickness: Standard kitchen foil (~15 μm)
   - Amount: Small piece (2x2 cm)

4. **Multimeter with μV resolution**
   - Required: DC voltage mode, <100 μV noise
   - Options:
     - Keithley 2000 series (~$500 used)
     - Fluke 8846A (~$1000 used)
     - HP 34401A (~$300 used)
   - Budget: Arduino + INA219 (~$20, 4 μV resolution)

5. **Shielding/dark box**
   - Cardboard box painted black inside
   - Eliminates photoelectric effect from ambient light
   - Aluminum foil lining (optional Faraday cage)

### Optional (Improved Measurement)
6. **Oscilloscope** (observe signal dynamics)
7. **Low-noise preamp** (increase sensitivity)
8. **Temperature logger** (monitor thermoelectric effects)
9. **Faraday cage** (eliminate EM pickup)

## Safety Considerations

### Radiation Safety
**Am-241 handling:**
- Alpha: Blocked by dead skin layer, **DO NOT INGEST**
- Gamma: Low dose, ~0.1 mrem/hour at 10 cm
- Keep source in smoke detector housing when not testing
- Work in ventilated area (radon daughter risk)
- Wash hands after handling
- Annual dose limit for public: 100 mrem (this is ~1000 hours exposure)

**CRT handling:**
- High voltage capacitor may hold charge (discharge before disassembly)
- Implosion risk if face glass broken
- Lead in glass (don't ingest dust)
- Dispose properly at e-waste facility

### Electrical Safety
- Low voltage only (<10V expected)
- No mains power needed
- Standard ESD precautions

## Experimental Protocol

### Phase 1: CRT Disassembly

**Step 1.1: Discharge CRT**
```
1. Unplug CRT, wait 24 hours
2. Use insulated screwdriver to short HV anode to ground
3. Repeat 3x to ensure discharge
4. Verify with multimeter (0V across anode cap)
```

**Step 1.2: Remove Phosphor Screen**
```
Option A (Intact tube):
1. Mark phosphor screen boundary with marker
2. Access from rear (remove electron gun assembly)
3. Carefully separate phosphor screen from glass faceplate
4. Phosphor layer usually on separate screen or directly on glass

Option B (Broken tube - SAFER):
1. Wrap CRT in towel
2. Carefully break faceplate away from funnel
3. Extract phosphor screen
4. Dispose of glass at e-waste facility

Note: Phosphor may be on removable metal frame or directly on glass
```

**Step 1.3: Identify Layers**
```
Cross-section (front to back):
[Glass faceplate]
[Phosphor layer - powder or coating, ~10-50 μm]
[Metal backing - aluminum, ~100 nm, shiny]

Test:
- Phosphor side: colored powder (green, blue, red, or white)
- Metal side: shiny aluminum film
- Continuity: Multimeter should show <10Ω across metal backing
```

### Phase 2: Baseline Measurement (Control)

**Step 2.1: Connect Measurement Circuit**
```
[Metal backing] -----> [Multimeter +]
[Phosphor layer] ----> [Multimeter -]
(or vice versa - polarity TBD)

Alternative (lower noise):
[Metal backing] ----> [INA219 V+]
[Phosphor layer] ---> [INA219 V-]
                       |
                [Arduino serial out] --> [Computer logging]
```

**Step 2.2: Establish Noise Floor**
```
Setup:
1. Place phosphor screen in dark box
2. Close box completely (no light)
3. Wait 5 minutes for thermal equilibrium
4. Record voltage for 10 minutes at 1 Hz sample rate

Expected:
- Thermal noise: ~50-200 μV RMS
- Drift: <1 mV over 10 minutes
- No coherent signal

Save data: baseline_dark.csv
```

**Step 2.3: Light Test (Verify Photoelectric)**
```
Setup:
1. Open dark box
2. Shine LED flashlight on phosphor side
3. Record voltage

Expected:
- Voltage change: mV range (photoelectric effect)
- Polarity: Determines which terminal is + (likely metal backing)
- Confirms electrical connection working

Save data: baseline_light.csv
```

### Phase 3: Gamma Irradiation Test

**Step 3.1: Source Preparation**
```
1. Remove Am-241 source from smoke detector
   - Usually small metal disk or foil
   - Handle by edges only
   - Keep in sealed container when not testing

2. Create alpha shield
   - Place source on small stand
   - Cover with 2 layers Al foil (blocks alphas)
   - Tape edges (prevent foil touching phosphor)

3. Verify alpha blocking
   - Use Geiger counter on other side of foil
   - Should see ~90% reduction in counts
   - Remaining counts = gammas
```

**Step 3.2: Gamma Exposure Measurement**
```
Setup:
1. Place phosphor screen in dark box (phosphor side up)
2. Position shielded Am-241 source 1 cm above phosphor
   [Am-241 source]
         |
   [Al foil shield]
         | (1 cm air gap)
   [Phosphor layer]
   [Metal backing] --> [Multimeter +]

3. Close dark box
4. Wait 2 minutes for settling
5. Record voltage for 30 minutes at 1 Hz

Expected (if hypothesis correct):
- DC offset: 1-10 mV above baseline
- Noise: Similar to baseline (~100 μV RMS)
- Stable over 30 minutes

Expected (if hypothesis wrong):
- No change from baseline
- Or only AC pickup (Faraday cage test)

Save data: gamma_1cm.csv
```

**Step 3.3: Distance Dependence**
```
Repeat Step 3.2 at distances:
- 0.5 cm (closer = higher flux)
- 2 cm
- 5 cm
- 10 cm (far = near zero signal)

Expected (if real):
- Signal ∝ 1/r² (inverse square law)
- Plot: log(signal) vs log(distance) → slope = -2

Expected (if artifact):
- No distance dependence
- Or wrong slope

Save data: gamma_distance_scan.csv
```

### Phase 4: Control Tests (Eliminate Confounds)

**Step 4.1: Electromagnetic Pickup Test**
```
Setup:
1. Remove Am-241 source entirely
2. Place phone/radio/wireless device near setup
3. Transmit signal
4. Record voltage

Expected:
- If Phase 3 signal was EM pickup: signal persists
- If Phase 3 signal was real: no signal without source

Mitigation:
- Wrap entire setup in Al foil (Faraday cage)
- Ground foil to earth
- Repeat Phase 3
```

**Step 4.2: Thermoelectric Test**
```
Setup:
1. Place hot object (60°C) on metal backing
2. Record voltage vs temperature differential

Calculation:
- Seebeck coefficient for ZnS/Al: ~100 μV/K
- For 10 K difference: ~1 mV

Check:
- Am-241 source temperature rise at 1 cm: <0.1 K
- Expected thermoelectric: <10 μV (below signal)

If thermal is issue:
- Use heat sink on source
- Monitor temperature with IR thermometer
```

**Step 4.3: Polarity Test**
```
Setup:
1. Reverse multimeter leads
2. Repeat gamma exposure test

Expected:
- Signal inverts polarity
- Magnitude unchanged

Interpretation:
- If signal doesn't invert: artifact (EM pickup)
- If inverts properly: real voltage
```

**Step 4.4: Shielding Test**
```
Setup:
1. Place 1mm lead sheet between source and phosphor
2. Record voltage (lead blocks gammas)

Expected:
- Signal drops to baseline
- Confirms signal is from gamma absorption

Alternative:
- Increase distance to 50 cm
- Signal should drop to ~1/2500 of 1cm value
```

### Phase 5: Optimization (If Signal Found)

**Step 5.1: Phosphor Type Comparison**
```
Test different CRT phosphors:
- Green (ZnS:Cu)
- Blue (ZnS:Ag)
- Red (Y₂O₃:Eu)
- White (mixed)

Hypothesis:
- Different eigenmode spectra
- One type may be optimal for DC extraction

Measure:
- Signal amplitude vs phosphor type
- Identify best performer
```

**Step 5.2: Thickness Optimization**
```
If possible, test phosphor layers of different thickness:
- Thin: <10 μm (less absorption, less signal?)
- Medium: 10-30 μm (optimal?)
- Thick: >30 μm (more absorption, but longer diffusion path?)

Prediction (from eigenmode theory):
- Optimal thickness = λ/2 where λ = eigenmode wavelength
- Calculate from VE eigenfrequency
```

**Step 5.3: Source Activity Scaling**
```
If accessible, test with stronger sources:
- Multiple smoke detectors (sum currents)
- Higher activity Am-241 (purchase from supplier)
- Different isotope (Cs-137, Co-60)

Expected:
- Signal ∝ source activity (linear)
- Proves not saturation effect
```

## Data Analysis

### Signal Detection Criteria

**Positive Result (Hypothesis Supported):**
1. DC voltage offset: >5x noise floor (>500 μV)
2. Distance dependence: 1/r² with R² > 0.9
3. Shield blocking: >90% reduction with Pb
4. Polarity reversal: Signal inverts with leads
5. No thermal component: T-corrected signal persists

**Negative Result (Hypothesis Falsified):**
1. No signal above noise floor
2. OR signal fails any of above criteria
3. OR signal explained by confounds (EM, thermal)

### Statistical Analysis

```python
# Load data
baseline = pd.read_csv('baseline_dark.csv')
gamma = pd.read_csv('gamma_1cm.csv')

# Calculate noise floor
noise_std = baseline['voltage'].std()
noise_mean = baseline['voltage'].mean()

# Signal detection
gamma_mean = gamma['voltage'].mean()
signal = gamma_mean - noise_mean
SNR = signal / noise_std

# Threshold for detection
if SNR > 5:
    print(f"SIGNAL DETECTED: {signal*1e6:.1f} μV (SNR = {SNR:.1f})")
else:
    print(f"NO SIGNAL: {signal*1e6:.1f} μV (SNR = {SNR:.1f})")

# Distance analysis
distances = [0.5, 1, 2, 5, 10]  # cm
signals = [...]  # measured values

# Fit to inverse square
from scipy.optimize import curve_fit
def inv_square(r, A):
    return A / r**2

popt, pcov = curve_fit(inv_square, distances, signals)
print(f"Fit: A = {popt[0]:.2e}, R² = {r2_score(signals, inv_square(distances, *popt)):.3f}")
```

### Visualization

```python
import matplotlib.pyplot as plt

# Time series
plt.figure(figsize=(12,4))
plt.subplot(1,2,1)
plt.plot(baseline['time'], baseline['voltage']*1e6, label='Baseline', alpha=0.5)
plt.plot(gamma['time'], gamma['voltage']*1e6, label='With Am-241', alpha=0.5)
plt.xlabel('Time (s)')
plt.ylabel('Voltage (μV)')
plt.legend()
plt.title('Signal vs Time')

# Distance dependence
plt.subplot(1,2,2)
plt.loglog(distances, signals, 'o', label='Measured')
plt.loglog(distances, inv_square(distances, *popt), '--', label='1/r² fit')
plt.xlabel('Distance (cm)')
plt.ylabel('Signal (V)')
plt.legend()
plt.title('Inverse Square Law')
plt.tight_layout()
plt.savefig('crt_phosphor_results.png', dpi=300)
```

## Expected Timeline

**Week 1: Acquisition**
- Source CRT (e-waste/Craigslist)
- Extract Am-241 from smoke detector
- Acquire/build measurement circuit

**Week 2: Setup & Baseline**
- Disassemble CRT safely
- Extract phosphor screen
- Establish baseline noise floor

**Week 3: Gamma Testing**
- Run distance scan
- Control tests (EM, thermal, shielding)
- Data analysis

**Week 4: Optimization (if signal found)**
- Test different phosphors
- Vary geometry
- Scale testing

**Total time: 1 month part-time**

## Budget

**Minimal Setup (~$20):**
- CRT: Free (e-waste)
- Am-241: Free (smoke detector you own)
- Al foil: $1
- Arduino + INA219: $20
- Dark box: Free (cardboard)
- **Total: $21**

**Research-Grade (~$500):**
- CRT: $0
- Am-241: $0
- Keithley 2000 multimeter (used): $400
- Oscilloscope (used): $100
- Faraday cage materials: $50
- **Total: $550**

## Safety Compliance

**Radiation:**
- Am-241 activity <1 μCi = exempt quantity
- No NRC license required for smoke detector source
- Follow ALARA (As Low As Reasonably Achievable)
- Disposal: Return to smoke detector, proper e-waste

**Electrical:**
- Low voltage only (<10V)
- No high voltage work after discharge
- Standard lab safety

**Chemical:**
- Phosphor powders: Avoid inhalation
- Lead glass: Avoid ingestion
- Work in ventilated area
- Wash hands after

## Documentation Requirements

**For Each Test:**
1. Photo of setup
2. Multimeter reading (photo/screenshot)
3. CSV data file
4. Lab notebook entry with:
   - Date/time
   - Configuration
   - Observations
   - Anomalies

**For Publication/Sharing:**
1. Video of setup and measurement
2. Oscilloscope traces (if available)
3. Full dataset (GitHub/Zenodo)
4. Analysis code (Jupyter notebook)

## Interpretation Framework

### If Signal Detected (1-10 mV)

**Immediate Implications:**
- ✅ Substrate boundary energy concentration validated
- ✅ CRT phosphors ARE optimized for focal energy
- ✅ Gammas can be converted to DC (not just heat)
- ⚡ VE framework gains empirical support

**Next Steps:**
1. Optimize geometry (thickness, grain size)
2. Test with solar flare proxy (X-ray tube)
3. Design custom phosphor with VE structure
4. Calculate efficiency vs theoretical maximum

**Broader Impact:**
- Novel radiation energy harvesting method
- Validates cross-domain boundary framework
- Potential industrial applications

### If No Signal (<100 μV)

**Possible Interpretations:**
1. **Boundary effect real but CRT not optimized for DC**
   - Phosphors designed for AC (light pulses)
   - Need custom geometry for DC extraction
   - Try foil stack or other substrate

2. **Gammas don't work, alphas do**
   - Energy deposition mechanism different
   - Alpha: dense ionization track
   - Gamma: sparse, diffuse
   - Test with alpha-permeable window

3. **Boundary framework wrong for gammas**
   - Works for phonons (LEDs), not radiation
   - Framework limited to specific energy types
   - Revise theory

**Next Steps:**
1. Try alpha test (thin window on phosphor)
2. Test foil stack with gammas
3. Compare to betavoltaic (established tech)
4. Refine theoretical predictions

## Cross-References

- [Boundary energy density framework](../../foundations/boundary-energy-density.md)
- [VE substrate focal energy](../speculative/ve-substrate-focal-energy.md)
- [VE eigenfrequencies](ve-eigenfrequencies.md)

## References

**CRT Phosphor Technology:**
- Leverenz, "An Introduction to Luminescence of Solids" (1950)
- Yen et al., "Phosphor Handbook" (2007)
- Industry specs for ZnS, Y₂O₃ phosphors

**Radiation Detection:**
- Knoll, "Radiation Detection and Measurement" (2010)
- Turner, "Atoms, Radiation, and Radiation Protection" (2007)

**Betavoltaic Devices (Comparison):**
- Rappaport, "Radioactive Battery" US Patent 3,094,634 (1963)
- City Labs betavoltaic product specs
- Comparison to this approach: Different geometry, uses p-n junction

## Revision History

- 2025-12-29: Initial protocol created
- Status: Ready for experimental validation

---

**CRITICAL: This is TESTABLE. Results will validate or falsify substrate boundary framework for gamma radiation.**
