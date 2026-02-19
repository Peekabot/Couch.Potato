#!/usr/bin/env python3
"""
Software Detective Quantum Efficiency (DQE) - Timing-Based Bot Filter

Multi-stage passive filter. Each stage applies a frequency-domain threshold
to inter-request timing. Human sessions percolate through; bot sessions attenuate.

No explicit classification. Bots self-select out via the timing boundary.

See: theories/SOFTWARE_DQE.md

Usage:
    python3 software_dqe.py                  # run built-in test
    python3 software_dqe.py --timestamps t1,t2,t3,...   # analyze real timestamps (unix epoch floats)
"""

import sys
import numpy as np
import json
import argparse
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Core DQE stages
# ---------------------------------------------------------------------------

@dataclass
class Stage:
    name: str
    center_freq: float   # Hz — expected dominant human timing frequency
    bandwidth: float     # Hz — pass-band (1-sigma of Gaussian)
    noise_floor: float   # minimum denominator for SNR calculation

    def snr(self, freqs: np.ndarray, power: np.ndarray) -> float:
        H = np.exp(-0.5 * ((freqs - self.center_freq) / self.bandwidth) ** 2)
        signal = float(np.sum(power * H))
        return signal / (self.noise_floor + 1e-12)

    def passes(self, freqs: np.ndarray, power: np.ndarray) -> bool:
        return self.snr(freqs, power) > 1.0


# Three stages at different timescales.
# Human timing is noisy across all three; bots typically fail at least one.
STAGES = [
    Stage("inter_request",  center_freq=0.3,  bandwidth=0.4,  noise_floor=1e3),
    Stage("interaction",    center_freq=2.5,  bandwidth=2.5,  noise_floor=5e2),
    Stage("session_burst",  center_freq=0.02, bandwidth=0.03, noise_floor=1e2),
]


# ---------------------------------------------------------------------------
# Analyser
# ---------------------------------------------------------------------------

def analyze(timestamps: list[float], stages: list[Stage] = STAGES) -> dict:
    """
    Analyse a sequence of request timestamps.

    Returns a dict with:
        passed      : bool — did the session pass all stages?
        stage_snrs  : {stage_name: float}
        dominant_hz : float — dominant inter-arrival frequency
        n_requests  : int
        cdq_product : float — product of all stage SNRs (overall DQE score)
    """
    ts = np.sort(timestamps)
    if len(ts) < 4:
        return {"error": "Need at least 4 timestamps", "passed": False}

    iat = np.diff(ts)                                        # inter-arrival times (seconds)
    mean_iat = float(np.mean(iat))
    if mean_iat <= 0:
        return {"error": "Zero mean inter-arrival time", "passed": False}

    freqs = np.fft.rfftfreq(len(iat), d=mean_iat)
    power = np.abs(np.fft.rfft(iat)) ** 2

    # Dominant frequency (skip DC bin 0)
    dominant_hz = float(freqs[np.argmax(power[1:]) + 1]) if len(freqs) > 1 else 0.0

    stage_snrs = {}
    passed_all = True
    dqe_product = 1.0

    for s in stages:
        snr_val = s.snr(freqs, power)
        stage_snrs[s.name] = round(snr_val, 4)
        dqe_product *= snr_val
        if snr_val <= 1.0:
            passed_all = False

    return {
        "passed": passed_all,
        "stage_snrs": stage_snrs,
        "dqe_product": round(dqe_product, 6),
        "dominant_hz": round(dominant_hz, 4),
        "n_requests": len(ts),
        "mean_iat_sec": round(mean_iat, 3),
    }


# ---------------------------------------------------------------------------
# Synthetic traffic generators
# ---------------------------------------------------------------------------

def gen_human(n=40, seed=42) -> np.ndarray:
    """Human-like: Poisson inter-arrivals, 1–8 second mean, occasional bursts."""
    rng = np.random.default_rng(seed)
    iats = rng.exponential(scale=3.0, size=n)
    iats += rng.normal(0, 0.3, size=n)               # motor noise
    iats = np.clip(iats, 0.05, 60.0)
    return np.cumsum(iats)


def gen_bot_regular(n=40, interval=0.5, seed=42) -> np.ndarray:
    """Bot: near-perfectly regular intervals — classic scraper pattern."""
    rng = np.random.default_rng(seed)
    iats = np.full(n, interval) + rng.normal(0, 0.005, size=n)
    return np.cumsum(np.clip(iats, 0.001, None))


def gen_bot_fast(n=40, seed=42) -> np.ndarray:
    """Bot: very fast, sub-100ms intervals — aggressive crawler."""
    rng = np.random.default_rng(seed)
    iats = rng.exponential(scale=0.05, size=n)
    return np.cumsum(np.clip(iats, 0.001, None))


def gen_human_behind_cdn(n=40, cdn_jitter_ms=30, seed=42) -> np.ndarray:
    """Human traffic with CDN-added jitter. Tests whether filter survives."""
    rng = np.random.default_rng(seed)
    ts = gen_human(n, seed)
    jitter = rng.normal(0, cdn_jitter_ms / 1000.0, size=n)
    return np.sort(ts + jitter)


def gen_bot_behind_cdn(n=40, interval=0.5, cdn_jitter_ms=30, seed=42) -> np.ndarray:
    """Regular bot with CDN jitter added. Does jitter disguise it?"""
    rng = np.random.default_rng(seed)
    ts = gen_bot_regular(n, interval, seed)
    jitter = rng.normal(0, cdn_jitter_ms / 1000.0, size=n)
    return np.sort(ts + jitter)


# ---------------------------------------------------------------------------
# Test suite
# ---------------------------------------------------------------------------

def run_tests():
    cases = [
        ("Human (clean)",           gen_human(),                                True),
        ("Bot: regular 500ms",      gen_bot_regular(),                          False),
        ("Bot: fast crawler",       gen_bot_fast(),                             False),
        ("Human + CDN jitter 30ms", gen_human_behind_cdn(cdn_jitter_ms=30),     True),
        ("Bot + CDN jitter 30ms",   gen_bot_behind_cdn(cdn_jitter_ms=30),       False),
        ("Bot + CDN jitter 200ms",  gen_bot_behind_cdn(cdn_jitter_ms=200),      None),  # unclear — the critical test
    ]

    print("=" * 70)
    print("Software DQE — Timing Filter Test")
    print("=" * 70)

    results = []
    for label, ts, expected in cases:
        r = analyze(ts.tolist())
        passed = r.get("passed", False)
        status = "PASS" if passed else "FAIL"
        correct = "✓" if expected is None else ("✓" if passed == expected else "✗")
        snrs = r.get("stage_snrs", {})
        snr_str = " | ".join(f"{k}: {v:.2f}" for k, v in snrs.items())
        print(f"\n[{correct}] {label}")
        print(f"    Result: {status}  DQE={r.get('dqe_product', 0):.4f}  "
              f"dominant_freq={r.get('dominant_hz', 0):.3f}Hz")
        print(f"    Stage SNRs: {snr_str}")
        results.append((label, passed, expected))

    print("\n" + "=" * 70)

    # CDN robustness sweep: at what jitter level does bot detection break?
    print("\nCDN Robustness Sweep — bot (500ms regular) + increasing jitter")
    print(f"{'Jitter (ms)':<15} {'Bot passes filter':<20} {'DQE product'}")
    print("-" * 55)
    for jitter_ms in [0, 10, 30, 50, 100, 150, 200, 300, 500]:
        ts = gen_bot_behind_cdn(cdn_jitter_ms=jitter_ms)
        r = analyze(ts.tolist())
        passes = r.get("passed", False)
        dqe = r.get("dqe_product", 0)
        flag = "  <-- bot disguised" if passes else ""
        print(f"{jitter_ms:<15} {str(passes):<20} {dqe:.4f}{flag}")

    print("\n" + "=" * 70)
    print("Interpretation:")
    print("  If bot is disguised only at CDN jitter >> human inter-request variance,")
    print("  the framework has teeth. Check 'dominant_hz' for bots — should be")
    print("  a sharp spike vs. broad noise for humans.")
    print("=" * 70)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Software DQE timing filter")
    parser.add_argument("--timestamps", type=str, default=None,
                        help="Comma-separated unix epoch timestamps (float seconds)")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")
    args = parser.parse_args()

    if args.timestamps:
        try:
            ts = [float(x.strip()) for x in args.timestamps.split(",")]
        except ValueError:
            print("Error: timestamps must be comma-separated floats", file=sys.stderr)
            sys.exit(1)
        result = analyze(ts)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"Passed: {result['passed']}")
            print(f"DQE product: {result.get('dqe_product')}")
            print(f"Stage SNRs: {result.get('stage_snrs')}")
            print(f"Dominant freq: {result.get('dominant_hz')} Hz")
    else:
        run_tests()


if __name__ == "__main__":
    main()
