"""
Interface Calculus — Interface Physics Simulator
=================================================
Runs on CPU (numpy) with a TPU/GPU upgrade path via JAX.

Models the plasma boundary layer as a 1D advection-diffusion system:

  ∂φ/∂t = -u ∂φ/∂x + D ∂²φ/∂x²

where:
  φ(x,t)  — interface density field (dimensionless)
  u        — advection velocity (proxy: voltage_V)
  D        — diffusion coefficient (proxy: temp-dependent, scales with T_K)

The Reynolds number governs the ratio u/D·L — when Re > threshold the
interface becomes turbulent and φ develops sharp gradients ("the wall").

Optional JAX path:
  pip install jax jaxlib
  Set USE_JAX=1 in environment.

Usage (standalone test):
  python3 tpu_sim.py
"""

import os
import math
import time

USE_JAX = os.getenv("USE_JAX", "0") == "1"

if USE_JAX:
    try:
        import jax.numpy as jnp
        import jax
        _xp = jnp
        print("[tpu_sim] JAX backend active")
    except ImportError:
        USE_JAX = False
        import numpy as jnp
        _xp = jnp
        print("[tpu_sim] JAX not found, using numpy")
else:
    import numpy as _xp

import numpy as np   # always available for I/O

# ── Grid ─────────────────────────────────────────────────────────────────────

NX      = 64          # spatial grid points
L_GRID  = 0.01        # physical length (metres) — matches L_CHAR in aggregator
DX      = L_GRID / NX
DT      = 1e-4        # simulation timestep (seconds)
STEPS   = 50          # steps per aggregator call (~5ms of simulated time)

# ── Simulator ────────────────────────────────────────────────────────────────

class InterfaceSimulator:
    """
    1D finite-difference advection-diffusion of the interface density field.
    Re-initialised if the node restarts; state persists across sensor packets.
    """

    def __init__(self):
        self.phi = np.ones(NX) * 0.5   # start at half-density
        self.t   = 0.0
        self.history_reynolds: list = []
        self.history_phi_max:  list = []
        self._step_count = 0

    def _diffusion_coeff(self, temp_C: float) -> float:
        """
        Temperature-dependent diffusion (Arrhenius-like).
        Higher T → looser interface → higher D → more stable (lower Re).
        """
        T_K = max(temp_C + 273.15, 200.0)
        D_ref  = 1e-5
        E_over_R = 500.0   # effective activation energy / R  [K]
        return D_ref * math.exp(-E_over_R / T_K)

    def _advection_velocity(self, voltage_V: float, current_mA: float) -> float:
        """
        Interface "flow" velocity — driven by electric field (V/L) and
        scaled by current (charge carrier density proxy).
        """
        E_field = voltage_V / L_GRID           # V/m
        I_A     = current_mA / 1000.0
        return min(E_field * 1e-6 * (1 + I_A), 1.0)   # clip to physical range

    def step(
        self,
        voltage_V:  float,
        current_mA: float,
        temp_C:     float,
        reynolds:   float,
    ) -> dict:
        """
        Advance the simulation STEPS timesteps and return summary metrics.
        """
        u = self._advection_velocity(voltage_V, current_mA)
        D = self._diffusion_coeff(temp_C)

        phi = self.phi.copy()

        for _ in range(STEPS):
            # Upwind scheme for advection (stability: CFL ≤ 1)
            dphi_adv = np.zeros(NX)
            if u >= 0:
                dphi_adv[1:] = (phi[1:] - phi[:-1]) / DX
            else:
                dphi_adv[:-1] = (phi[1:] - phi[:-1]) / DX

            # Central difference for diffusion
            dphi_diff = np.zeros(NX)
            dphi_diff[1:-1] = (phi[2:] - 2 * phi[1:-1] + phi[:-2]) / DX**2

            # Boundary conditions: Neumann (zero flux)
            dphi_diff[0]  = dphi_diff[1]
            dphi_diff[-1] = dphi_diff[-2]

            phi = phi + DT * (-u * dphi_adv + D * dphi_diff)

            # Inject turbulent forcing when Re > threshold
            if reynolds > 2300:
                noise_amp = 0.05 * (reynolds / 2300 - 1.0)
                phi += np.random.randn(NX) * noise_amp * DT

            # Clip to physical range [0, 1]
            phi = np.clip(phi, 0.0, 1.0)

        self.phi = phi
        self.t  += STEPS * DT
        self._step_count += STEPS

        phi_max  = float(np.max(phi))
        phi_mean = float(np.mean(phi))
        phi_std  = float(np.std(phi))
        gradient = float(np.max(np.abs(np.diff(phi)))) / DX   # max spatial gradient

        # Wall signature: sharp gradient near midpoint
        mid = NX // 2
        wall_strength = float(np.max(np.abs(np.diff(phi[mid-5:mid+5])))) / DX

        self.history_reynolds.append(reynolds)
        self.history_phi_max.append(phi_max)

        # Keep history bounded
        if len(self.history_reynolds) > 200:
            self.history_reynolds.pop(0)
            self.history_phi_max.pop(0)

        return {
            "sim_t_s":       round(self.t, 6),
            "phi_max":       round(phi_max,     4),
            "phi_mean":      round(phi_mean,    4),
            "phi_std":       round(phi_std,     4),
            "max_gradient":  round(gradient,    2),
            "wall_strength": round(wall_strength, 2),
            "u":             round(u, 6),
            "D":             round(D, 8),
            "step_count":    self._step_count,
        }

    def reset(self):
        """Re-initialise field — call after 'reset' decision from Groq."""
        self.phi = np.ones(NX) * 0.5
        self.t   = 0.0
        self._step_count = 0
        print("[tpu_sim] Field reset to uniform 0.5")

    @property
    def field(self) -> list:
        return self.phi.tolist()


# ── Standalone test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    sim = InterfaceSimulator()
    print("Interface Simulator — standalone test")
    print(f"Grid: {NX} pts over {L_GRID*100:.1f} cm | dt={DT} s | {STEPS} steps/call")
    print()

    scenarios = [
        (1.0,  10.0, 25.0,  500.0,  "laminar"),
        (2.5,  50.0, 45.0, 1500.0,  "transitional"),
        (5.0, 200.0, 70.0, 3000.0,  "turbulent"),
    ]

    for V, I, T, Re, label in scenarios:
        t0 = time.perf_counter()
        result = sim.step(V, I, T, Re)
        dt_ms  = (time.perf_counter() - t0) * 1000
        print(f"[{label:13s}] Re={Re:.0f} | wall={result['wall_strength']:.2f} | "
              f"phi_std={result['phi_std']:.4f} | sim_t={result['sim_t_s']:.4f}s | "
              f"compute={dt_ms:.1f}ms")
