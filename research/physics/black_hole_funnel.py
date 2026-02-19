import numpy as np
import matplotlib.pyplot as plt

# Constants
hbar = 1.054571817e-34
c = 2.99792458e8
G = 6.67430e-11
k_B = 1.380649e-23

class BlackHoleFunnel:
    def __init__(self, M):
        self.M = M
        self.r_s = 2 * G * M / c**2  # Schwarzschild radius

    def geometry_factor(self, r):
        """Spacetime curvature concentration near horizon"""
        return 1 / (1 - self.r_s / r)**2 if r > self.r_s else np.inf

    def flux_concentration(self):
        """Energy flux per unit area at horizon ~ 1/M"""
        return c**4 / (G * self.M)

    def substrate_coupling(self):
        """Planck-scale quantum coupling"""
        return hbar * c**3 / (G * k_B)

    def hawking_temp(self):
        """T = (flux × substrate) / (geometry × boundary)"""
        flux = self.flux_concentration()
        coupling = self.substrate_coupling()
        boundary_area = 4 * np.pi * self.r_s**2

        # Funnel formula: concentration at boundary
        T = (flux * hbar) / (8 * np.pi * G * self.M * k_B)
        return T

    def energy_flux_profile(self, r_array):
        """Energy density as function of radius"""
        return np.array([self.geometry_factor(r) * self.flux_concentration()
                        for r in r_array])

# Compare black hole masses
M_sun = 1.9885e30
M_stellar = 10 * M_sun
M_micro = 1e-8  # kg (microscopic black hole)

holes = [
    ("Solar mass", BlackHoleFunnel(M_sun)),
    ("10 solar", BlackHoleFunnel(M_stellar)),
    ("Microscopic", BlackHoleFunnel(M_micro))
]

print("Black Hole Funnel Analysis")
print("="*50)
for name, bh in holes:
    T = bh.hawking_temp()
    print(f"{name:15s} | M={bh.M:.2e} kg | r_s={bh.r_s:.2e} m | T={T:.2e} K")

# Visualize funnel concentration
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

# Left: flux concentration vs radius for different masses
for name, bh in holes:
    r_array = np.linspace(bh.r_s * 1.01, bh.r_s * 10, 100)
    flux = bh.energy_flux_profile(r_array)
    ax1.plot(r_array / bh.r_s, flux / flux[0], label=name)

ax1.set_xlabel("r / r_s (Schwarzschild radii)")
ax1.set_ylabel("Normalized Energy Flux")
ax1.set_yscale('log')
ax1.set_title("Funnel Concentration Near Horizon")
ax1.legend()
ax1.grid(True, alpha=0.3)

# Right: Hawking temp vs mass (funnel scaling)
masses = np.logspace(20, 35, 50)
temps = [BlackHoleFunnel(m).hawking_temp() for m in masses]

ax2.plot(masses / M_sun, temps)
ax2.set_xscale('log')
ax2.set_yscale('log')
ax2.set_xlabel("Mass (solar masses)")
ax2.set_ylabel("Hawking Temperature (K)")
ax2.set_title("T ~ 1/M (Funnel Scaling Law)")
ax2.grid(True, alpha=0.3)

plt.tight_layout()
plt.savefig('black_hole_funnel.png', dpi=150, bbox_inches='tight')
plt.close()

print("\n✓ Visualization saved")
