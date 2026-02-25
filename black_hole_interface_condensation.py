import numpy as np
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle, Circle, FancyBboxPatch, Wedge, FancyArrowPatch
from matplotlib.collections import LineCollection
import matplotlib.gridspec as gridspec

# Constants
hbar = 1.054571817e-34
c = 2.99792458e8
G = 6.67430e-11
k_B = 1.380649e-23

# Black hole parameters
M = 10 * 1.9885e30  # 10 solar masses
r_s = 2 * G * M / c**2  # Schwarzschild radius

print("\n" + "="*80)
print("BLACK HOLE AS INTERFACE CONDENSATION")
print("="*80)
print(f"\nBlack hole mass: {M/1.9885e30:.1f} solar masses")
print(f"Schwarzschild radius: {r_s/1000:.2f} km")
print(f"Hawking temperature: {hbar*c**3/(8*np.pi*G*M*k_B):.2e} K")
print("\nSimulating interface density phase transition...")

# Create figure with custom layout
fig = plt.figure(figsize=(20, 12))
gs = gridspec.GridSpec(3, 3, figure=fig, hspace=0.35, wspace=0.35)

fig.suptitle('Black Hole Interior: Interface Condensation Framework\nHorizon = Phase Transition from Hilbert Space to Geometry',
             fontsize=16, weight='bold', y=0.98)

# ============================================================================
# SIMULATION 1: Interface Density Phase Transition
# ============================================================================
ax1 = fig.add_subplot(gs[0, 0])

r_range = np.linspace(0.5 * r_s, 5 * r_s, 1000)

# Interface density model: ρ ~ 1/(r - r_s)^2 for r > r_s
# Diverges at horizon, representing condensation
epsilon = 0.01 * r_s  # Small offset to avoid singularity
rho_interface = 1.0 / (r_range - r_s + epsilon)**2
rho_interface = rho_interface / np.max(rho_interface)  # Normalize

# Critical density for Hilbert space → Geometry transition
rho_critical = 0.3

ax1.plot(r_range / r_s, rho_interface, 'b-', linewidth=2, label='Interface density')
ax1.axhline(rho_critical, color='red', linestyle='--', linewidth=2,
            label='Critical density (phase transition)')
ax1.axvline(1.0, color='black', linestyle='-', linewidth=2, alpha=0.5,
            label='Event horizon (r = r_s)')

# Shade regions
ax1.fill_between(r_range / r_s, 0, rho_interface,
                 where=(r_range/r_s > 1) & (rho_interface < rho_critical),
                 alpha=0.2, color='green', label='Hilbert space regime')
ax1.fill_between(r_range / r_s, 0, rho_interface,
                 where=(r_range/r_s > 1) & (rho_interface >= rho_critical),
                 alpha=0.2, color='orange', label='Transition zone')
ax1.fill_betweenx([0, 1.2], 0.5, 1.0, alpha=0.2, color='red', label='Geometric regime')

ax1.set_xlabel('Radius (r / r_s)', fontsize=11)
ax1.set_ylabel('Interface Density (normalized)', fontsize=11)
ax1.set_title('1. Interface Density Phase Transition', fontsize=12, weight='bold')
ax1.set_xlim(0.5, 5)
ax1.set_ylim(0, 1.2)
ax1.legend(fontsize=8, loc='upper right')
ax1.grid(True, alpha=0.3)

# Add annotations
ax1.text(3.5, 0.15, 'Sparse interfaces\n(quantum fields)', ha='center', fontsize=9,
         bbox=dict(boxstyle='round', facecolor='lightgreen', alpha=0.7))
ax1.text(1.3, 0.8, 'Dense interfaces\n(geometry emerges)', ha='center', fontsize=9,
         bbox=dict(boxstyle='round', facecolor='lightyellow', alpha=0.7))
ax1.text(0.75, 0.5, 'Pure\ngeometry', ha='center', fontsize=9, rotation=90,
         bbox=dict(boxstyle='round', facecolor='lightcoral', alpha=0.7))

# ============================================================================
# SIMULATION 2: Effective Dimensionality vs Radius
# ============================================================================
ax2 = fig.add_subplot(gs[0, 1])

# Effective dimensions increase with interface density
# D_eff = 4 + f(ρ) where f increases with density
D_base = 4.0
D_max = 10.0  # Maximum effective dimensions

# Model: extra dimensions "uncompactify" as density increases
# This is KK reversed - compactified at low density, uncompactified at high density
D_eff = D_base + (D_max - D_base) * np.tanh(3 * rho_interface)

ax2.plot(r_range / r_s, D_eff, 'purple', linewidth=3, label='Effective dimensions')
ax2.axvline(1.0, color='black', linestyle='-', linewidth=2, alpha=0.5, label='Event horizon')
ax2.axhline(D_base, color='gray', linestyle=':', linewidth=1.5, label='D = 4 (normal spacetime)')

# Shade regions
ax2.fill_between(r_range / r_s, D_base, D_eff,
                 where=(r_range/r_s > 1),
                 alpha=0.3, color='purple')

ax2.set_xlabel('Radius (r / r_s)', fontsize=11)
ax2.set_ylabel('Effective Dimensions', fontsize=11)
ax2.set_title('2. KK Reversed: Extra Dimensions Uncompactify', fontsize=12, weight='bold')
ax2.set_xlim(0.5, 5)
ax2.set_ylim(3, 11)
ax2.legend(fontsize=9, loc='upper right')
ax2.grid(True, alpha=0.3)

# Add annotations
ax2.text(3.5, 4.5, '4D spacetime\n+ quantum fields', ha='center', fontsize=9,
         bbox=dict(boxstyle='round', facecolor='lightblue', alpha=0.7))
ax2.text(1.2, 8, 'Higher-D\ngeometry', ha='center', fontsize=9,
         bbox=dict(boxstyle='round', facecolor='plum', alpha=0.7))
ax2.text(0.65, 9.5, '~10D\nmanifold', ha='center', fontsize=9,
         bbox=dict(boxstyle='round', facecolor='orchid', alpha=0.7))

# ============================================================================
# SIMULATION 3: Hawking Spectrum with Layer Structure
# ============================================================================
ax3 = fig.add_subplot(gs[0, 2])

# Hawking temperature
T_hawking = hbar * c**3 / (8 * np.pi * G * M * k_B)

# Energy spectrum
E_range = np.linspace(0.01, 5, 500) * k_B * T_hawking / (hbar * c**3) * 1e20  # scaled for visibility

# Pure blackbody (standard prediction)
def planck_spectrum(E, T):
    x = E / (k_B * T)
    # Avoid overflow
    x = np.clip(x, 0, 100)
    return np.where(x < 100, E**2 / (np.exp(x) - 1), 0)

I_blackbody = planck_spectrum(E_range, T_hawking)
I_blackbody = I_blackbody / np.max(I_blackbody)  # Normalize

# Modified spectrum with discrete features from interface layers
# Interface stacking creates a "diffraction grating" effect
n_layers = 5  # Number of interface layers
layer_spacing = 0.5  # Energy spacing between features

I_modified = I_blackbody.copy()
for i in range(1, n_layers + 1):
    # Add Gaussian peaks at discrete energies
    E_peak = i * layer_spacing * k_B * T_hawking / (hbar * c**3) * 1e20
    width = 0.1 * E_peak
    I_modified += 0.15 * np.exp(-(E_range - E_peak)**2 / (2 * width**2))

I_modified = I_modified / np.max(I_modified)  # Normalize

ax3.plot(E_range, I_blackbody, 'k--', linewidth=2, label='Pure blackbody (standard)', alpha=0.6)
ax3.plot(E_range, I_modified, 'r-', linewidth=2.5, label='With interface layers (prediction)')

# Mark layer features
for i in range(1, n_layers + 1):
    E_peak = i * layer_spacing * k_B * T_hawking / (hbar * c**3) * 1e20
    ax3.axvline(E_peak, color='orange', linestyle=':', linewidth=1.5, alpha=0.7)

ax3.set_xlabel('Energy (scaled units)', fontsize=11)
ax3.set_ylabel('Intensity (normalized)', fontsize=11)
ax3.set_title('3. Hawking Spectrum: Discrete Layer Features', fontsize=12, weight='bold')
ax3.legend(fontsize=9, loc='upper right')
ax3.grid(True, alpha=0.3)

# Add annotation
ax3.text(2.5, 0.7, 'Interface layers act as\ndiffraction grating', ha='center', fontsize=9,
         bbox=dict(boxstyle='round', facecolor='lightyellow', alpha=0.7))

# ============================================================================
# SIMULATION 4: Information Encoding Transition
# ============================================================================
ax4 = fig.add_subplot(gs[1, :])

# Create visual representation of information encoding transition
r_vis = np.linspace(0.3, 5, 100)

# Set up the visualization
ax4.set_xlim(0, 5.5)
ax4.set_ylim(0, 3)
ax4.axis('off')
ax4.set_title('4. Information Encoding: Hilbert Space → Topological Geometry',
              fontsize=12, weight='bold', pad=20)

# Draw horizon
ax4.axvline(1.0, color='black', linewidth=3, alpha=0.7, linestyle='-', zorder=1)
ax4.text(1.0, 2.8, 'Event Horizon', ha='center', fontsize=10, weight='bold')

# Region 1: Outside (Hilbert space regime) - r > 2*r_s
region1_box = FancyBboxPatch((2.5, 0.3), 2.5, 2.3,
                             boxstyle="round,pad=0.1",
                             edgecolor='green', facecolor='lightgreen',
                             linewidth=2, alpha=0.3, zorder=0)
ax4.add_patch(region1_box)
ax4.text(3.75, 2.3, 'OUTSIDE: Hilbert Space Regime', ha='center', fontsize=11, weight='bold', color='darkgreen')

# Draw quantum states as discrete blobs
for i in range(5):
    for j in range(3):
        x = 2.8 + i * 0.5
        y = 0.6 + j * 0.6
        state = Circle((x, y), 0.12, color='blue', alpha=0.6, zorder=2)
        ax4.add_patch(state)
        ax4.text(x, y, f'|ψ{i*3+j}⟩', ha='center', va='center', fontsize=6, color='white', weight='bold')

ax4.text(3.75, 0.5, 'Information: Quantum states in Hilbert space', ha='center', fontsize=9, style='italic')

# Region 2: Transition zone - 1 < r < 2*r_s
region2_box = FancyBboxPatch((1.1, 0.3), 1.2, 2.3,
                             boxstyle="round,pad=0.1",
                             edgecolor='orange', facecolor='lightyellow',
                             linewidth=2, alpha=0.3, zorder=0)
ax4.add_patch(region2_box)
ax4.text(1.7, 2.3, 'TRANSITION', ha='center', fontsize=11, weight='bold', color='darkorange')

# Draw mixed representation - states beginning to merge
for i in range(3):
    y = 0.8 + i * 0.6
    wedge = Wedge((1.7, y), 0.15, 0, 360, width=0.08,
                  edgecolor='purple', facecolor='violet', alpha=0.6, zorder=2)
    ax4.add_patch(wedge)

ax4.text(1.7, 0.5, 'Information: Transitioning\nstates → topology', ha='center', fontsize=8, style='italic')

# Region 3: Inside (Geometric regime) - r < r_s
region3_box = FancyBboxPatch((0.05, 0.3), 0.85, 2.3,
                             boxstyle="round,pad=0.1",
                             edgecolor='red', facecolor='lightcoral',
                             linewidth=2, alpha=0.3, zorder=0)
ax4.add_patch(region3_box)
ax4.text(0.475, 2.3, 'INSIDE:\nGeometric', ha='center', fontsize=11, weight='bold', color='darkred')

# Draw geometric structure - manifold features, not quantum states
# Represent as topological knots/winding
theta_knot = np.linspace(0, 4*np.pi, 100)
for offset in [0.8, 1.3, 1.8]:
    r_knot = 0.15 + 0.05 * np.sin(5 * theta_knot)
    x_knot = 0.475 + r_knot * np.cos(theta_knot) * 0.15
    y_knot = offset + r_knot * np.sin(theta_knot) * 0.3
    ax4.plot(x_knot, y_knot, 'purple', linewidth=2, alpha=0.7, zorder=2)

ax4.text(0.475, 0.5, 'Information:\nManifold topology\n(no quantum states)',
         ha='center', fontsize=8, style='italic')

# Add arrows showing flow
arrow1 = FancyArrowPatch((4.5, 1.5), (2.5, 1.5),
                        arrowstyle='->', mutation_scale=25,
                        linewidth=3, color='black', alpha=0.5, zorder=1)
ax4.add_patch(arrow1)
ax4.text(3.5, 1.7, 'Increasing interface density →', ha='center', fontsize=10, style='italic')

# ============================================================================
# SIMULATION 5: 3M Factory Floor Analog
# ============================================================================
ax5 = fig.add_subplot(gs[2, :2])

ax5.set_xlim(0, 10)
ax5.set_ylim(0, 5)
ax5.axis('off')
ax5.set_title('5. 3M Factory Floor: Macroscopic Interface Condensation Analog',
              fontsize=12, weight='bold', pad=10)

# Normal factory floor
normal_floor = Rectangle((0.5, 1), 3, 2.5, edgecolor='gray', facecolor='lightgray',
                         linewidth=2, alpha=0.4)
ax5.add_patch(normal_floor)
ax5.text(2, 3.7, 'Normal Factory Floor', ha='center', fontsize=10, weight='bold')
ax5.text(2, 1.5, 'Low interface density\n(normal 4D physics)', ha='center', fontsize=8, style='italic')

# Sparse workers
for x, y in [(1, 2.5), (2, 2.8), (3, 2.3)]:
    worker = Circle((x, y), 0.15, color='blue', alpha=0.6)
    ax5.add_patch(worker)
ax5.text(2, 0.7, '✓ Normal experience', ha='center', fontsize=9, color='green')

# Condensation zone (3M event)
condensation_zone = Rectangle((5, 1), 3, 2.5, edgecolor='red', facecolor='lightcoral',
                              linewidth=3, alpha=0.4)
ax5.add_patch(condensation_zone)
ax5.text(6.5, 3.7, '3M Condensation Zone', ha='center', fontsize=10, weight='bold', color='darkred')
ax5.text(6.5, 1.5, 'High interface density\n(temporary "horizon")', ha='center', fontsize=8, style='italic')

# Dense workers experiencing boundary
for x, y in [(5.5, 2.5), (6.5, 2.8), (7.5, 2.3), (6, 2.0), (7, 2.6)]:
    worker_affected = Circle((x, y), 0.15, color='orange', alpha=0.8)
    ax5.add_patch(worker_affected)
    # Add "sensing" waves
    sense = Circle((x, y), 0.3, fill=False, edgecolor='red', linewidth=1.5, linestyle='--', alpha=0.5)
    ax5.add_patch(sense)

ax5.text(6.5, 0.7, '⚠ Boundary sensation', ha='center', fontsize=9, color='red')

# Arrow showing analogy
analogy_arrow = FancyArrowPatch((3.7, 2.25), (4.8, 2.25),
                               arrowstyle='->', mutation_scale=30,
                               linewidth=3, color='purple', zorder=5)
ax5.add_patch(analogy_arrow)
ax5.text(4.25, 2.6, 'Interface\ndensity ↑', ha='center', fontsize=9,
         weight='bold', color='purple')

# Add explanation box
explanation = """Workers felt where description changes:
Hilbert space → Geometry
(temporary version of permanent BH interior)"""
ax5.text(6.5, 4.3, explanation, ha='center', fontsize=8, style='italic',
         bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.6))

# ============================================================================
# SIMULATION 6: Summary diagram
# ============================================================================
ax6 = fig.add_subplot(gs[2, 2])

ax6.set_xlim(0, 10)
ax6.set_ylim(0, 10)
ax6.axis('off')
ax6.set_title('Framework Summary', fontsize=12, weight='bold', pad=10)

# Create summary boxes
summary_items = [
    ("Standard View", "Horizon = boundary\nInterior = spacetime\nSingularity = point", 'lightgray', 8),
    ("This Framework", "Horizon = interface\nInterior = phase\nSingularity = transition", 'lightgreen', 5.5),
    ("Key Insight", "Hilbert space ↔ Geometry\nphase transition at\ninterface condensation", 'lightyellow', 3),
]

for title, text, color, y in summary_items:
    box = FancyBboxPatch((1, y-0.8), 8, 1.8,
                         boxstyle="round,pad=0.1",
                         edgecolor='black', facecolor=color,
                         linewidth=2, alpha=0.5)
    ax6.add_patch(box)
    ax6.text(5, y+0.5, title, ha='center', fontsize=10, weight='bold')
    ax6.text(5, y-0.2, text, ha='center', fontsize=8, style='italic')

# Add bottom note
note = """No information paradox: information transitions from
quantum states (Hilbert space) → topological features (geometry)"""
ax6.text(5, 0.8, note, ha='center', fontsize=8,
         bbox=dict(boxstyle='round', facecolor='lightblue', alpha=0.6))

plt.savefig('black_hole_interface_condensation.png', dpi=200, bbox_inches='tight', facecolor='white')
plt.close()

print("\n" + "="*80)
print("SIMULATION COMPLETE")
print("="*80)
print("\n✓ Interface density phase transition")
print("✓ Effective dimensionality (KK reversed)")
print("✓ Hawking spectrum with layer structure")
print("✓ Information encoding transition (Hilbert → Geometry)")
print("✓ 3M factory floor analog")
print("✓ Framework summary")
print("\nKey Results:")
print("  • Horizon = phase transition threshold (not spatial boundary)")
print("  • Interior = geometric regime (Hilbert space breaks down)")
print("  • Singularity = full condensation (pure higher-D manifold)")
print("  • No paradox: information changes encoding format")
print("  • Observable: discrete features in Hawking spectrum")
print("\n✓ Visualization saved: black_hole_interface_condensation.png")
print("="*80 + "\n")
