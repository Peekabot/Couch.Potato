import numpy as np
import matplotlib.pyplot as plt
from matplotlib.patches import Circle, FancyArrowPatch, Wedge
from matplotlib.collections import LineCollection
import matplotlib.patches as mpatches

# Constants
hbar = 1.054571817e-34
c = 2.99792458e8
G = 6.67430e-11
k_B = 1.380649e-23
e = 1.602176634e-19

fig, axes = plt.subplots(1, 3, figsize=(18, 6))
fig.suptitle('Universal Funnel Mechanism: Three Systems, Same Pattern',
             fontsize=16, weight='bold', y=0.98)

# ============================================================================
# SIMULATION 1: LED - Electrical → Optical (Triplet Energy Transfer)
# ============================================================================
ax1 = axes[0]
ax1.set_xlim(-2, 2)
ax1.set_ylim(-1, 4)
ax1.set_aspect('equal')
ax1.axis('off')
ax1.set_title('LED Funnel: Electrical → Optical\n(Cambridge 2025)',
              fontsize=12, weight='bold', pad=10)

# Flux: electrons and holes coming in
for i, (x, label, color) in enumerate([(-1.5, 'e⁻', 'blue'), (1.5, 'h⁺', 'red')]):
    # Incoming charges (flux)
    for j in range(3):
        y = 3.5 - j*0.3
        ax1.add_patch(Circle((x, y), 0.08, color=color, alpha=0.7, zorder=3))
    ax1.text(x, 3.9, label + ' flux', ha='center', fontsize=8, color=color, weight='bold')

# Substrate: Organic molecule (9-ACA antenna)
organic = mpatches.FancyBboxPatch((-0.8, 1.5), 1.6, 0.6,
                                  boxstyle="round,pad=0.05",
                                  edgecolor='green', facecolor='lightgreen',
                                  linewidth=2, alpha=0.4, zorder=1)
ax1.add_patch(organic)
ax1.text(0, 1.8, 'Organic Antenna\n(9-ACA)', ha='center', fontsize=9,
         weight='bold', color='darkgreen')

# Concentration: Triplet exciton formation
triplet_region = Wedge((0, 1.8), 0.5, 0, 360, width=0.15,
                       edgecolor='orange', facecolor='yellow',
                       linewidth=2, alpha=0.6, zorder=2)
ax1.add_patch(triplet_region)
ax1.text(0, 1.3, 'Triplet\nConcentration', ha='center', fontsize=8,
         style='italic', color='darkorange')

# Energy transfer arrows (98% efficient!)
arrow1 = FancyArrowPatch((-1.2, 3.2), (-0.5, 2.2),
                        arrowstyle='->', mutation_scale=15,
                        linewidth=2, color='blue', zorder=2)
ax1.add_patch(arrow1)
arrow2 = FancyArrowPatch((1.2, 3.2), (0.5, 2.2),
                        arrowstyle='->', mutation_scale=15,
                        linewidth=2, color='red', zorder=2)
ax1.add_patch(arrow2)

# Reaction: Lanthanide nanoparticle emission
lanthanide = Circle((0, 0.3), 0.35, edgecolor='purple',
                    facecolor='violet', linewidth=2, alpha=0.5, zorder=2)
ax1.add_patch(lanthanide)
ax1.text(0, 0.3, 'LnNP', ha='center', fontsize=10, weight='bold', color='darkviolet')

# Dexter transfer
dexter_arrow = FancyArrowPatch((0, 1.3), (0, 0.7),
                              arrowstyle='->', mutation_scale=20,
                              linewidth=3, color='orange',
                              linestyle='--', zorder=2)
ax1.add_patch(dexter_arrow)
ax1.text(0.4, 1.0, '98% TET', fontsize=8, weight='bold', color='orange')

# Output: Near-IR photons
for i in range(4):
    angle = i * np.pi / 2
    x_end = 0.7 * np.cos(angle)
    y_end = 0.3 + 0.7 * np.sin(angle)
    photon_arrow = FancyArrowPatch((0, 0.3), (x_end, y_end),
                                   arrowstyle='->', mutation_scale=12,
                                   linewidth=2, color='red',
                                   alpha=0.7, zorder=3)
    ax1.add_patch(photon_arrow)

ax1.text(0, -0.5, 'Near-IR Light', ha='center', fontsize=10,
         weight='bold', color='red')

# Pattern annotation
ax1.text(0, -0.9, 'Flux→Substrate→Concentration→Reaction',
         ha='center', fontsize=8, style='italic',
         bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))

# ============================================================================
# SIMULATION 2: Black Hole - Gravitational → Thermal
# ============================================================================
ax2 = axes[1]
ax2.set_xlim(-2, 2)
ax2.set_ylim(-1, 4)
ax2.set_aspect('equal')
ax2.axis('off')
ax2.set_title('Black Hole Funnel: Gravitational → Thermal\n(Hawking 1974)',
              fontsize=12, weight='bold', pad=10)

# Flux: spacetime curvature (represented as field lines)
theta = np.linspace(0, 2*np.pi, 12)
for t in theta:
    r_start = 2.0
    x_start = r_start * np.cos(t)
    y_start = 2.0 + r_start * np.sin(t)

    r_end = 0.6
    x_end = r_end * np.cos(t)
    y_end = 2.0 + r_end * np.sin(t)

    ax2.plot([x_start, x_end], [y_start, y_end],
            'b-', alpha=0.4, linewidth=1.5)

ax2.text(0, 3.8, 'Curvature flux', ha='center', fontsize=8,
         color='blue', weight='bold')

# Substrate: Quantum vacuum (spacetime itself)
vacuum_region = Circle((0, 2.0), 1.2, edgecolor='green',
                       facecolor='lightgreen', linewidth=2,
                       alpha=0.3, linestyle='--', zorder=1)
ax2.add_patch(vacuum_region)
ax2.text(0, 3.3, 'Quantum Vacuum\n(Spacetime)', ha='center',
         fontsize=9, weight='bold', color='darkgreen')

# Concentration: Event horizon (geometric funnel)
horizon = Circle((0, 2.0), 0.5, edgecolor='red', facecolor='black',
                linewidth=3, alpha=0.8, zorder=2)
ax2.add_patch(horizon)
ax2.text(0, 2.0, 'r_s', ha='center', fontsize=10,
         weight='bold', color='white')

# Funnel geometry
ax2.text(0, 1.3, 'Event Horizon\nFunnel', ha='center', fontsize=8,
         style='italic', color='darkred')

# Singularity
singularity = Circle((0, 2.0), 0.05, color='white', zorder=3)
ax2.add_patch(singularity)

# Reaction: Hawking radiation (thermal photons)
for i in range(6):
    angle = i * np.pi / 3
    x_start = 0.6 * np.cos(angle)
    y_start = 2.0 + 0.6 * np.sin(angle)
    x_end = 1.3 * np.cos(angle)
    y_end = 2.0 + 1.3 * np.sin(angle)

    radiation = FancyArrowPatch((x_start, y_start), (x_end, y_end),
                               arrowstyle='->', mutation_scale=12,
                               linewidth=2, color='orange',
                               alpha=0.8, zorder=3)
    ax2.add_patch(radiation)

ax2.text(0, 0.5, 'Hawking Radiation', ha='center', fontsize=10,
         weight='bold', color='orange')

# Temperature scaling
ax2.text(0, 0.0, r'$T \sim \frac{1}{M}$', ha='center', fontsize=11,
         bbox=dict(boxstyle='round', facecolor='yellow', alpha=0.5))

# Pattern annotation
ax2.text(0, -0.6, 'Flux→Substrate→Concentration→Reaction',
         ha='center', fontsize=8, style='italic',
         bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))

# ============================================================================
# SIMULATION 3: Fusion - Kinetic → Nuclear
# ============================================================================
ax3 = axes[2]
ax3.set_xlim(-2, 2)
ax3.set_ylim(-1, 4)
ax3.set_aspect('equal')
ax3.axis('off')
ax3.set_title('Fusion Funnel: Kinetic → Nuclear\n(Deuterium-Deuterium)',
              fontsize=12, weight='bold', pad=10)

# Flux: Two deuterium nuclei approaching
d1_positions = [(-1.5, 3.5), (-1.2, 3.2), (-0.9, 2.9)]
d2_positions = [(1.5, 3.5), (1.2, 3.2), (0.9, 2.9)]

for i, (pos1, pos2) in enumerate(zip(d1_positions, d2_positions)):
    alpha = 0.3 + i * 0.3
    ax3.add_patch(Circle(pos1, 0.12, color='red', alpha=alpha, zorder=2))
    ax3.add_patch(Circle(pos2, 0.12, color='red', alpha=alpha, zorder=2))
    ax3.text(pos1[0], pos1[1], 'D', ha='center', va='center',
            fontsize=7, weight='bold', color='white')
    ax3.text(pos2[0], pos2[1], 'D', ha='center', va='center',
            fontsize=7, weight='bold', color='white')

ax3.text(-1.5, 3.9, 'D flux →', ha='center', fontsize=8,
        color='red', weight='bold')
ax3.text(1.5, 3.9, '← D flux', ha='center', fontsize=8,
        color='red', weight='bold')

# Substrate: Electron screening (plasma)
plasma_region = Circle((0, 2.0), 1.0, edgecolor='green',
                      facecolor='lightgreen', linewidth=2,
                      alpha=0.3, linestyle='--', zorder=1)
ax3.add_patch(plasma_region)
ax3.text(0, 3.2, 'Electron Cloud\n(Plasma Screening)', ha='center',
        fontsize=9, weight='bold', color='darkgreen')

# Draw electron cloud
n_electrons = 20
for i in range(n_electrons):
    angle = i * 2 * np.pi / n_electrons
    r = 0.8
    x = r * np.cos(angle)
    y = 2.0 + r * np.sin(angle)
    ax3.add_patch(Circle((x, y), 0.05, color='blue', alpha=0.5, zorder=1))

# Concentration: Coulomb barrier penetration
barrier = Wedge((0, 2.0), 0.6, 0, 360, width=0.2,
               edgecolor='orange', facecolor='yellow',
               linewidth=2, alpha=0.5, zorder=2)
ax3.add_patch(barrier)
ax3.text(0, 1.2, 'Coulomb Barrier\nTunneling', ha='center', fontsize=8,
        style='italic', color='darkorange')

# Approaching nuclei at barrier
ax3.add_patch(Circle((-0.3, 2.0), 0.15, color='red',
                    edgecolor='darkred', linewidth=2, zorder=3))
ax3.add_patch(Circle((0.3, 2.0), 0.15, color='red',
                    edgecolor='darkred', linewidth=2, zorder=3))
ax3.text(-0.3, 2.0, 'D', ha='center', va='center',
        fontsize=8, weight='bold', color='white')
ax3.text(0.3, 2.0, 'D', ha='center', va='center',
        fontsize=8, weight='bold', color='white')

# Reaction: Fusion products
fusion_region = Circle((0, 0.5), 0.25, edgecolor='purple',
                      facecolor='violet', linewidth=2, alpha=0.6, zorder=2)
ax3.add_patch(fusion_region)
ax3.text(0, 0.5, '³He', ha='center', va='center',
        fontsize=9, weight='bold', color='white')

# Neutron emission
neutron = FancyArrowPatch((0, 0.5), (1.2, 0.5),
                         arrowstyle='->', mutation_scale=15,
                         linewidth=3, color='green', zorder=3)
ax3.add_patch(neutron)
ax3.text(1.4, 0.5, 'n', ha='left', fontsize=10,
        weight='bold', color='green')

# Energy release
ax3.text(0, 0.0, 'E = 3.27 MeV', ha='center', fontsize=10,
        bbox=dict(boxstyle='round', facecolor='yellow', alpha=0.5))

# Tunneling arrow
tunnel_arrow = FancyArrowPatch((0, 1.4), (0, 0.8),
                              arrowstyle='->', mutation_scale=20,
                              linewidth=3, color='orange',
                              linestyle='--', zorder=2)
ax3.add_patch(tunnel_arrow)
ax3.text(0.4, 1.1, 'Quantum\nTunnel', fontsize=8,
        weight='bold', color='orange')

# Pattern annotation
ax3.text(0, -0.6, 'Flux→Substrate→Concentration→Reaction',
         ha='center', fontsize=8, style='italic',
         bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))

# ============================================================================
# Save and display
# ============================================================================
plt.tight_layout(rect=[0, 0, 1, 0.96])
plt.savefig('universal_funnel_simulations.png', dpi=200, bbox_inches='tight', facecolor='white')
plt.close()

print("\n" + "="*70)
print("UNIVERSAL FUNNEL SIMULATIONS")
print("="*70)
print("\n✓ Three systems, same pattern:\n")

print("1. LED (Cambridge 2025)")
print("   Flux: Electrical charges (e⁻ + h⁺)")
print("   Substrate: Organic antenna molecules (9-ACA)")
print("   Concentration: Triplet exciton formation")
print("   Reaction: Near-IR photon emission (98% efficient)")
print("   Mechanism: Dexter energy transfer\n")

print("2. Black Hole (Hawking 1974)")
print("   Flux: Spacetime curvature (gravitational)")
print("   Substrate: Quantum vacuum (spacetime itself)")
print("   Concentration: Event horizon geometric funnel")
print("   Reaction: Hawking radiation (thermal)")
print("   Scaling: T ~ 1/M\n")

print("3. Deuterium Fusion")
print("   Flux: Kinetic energy (nuclear collisions)")
print("   Substrate: Electron screening (plasma)")
print("   Concentration: Coulomb barrier penetration")
print("   Reaction: ³He + neutron + 3.27 MeV")
print("   Mechanism: Quantum tunneling\n")

print("="*70)
print("SAME PATTERN ACROSS ALL SCALES")
print("="*70)
print("Flux → Substrate → Concentration → Reaction")
print("\n✓ Visualization saved to: universal_funnel_simulations.png\n")
