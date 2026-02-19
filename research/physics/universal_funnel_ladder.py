import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import numpy as np

fig, ax = plt.subplots(figsize=(16, 10))
ax.set_xlim(0, 10)
ax.set_ylim(0, 12)
ax.axis('off')

# Title
ax.text(5, 11.5, "Universal Funnel Mechanism: Energy Transfer Across Scales",
        ha='center', fontsize=20, weight='bold')

# Universal formula at top
formula_box = FancyBboxPatch((2.5, 10.5), 5, 0.8,
                             boxstyle="round,pad=0.1",
                             edgecolor='black', facecolor='lightgray', linewidth=2)
ax.add_patch(formula_box)
ax.text(5, 10.9, r'$E_{reaction} = f(E_{flux}, S, F)$',
        ha='center', fontsize=14, weight='bold', style='italic')

# Define scale levels
scales = [
    {
        'name': 'Classical: Motors',
        'y': 8.5,
        'flux': 'EM field energy',
        'substrate': 'Wire lattice + air',
        'concentration': 'Magnetic torque\n(geometry × drag)',
        'reaction': 'Mechanical rotation',
        'scaling': r'$P \sim V \cdot I \cdot \eta_{geometry}$',
        'color': '#FFE5B4'
    },
    {
        'name': 'Nuclear: Deuterium Fusion',
        'y': 6.5,
        'flux': 'Kinetic energy\n(particle collisions)',
        'substrate': 'Electron screening\n(plasma)',
        'concentration': 'Coulomb barrier\npenetration',
        'reaction': 'Nuclear fusion\n(3He + neutron)',
        'scaling': r'$\sigma \sim \exp(-E_G/E) \cdot S(E)$',
        'color': '#FFD4D4'
    },
    {
        'name': 'Gravitational: Black Holes',
        'y': 4.5,
        'flux': 'Spacetime curvature\n(gravitational energy)',
        'substrate': 'Quantum vacuum\n(spacetime itself)',
        'concentration': 'Event horizon\n(geometric funnel)',
        'reaction': 'Hawking radiation',
        'scaling': r'$T \sim \frac{\hbar c^3}{8\pi G M k_B}$ (T ~ 1/M)',
        'color': '#D4E5FF'
    },
    {
        'name': 'Biological: Life',
        'y': 2.5,
        'flux': 'Chemical/thermal\ngradients',
        'substrate': 'Membrane boundaries\n+ fluid layers',
        'concentration': 'Ion pumps\n(gradient funneling)',
        'reaction': 'Metabolism\n(ATP synthesis)',
        'scaling': r'$\Delta G = \Delta H - T\Delta S$ (boundary work)',
        'color': '#D4FFD4'
    }
]

# Draw each scale level
for scale in scales:
    y = scale['y']

    # Main box
    main_box = FancyBboxPatch((0.5, y - 0.3), 9, 1.5,
                              boxstyle="round,pad=0.05",
                              edgecolor='black', facecolor=scale['color'],
                              linewidth=2, alpha=0.3)
    ax.add_patch(main_box)

    # Title
    ax.text(5, y + 1.0, scale['name'], ha='center', fontsize=13, weight='bold')

    # Flux box
    flux_box = FancyBboxPatch((0.7, y - 0.2), 1.5, 0.9,
                              boxstyle="round,pad=0.05",
                              edgecolor='blue', facecolor='white', linewidth=1.5)
    ax.add_patch(flux_box)
    ax.text(1.45, y + 0.55, 'FLUX', ha='center', fontsize=9, weight='bold', color='blue')
    ax.text(1.45, y + 0.15, scale['flux'], ha='center', fontsize=7.5, style='italic')

    # Arrow 1
    arrow1 = FancyArrowPatch((2.3, y + 0.3), (2.9, y + 0.3),
                            arrowstyle='->', mutation_scale=20, linewidth=2, color='black')
    ax.add_patch(arrow1)

    # Substrate box
    sub_box = FancyBboxPatch((3.0, y - 0.2), 1.5, 0.9,
                             boxstyle="round,pad=0.05",
                             edgecolor='green', facecolor='white', linewidth=1.5)
    ax.add_patch(sub_box)
    ax.text(3.75, y + 0.55, 'SUBSTRATE', ha='center', fontsize=9, weight='bold', color='green')
    ax.text(3.75, y + 0.15, scale['substrate'], ha='center', fontsize=7.5, style='italic')

    # Arrow 2
    arrow2 = FancyArrowPatch((4.6, y + 0.3), (5.2, y + 0.3),
                            arrowstyle='->', mutation_scale=20, linewidth=2, color='black')
    ax.add_patch(arrow2)

    # Concentration box
    conc_box = FancyBboxPatch((5.3, y - 0.2), 1.5, 0.9,
                              boxstyle="round,pad=0.05",
                              edgecolor='red', facecolor='white', linewidth=1.5)
    ax.add_patch(conc_box)
    ax.text(6.05, y + 0.55, 'CONCENTRATION', ha='center', fontsize=9, weight='bold', color='red')
    ax.text(6.05, y + 0.15, scale['concentration'], ha='center', fontsize=7.5, style='italic')

    # Arrow 3
    arrow3 = FancyArrowPatch((6.9, y + 0.3), (7.5, y + 0.3),
                            arrowstyle='->', mutation_scale=20, linewidth=2, color='black')
    ax.add_patch(arrow3)

    # Reaction box
    react_box = FancyBboxPatch((7.6, y - 0.2), 1.5, 0.9,
                               boxstyle="round,pad=0.05",
                               edgecolor='purple', facecolor='white', linewidth=1.5)
    ax.add_patch(react_box)
    ax.text(8.35, y + 0.55, 'REACTION', ha='center', fontsize=9, weight='bold', color='purple')
    ax.text(8.35, y + 0.15, scale['reaction'], ha='center', fontsize=7.5, style='italic')

    # Scaling law below
    ax.text(5, y - 0.65, scale['scaling'], ha='center', fontsize=9,
            bbox=dict(boxstyle='round,pad=0.3', facecolor='yellow', alpha=0.3))

# Vertical connecting arrows showing scale hierarchy
for i in range(len(scales) - 1):
    y1 = scales[i]['y'] - 0.9
    y2 = scales[i + 1]['y'] + 1.2
    arrow = FancyArrowPatch((9.5, y1), (9.5, y2),
                           arrowstyle='<->', mutation_scale=25,
                           linewidth=2.5, color='gray', linestyle='--')
    ax.add_patch(arrow)

ax.text(9.7, 7.5, 'Scale\nHierarchy', ha='left', fontsize=10,
        weight='bold', color='gray', rotation=-90, va='center')

# Bottom summary box
summary_box = FancyBboxPatch((0.5, 0.2), 9, 1.2,
                             boxstyle="round,pad=0.1",
                             edgecolor='black', facecolor='lightyellow',
                             linewidth=2.5, alpha=0.5)
ax.add_patch(summary_box)

summary_text = """UNIVERSAL PATTERN: All energy transfer requires substrate-mediated concentration
• Substrate identity changes with scale (wire → plasma → spacetime → membrane)
• Funnel mechanism is scale-invariant (geometry/boundary/gradient concentration)
• Scaling laws emerge from substrate coupling: f(E_flux, S, F) → E_reaction"""

ax.text(5, 0.8, summary_text, ha='center', fontsize=9.5,
        style='italic', linespacing=1.6)

plt.tight_layout()
plt.savefig('universal_funnel_ladder.png', dpi=200, bbox_inches='tight', facecolor='white')
plt.close()

print("\n✓ Universal funnel ladder diagram created")
