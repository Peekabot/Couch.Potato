# GitHub Workflow for Theory Development

## Basic Git Commands You Need

### Starting Work
```bash
# See what branch you're on and what's changed
git status

# Switch to your theory branch
git checkout claude/organize-theories-242Pe

# Create a new theory branch (if needed)
git checkout -b theory/new-idea-name
```

### Adding a New Theory
```bash
# 1. Create your markdown file
# Put it in the right domain folder: theories/domains/[domain]/[theory-name].md

# 2. Stage the file
git add theories/domains/semiconductor/new-theory.md

# 3. Commit with descriptive message
git commit -m "Add theory: phonon eigenmode coupling in quantum dots

- Derive eigenmode spectrum for spherical QD
- Connect to size-dependent emission
- Predict optimal size for minimal phonon loss"

# 4. Push to GitHub
git push -u origin claude/organize-theories-242Pe
```

### Updating Existing Theory
```bash
# 1. Edit the file (use any text editor or Claude)

# 2. See what changed
git diff theories/domains/semiconductor/phonon-bottleneck.md

# 3. Stage and commit
git add theories/domains/semiconductor/phonon-bottleneck.md
git commit -m "Update phonon bottleneck: add graded interface section"

# 4. Push
git push
```

### Linking Theories Together
When you find connections between theories:

1. Add cross-reference links in markdown:
```markdown
## Cross-References
- [Related theory](../../domains/other/theory-name.md)
- [Foundation](../../foundations/boundary-energy-density.md)
```

2. Update the main [README.md](README.md) index

3. Consider creating new file in `cross-domain/` if it's a major connection

### Using GitHub Issues for Open Questions

```bash
# Create issue from command line (requires 'gh' CLI)
gh issue create --title "Verify: phonon reflection at GaN/InGaN interface" \
                --body "Need to calculate from first principles or find literature value"

# Or just use GitHub web interface: click "Issues" → "New Issue"
```

Label your issues:
- `verification-needed` - Testable claim that needs experimental check
- `literature-search` - Need to find if someone already did this
- `calculation` - Math that needs to be worked out
- `open-question` - Fundamental uncertainty

### Organizing by Domain

Current structure:
```
theories/
├── foundations/          # Core mathematical frameworks
├── domains/             # Domain-specific phenomena
│   ├── semiconductor/
│   ├── electrostatics/
│   ├── metallurgy/
│   ├── thermodynamics/
│   └── geometry/
├── cross-domain/        # Unified theories spanning multiple domains
├── predictions/         # Testable experimental predictions
└── verification/        # Experimental data and results
```

**Rule of thumb:**
- If theory is specific to one field → `domains/[field]/`
- If theory connects multiple fields → `cross-domain/`
- If theory is mathematical foundation → `foundations/`
- If it's a specific testable claim → `predictions/`

### Writing Style

Keep it like a science diary, not a paper:
- ✅ "I keep seeing this pattern..."
- ✅ "Had to convince myself this isn't confirmation bias"
- ✅ "Textbook says X, but here's what's really happening"
- ❌ "It is well known that..."
- ❌ "We propose a novel framework..."
- ❌ Overly formal academic language

### Math Formatting

GitHub supports LaTeX in markdown:

**Inline:** `$E = mc^2$` renders as $E = mc^2$

**Display:**
```
$$
u = \frac{1}{2}\varepsilon_0 E^2
$$
```
renders as:
$$u = \frac{1}{2}\varepsilon_0 E^2$$

**Aligned equations:**
```
$$
\begin{align}
u_E &= \frac{1}{2}\varepsilon_0 E^2 \\
    &= \frac{1}{2}\varepsilon_0 |\nabla V|^2
\end{align}
$$
```

### Committing Best Practices

**Good commit messages:**
```
Add theory: Damascus steel as phonon boundary trap

- Cementite nanowires at grain boundaries
- Explain pattern formation via thermal cycling
- Connect to modern phonon engineering
```

**Bad commit messages:**
```
Update
Fixed stuff
asdf
```

**Commit often:** Every time you finish a coherent thought, commit it. Don't wait until "everything is perfect."

### Branching Strategy

- `main` - stable, organized theories
- `claude/organize-theories-242Pe` - current active work
- `theory/[topic]` - experimental branches for new ideas

When theory is solid, merge to main:
```bash
git checkout main
git merge claude/organize-theories-242Pe
git push
```

### Creating a Pull Request (when ready)

```bash
# Make sure everything is pushed
git push -u origin claude/organize-theories-242Pe

# Create PR using GitHub CLI
gh pr create --title "Organize boundary energy theories" \
             --body "## Summary
- Add foundational boundary energy framework
- Document phonon bottleneck in LEDs
- Add Vector Equilibrium eigenmode theory
- Set up cross-domain linking system"

# Or use GitHub web interface
```

## Quick Reference

| Task | Command |
|------|---------|
| Check status | `git status` |
| See changes | `git diff [file]` |
| Stage file | `git add [file]` |
| Commit | `git commit -m "message"` |
| Push | `git push` |
| Create branch | `git checkout -b [name]` |
| Switch branch | `git checkout [name]` |
| View history | `git log --oneline` |

## Template for New Theory

See [THEORY_TEMPLATE.md](THEORY_TEMPLATE.md)

## Questions?

- GitHub docs: https://docs.github.com/en/get-started/quickstart/hello-world
- Markdown guide: https://www.markdownguide.org/basic-syntax/
- LaTeX math: https://en.wikibooks.org/wiki/LaTeX/Mathematics
