# ULU Labor Theory

## Universal Labor Units (ULU)

A measurement system for quantifying and valuing productive labor in a post-hierarchical organization.

## Core Principle

**All productive labor has equal hourly value.**

- 1 hour of software development = 1 ULU
- 1 hour of customer support = 1 ULU
- 1 hour of financial admin = 1 ULU
- 1 hour of bug bounty research = 1 ULU

**No role-based multipliers. No experience premiums. Pure meritocracy of output.**

---

## Rationale

### Traditional Problem

Companies create artificial hierarchies:
- "Senior" developer makes 2x junior
- "Manager" makes 1.5x individual contributor
- Based on **titles**, not **output**

### ULU Solution

Compensation reflects **actual contribution to revenue**, not arbitrary job titles.

**Example**:
- If Alice works 40 hours and Bob works 20 hours
- And company makes $900 profit
- Alice gets: $900 × (40/60) = $600
- Bob gets: $900 × (20/60) = $300
- **Ratio: 2:1 based purely on hours**

---

## Measurement

### What Counts as ULU?

**Productive Labor**:
✅ Writing code
✅ Customer support
✅ Bug bounty research
✅ Financial admin
✅ Documentation
✅ Design work
✅ Strategic planning
✅ Marketing
✅ Sales calls

**Not Productive Labor**:
❌ Commuting
❌ Lunch breaks
❌ Personal time
❌ Non-work conversations

### Self-Reporting System

```python
# Each member logs hours daily
member.log_time(
    date="2025-01-18",
    hours=8.5,
    description="Bug bounty recon + report writing"
)
```

**Verification**:
- Monthly peer review
- Output-based validation (commits, reports, tickets)
- Dispute resolution by consensus

---

## Examples

### Scenario 1: Equal Hours, Equal Pay

**Setup**:
- Daily revenue: $600
- Alice: 8 hours
- Bob: 8 hours
- Total: 16 ULU

**Distribution**:
- Alice: $600 × (8/16) = $300
- Bob: $600 × (8/16) = $300

**Result**: Perfect equality for equal effort

---

### Scenario 2: Unequal Hours

**Setup**:
- Daily revenue: $600
- Alice: 10 hours (bug bounty research)
- Bob: 2 hours (admin work)
- Total: 12 ULU

**Distribution**:
- Alice: $600 × (10/12) = $500
- Bob: $600 × (2/12) = $100

**Result**: 5:1 ratio reflecting contribution

---

### Scenario 3: Variable Contribution

**Month 1**:
- Alice: 160 hours (full-time)
- Bob: 80 hours (part-time)
- Carol: 40 hours (contractor)
- Total: 280 ULU

**Month 2**:
- Alice: 40 hours (vacation)
- Bob: 160 hours (stepped up)
- Carol: 80 hours (increased load)
- Total: 280 ULU

**Effect**: Shares flip dynamically. No fixed "salary."

---

## Benefits

### 1. **Eliminates Negotiation**

No salary discussions. No raises. No politics.

Your compensation = (Your ULU / Total ULU) × Revenue

### 2. **Perfectly Flexible**

- Want to work 20 hours/week? Fine. Get 20% of profit.
- Want to work 60 hours/week? Fine. Get 60% of profit.
- Take a month off? Fine. Get 0% that month.

### 3. **Naturally Meritocratic**

High performers self-select:
- Work more → Earn more
- Work less → Earn less
- No artificial caps or floors

### 4. **Transparent**

Everyone sees:
- Total ULU
- Their share
- Implied hourly rate (revenue / ULU)

**Example Dashboard**:
```
Total Revenue: $10,000
Total ULU: 200
Implied Rate: $50/ULU

Your ULU: 40 (20%)
Your Share: $2,000
Your Rate: $50/hour
```

---

## Edge Cases

### Extremely Low Revenue

**Problem**: What if revenue = $100 and total ULU = 200?

**Implied Rate**: $0.50/hour (unlivable)

**Solutions**:
1. **Bonds provide floor**: Members with bonds get 6% APR regardless
2. **Temporary withdrawal**: Members can reduce hours during slumps
3. **Member advances**: High earners can advance funds to others
4. **Reserve cushion**: Reserve can smooth short-term volatility

### Extremely High Revenue

**Problem**: What if revenue spikes to $50,000 in one day?

**Effect**: Implied rate = $250/hour (windfall)

**Solutions**:
1. **Reserve absorption**: Excess goes to reserve
2. **Voluntary distribution delay**: Save for lean times
3. **Discretionary bonuses**: Distribute over multiple periods

### Disputes

**Problem**: Alice claims 80 hours but Bob thinks she only worked 40.

**Resolution Process**:
1. Review output (commits, reports, customer interactions)
2. Peer vote on disputed hours
3. If unresolved, use median of estimates
4. Persistent disputes → member vote to remove

---

## Comparison to Traditional Models

| Model | Pros | Cons |
|-------|------|------|
| **Fixed Salary** | Predictable | Unfair (ignores effort) |
| **Equity** | Long-term aligned | Slow, illiquid |
| **Commission** | Performance-based | Only works for sales |
| **ULU** | Fair, transparent, flexible | Requires trust, low-revenue risk |

---

## Implementation

### Monthly ULU Update

```python
def calculate_monthly_ulu():
    """
    Calculate each member's ULU for the month
    """
    for member in members:
        # Sum daily hours
        monthly_hours = sum(
            member.daily_logs
            for date in current_month
        )

        # Validate against output
        if monthly_hours > 200:  # ~50hrs/week
            flag_for_review(member)

        # Update ULU
        member.ulu = monthly_hours
```

### Real-Time Dashboard

```python
def get_member_stats(member_id):
    """
    Show member's current standing
    """
    total_ulu = sum(m.ulu for m in members)
    member_ulu = get_member(member_id).ulu

    return {
        "ulu": member_ulu,
        "share": member_ulu / total_ulu,
        "implied_rate": last_revenue / total_ulu,
        "projected_monthly": (member_ulu / 30) * 30 * (last_revenue / total_ulu)
    }
```

---

## Future Enhancements

1. **Weighted ULU**: Voluntary peer-voting to weight certain hours higher
2. **Skill Multipliers**: Emergent from market (higher-value work attracts more ULU)
3. **Automated Tracking**: Integration with GitHub, Jira, etc.
4. **AI Validation**: Use activity logs to validate claimed hours

---

*Last Updated: 2025-01-18*
*Version: 1.0*
*Status: Active*
