# Bond Mechanism

## Overview

The **Bond Mechanism** provides members with a way to fund the organization while earning a guaranteed return, creating a stable capital base without traditional debt.

## Core Principle

**Members can lend capital to the organization in exchange for guaranteed 6% APR returns, paid daily from revenue.**

---

## How Bonds Work

### 1. **Bond Issuance**

Members contribute capital to the organization:

```python
member.issue_bond(
    principal=5000,  # $5,000 investment
    apr=0.06,        # 6% annual return
    callable=True    # Can be recalled by member
)
```

**Key Parameters:**
- **Principal**: Amount invested (USD)
- **APR**: Annual Percentage Rate (fixed at 6%)
- **Callable**: Member can recall bond at any time
- **Term**: No fixed term (perpetual until called)

---

### 2. **Daily Interest Calculation**

Interest accrues daily and is paid from revenue:

```
daily_interest = principal × (0.06 / 365)
```

**Example:**
- Principal: $5,000
- APR: 6%
- Daily interest: $5,000 × 0.06 / 365 = $0.82/day
- Annual payout: $300

---

### 3. **Payment Priority**

Bonds have **first priority** in the revenue distribution waterfall:

```
Revenue Distribution Order:
1. Bond obligations (6% APR) ← FIRST
2. Reserve top-up (15% NAV)
3. Member profit (ULU-weighted)
4. Yield deployment
```

**Why First Priority?**
- Guarantees stable returns for capital providers
- Reduces risk for members lending to organization
- Creates predictable cost structure
- Builds trust and enables scaling

---

## Bond Examples

### Scenario 1: Single Bond

**Setup:**
- Alice issues $10,000 bond
- Daily interest: $10,000 × 0.06 / 365 = $1.64
- Daily revenue: $100

**Distribution:**
```
Revenue: $100
1. Bond payment to Alice: $1.64
2. Remaining for other uses: $98.36
```

**Result**: Alice gets guaranteed $1.64/day regardless of profits

---

### Scenario 2: Multiple Bonds

**Setup:**
- Alice: $10,000 bond → $1.64/day
- Bob: $5,000 bond → $0.82/day
- Carol: $15,000 bond → $2.47/day
- Total daily bond obligation: $4.93
- Daily revenue: $200

**Distribution:**
```
Revenue: $200
1. Bond payments:
   - Alice: $1.64
   - Bob: $0.82
   - Carol: $2.47
   - Total: $4.93
2. Remaining: $195.07 (for reserve, profits, yield)
```

---

### Scenario 3: Low Revenue Day

**Setup:**
- Total daily bond obligation: $50
- Daily revenue: $30 (insufficient!)

**What Happens:**
```
Revenue: $30
Bond obligations: $50
Shortfall: -$20
```

**Resolution Options:**

1. **Partial Payment** (Proportional):
   - Pay 60% of each bond ($30 / $50 = 60%)
   - Accrue remaining 40% as debt

2. **Reserve Drawdown**:
   - Use reserve pool to cover shortfall
   - Reserve depletes by $20

3. **Member Vote**:
   - Suspend bond payments temporarily
   - Accrue interest for later payment
   - Requires unanimous consent

**Recommended**: Option 2 (reserve drawdown) to maintain trust

---

## Bond Lifecycle

### Issuance

```python
def issue_bond(member_id: str, principal: float):
    """
    Member lends capital to organization
    """
    bond = {
        "id": generate_bond_id(),
        "member_id": member_id,
        "principal": principal,
        "apr": 0.06,
        "issued_date": today(),
        "callable": True,
        "accrued_interest": 0
    }

    # Transfer funds
    organization_bank += principal
    member_bank -= principal

    # Record bond
    bonds.append(bond)

    return bond["id"]
```

---

### Daily Accrual

```python
def accrue_daily_interest():
    """
    Calculate daily interest for all bonds
    """
    for bond in active_bonds:
        daily_interest = bond["principal"] * 0.06 / 365
        bond["accrued_interest"] += daily_interest

        # Log for payment
        pending_payments.append({
            "bond_id": bond["id"],
            "amount": daily_interest,
            "date": today()
        })
```

---

### Payment Execution

```python
def pay_bond_obligations(revenue: float):
    """
    Pay bond interest from revenue (first priority)
    """
    total_obligation = sum(
        bond["principal"] * 0.06 / 365
        for bond in active_bonds
    )

    if revenue >= total_obligation:
        # Full payment
        for bond in active_bonds:
            interest = bond["principal"] * 0.06 / 365
            transfer(organization, bond["member_id"], interest)
            bond["accrued_interest"] -= interest

        return revenue - total_obligation  # Remaining revenue

    else:
        # Insufficient revenue - use reserve or accrue
        if reserve_balance >= (total_obligation - revenue):
            # Draw from reserve
            reserve_drawdown = total_obligation - revenue
            for bond in active_bonds:
                interest = bond["principal"] * 0.06 / 365
                transfer(organization, bond["member_id"], interest)
                bond["accrued_interest"] -= interest

            reserve_balance -= reserve_drawdown
            return 0  # All revenue used

        else:
            # Accrue for later payment
            log_warning("Insufficient funds for bond payments")
            return revenue  # Keep revenue for other uses
```

---

### Bond Recall

Members can recall bonds at any time:

```python
def recall_bond(bond_id: str):
    """
    Member recalls their bond
    """
    bond = get_bond(bond_id)

    # Pay accrued interest
    if bond["accrued_interest"] > 0:
        transfer(organization, bond["member_id"], bond["accrued_interest"])

    # Return principal
    transfer(organization, bond["member_id"], bond["principal"])

    # Mark bond as closed
    bond["status"] = "recalled"
    bond["closed_date"] = today()
```

**Notice Period**: 30 days recommended (allows org to prepare liquidity)

---

## Benefits

### For Bond Holders

✅ **Guaranteed Returns**
- Fixed 6% APR regardless of profitability
- First priority in revenue distribution
- Low risk compared to profit sharing

✅ **Liquidity**
- Callable at any time (with notice period)
- Not locked in like traditional investments

✅ **Transparency**
- Daily interest calculations visible
- Real-time bond ledger
- Full payment history

---

### For Organization

✅ **Stable Capital**
- Predictable cost (6% APR)
- No dilution of ownership
- Flexible terms (no fixed maturity)

✅ **Trust Building**
- Demonstrates reliability
- Attracts risk-averse members
- Creates foundation for growth

✅ **Flexible Scaling**
- Accept bonds as needed
- No external lenders/banks
- Member-controlled capitalization

---

## Risk Management

### Insufficient Revenue

**Problem**: What if bond obligations exceed revenue?

**Solutions**:
1. Reserve pool covers shortfalls (15% NAV minimum)
2. Member vote to suspend payments temporarily
3. Accrue interest for later payment
4. Recall bonds to reduce obligations

---

### Mass Recalls

**Problem**: What if all members recall bonds simultaneously?

**Solutions**:
1. **30-day notice period**: Gives org time to prepare
2. **Staggered payouts**: Max 20% of bonds callable per month
3. **Reserve liquidity**: 15% NAV can cover partial recalls
4. **Member coordination**: Voluntary agreements to stagger

---

### Opportunity Cost

**Problem**: 6% APR may be lower than profit sharing rates

**Example**:
- Organization makes $10,000 profit
- Member has $5,000 bond earning $300/year (6%)
- If invested as labor (ULU), might earn $2,000/year (40%)

**Mitigation**:
- Bonds are for **risk-averse capital**
- ULU is for **active labor contribution**
- Members can choose mix (e.g., 50% bond, 50% labor)

---

## Comparison to Alternatives

| Model | Return | Risk | Liquidity | Ownership |
|-------|--------|------|-----------|-----------|
| **Bond (6% APR)** | Fixed 6% | Low | High (callable) | None |
| **Profit Sharing (ULU)** | Variable | Medium | Instant | Indirect |
| **Equity** | Variable | High | Low | Direct |
| **Traditional Loan** | Fixed 8-15% | Medium | None | None |

---

## Implementation

### Bond Ledger

```python
bonds = [
    {
        "id": "BOND-001",
        "member_id": "alice",
        "principal": 10000,
        "apr": 0.06,
        "issued_date": "2025-01-01",
        "status": "active",
        "callable": True,
        "accrued_interest": 16.44  # 10 days of interest
    },
    {
        "id": "BOND-002",
        "member_id": "bob",
        "principal": 5000,
        "apr": 0.06,
        "issued_date": "2025-01-05",
        "status": "active",
        "callable": True,
        "accrued_interest": 4.11  # 5 days of interest
    }
]
```

---

### Dashboard

```python
def get_bond_stats():
    """
    Return current bond statistics
    """
    total_principal = sum(b["principal"] for b in active_bonds)
    daily_obligation = total_principal * 0.06 / 365
    annual_cost = total_principal * 0.06

    return {
        "total_bonds": len(active_bonds),
        "total_principal": total_principal,
        "daily_obligation": daily_obligation,
        "annual_cost": annual_cost,
        "coverage_ratio": daily_revenue / daily_obligation  # >1 is healthy
    }
```

**Example Output**:
```
Total Bonds: 3
Total Principal: $30,000
Daily Obligation: $4.93
Annual Cost: $1,800
Coverage Ratio: 40.5x (very healthy)
```

---

## Future Enhancements

1. **Variable APR**: Market-based rates (e.g., 4-8% based on demand)
2. **Tiered Bonds**: Higher returns for longer lock-ups
3. **Convertible Bonds**: Convert to ULU labor at member's choice
4. **Bond Trading**: Secondary market among members
5. **Collateralization**: Bonds backed by specific assets

---

*Last Updated: 2026-01-18*
*Version: 1.0*
*Status: Active*
