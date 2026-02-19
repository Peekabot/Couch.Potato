# Governance Framework

## Overview

A lightweight, democratic governance system for managing the organization without traditional hierarchical management.

## Core Principle

**All decisions made by member vote. No managers. No hierarchy.**

---

## Decision Types

### 1. **Operational Decisions** (No Vote Required)

Day-to-day activities that don't require consensus:

✅ Logging work hours (ULU)
✅ Submitting bug bounties
✅ Writing code
✅ Customer support
✅ Documentation

**Principle**: If it doesn't affect other members, no vote needed.

---

### 2. **Financial Decisions** (Simple Majority)

Decisions affecting money or resources:

📊 Issuing new bonds
📊 Changing reserve target (from 15%)
📊 Making capital purchases
📊 Setting operational budgets
📊 Deploying to new yield platforms

**Vote Threshold**: >50% of members

---

### 3. **Structural Decisions** (Supermajority)

Changes to core systems or policies:

🔒 Modifying ULU labor theory
🔒 Changing bond APR (from 6%)
🔒 Altering revenue distribution
🔒 Adding/removing members
🔒 Updating governance rules

**Vote Threshold**: ≥66% of members

---

### 4. **Emergency Decisions** (Unanimous)

Critical changes or crisis responses:

⚠️ Shutting down operations
⚠️ Dissolving the organization
⚠️ Suspending bond payments
⚠️ Clawing back distributions
⚠️ Overriding automated systems

**Vote Threshold**: 100% of members

---

## Voting Mechanism

### Proposal Process

```python
def create_proposal(
    title: str,
    description: str,
    type: str,  # operational, financial, structural, emergency
    proposed_by: str
):
    proposal = {
        "id": generate_id(),
        "title": title,
        "description": description,
        "type": type,
        "proposed_by": proposed_by,
        "created_date": today(),
        "voting_deadline": today() + 7,  # 7 days to vote
        "votes": {},
        "status": "open"
    }

    proposals.append(proposal)
    notify_all_members(proposal)

    return proposal["id"]
```

---

### Casting Votes

```python
def vote(proposal_id: str, member_id: str, vote: str):
    """
    Member casts vote (yes/no/abstain)
    """
    proposal = get_proposal(proposal_id)

    if member_id not in members:
        raise Error("Not a member")

    if today() > proposal["voting_deadline"]:
        raise Error("Voting closed")

    proposal["votes"][member_id] = vote  # yes, no, abstain

    # Auto-tally if all members voted
    if len(proposal["votes"]) == len(members):
        finalize_vote(proposal_id)
```

---

### Vote Tallying

```python
def tally_votes(proposal_id: str):
    """
    Calculate vote results
    """
    proposal = get_proposal(proposal_id)

    yes_votes = sum(1 for v in proposal["votes"].values() if v == "yes")
    no_votes = sum(1 for v in proposal["votes"].values() if v == "no")
    abstain = sum(1 for v in proposal["votes"].values() if v == "abstain")
    total_members = len(members)

    # Determine threshold based on type
    thresholds = {
        "operational": 0.50,  # >50%
        "financial": 0.50,    # >50%
        "structural": 0.66,   # ≥66%
        "emergency": 1.00     # 100%
    }

    required = thresholds[proposal["type"]]
    approval_rate = yes_votes / total_members

    if approval_rate >= required:
        proposal["status"] = "passed"
        execute_proposal(proposal)
    else:
        proposal["status"] = "rejected"

    notify_all_members(proposal)
```

---

## Examples

### Example 1: Issuing a Bond (Financial)

**Proposal**:
- Type: Financial
- Title: "Issue $10,000 bond to Alice"
- Description: "Alice will lend $10,000 at 6% APR to fund server costs"
- Threshold: >50%

**Votes**:
- Alice: Yes
- Bob: Yes
- Carol: No

**Result**:
```
Yes: 2 (66%)
No: 1 (33%)
Required: >50%
Status: PASSED ✅
```

**Action**: Issue bond to Alice, transfer $10,000 to org account

---

### Example 2: Changing ULU System (Structural)

**Proposal**:
- Type: Structural
- Title: "Weight ULU by skill level"
- Description: "Senior work = 1.5 ULU, junior work = 1 ULU"
- Threshold: ≥66%

**Votes**:
- Alice: Yes
- Bob: Yes
- Carol: No

**Result**:
```
Yes: 2 (66%)
No: 1 (33%)
Required: ≥66%
Status: PASSED ✅ (exactly at threshold)
```

**Action**: Update ULU calculation to include skill multipliers

---

### Example 3: Suspending Bond Payments (Emergency)

**Proposal**:
- Type: Emergency
- Title: "Suspend bond payments for 30 days"
- Description: "Zero revenue this month, need to preserve capital"
- Threshold: 100%

**Votes**:
- Alice: Yes
- Bob: Yes
- Carol: No

**Result**:
```
Yes: 2 (66%)
No: 1 (33%)
Required: 100%
Status: REJECTED ❌
```

**Action**: No change, bond payments continue

---

## Dispute Resolution

### Process

1. **Direct Discussion**: Members discuss issue directly
2. **Mediation**: Neutral third member facilitates discussion
3. **Vote**: If unresolved, put to member vote
4. **Exit**: If still unresolved, member can exit organization

---

### Example Dispute: Hours Claimed

**Situation**:
- Alice claims 80 hours for January
- Bob thinks Alice only worked 40 hours
- No consensus on actual hours

**Resolution**:

1. **Review Output**:
   - GitHub commits: 120 commits
   - Customer tickets: 15 resolved
   - Documentation: 3 new pages

2. **Peer Estimate**:
   - Bob estimates 40 hours
   - Carol estimates 60 hours
   - Median: 60 hours

3. **Vote**:
   - Proposal: "Credit Alice with 60 hours (median of estimates)"
   - Alice: Abstain
   - Bob: Yes
   - Carol: Yes
   - Result: PASSED (100% of non-abstaining members)

4. **Final**: Alice credited with 60 ULU

---

## Member Management

### Adding Members

**Requirements**:
1. Supermajority vote (≥66%)
2. Member contributes capital (bond) OR labor (ULU)
3. Agreement to governance rules

**Process**:
```python
def add_member(
    name: str,
    contribution_type: str,  # bond or labor
    contribution_amount: float
):
    proposal = create_proposal(
        title=f"Add {name} as member",
        description=f"{name} will contribute ${contribution_amount} as {contribution_type}",
        type="structural"
    )

    # Vote for 7 days
    # If passed, onboard member
```

---

### Removing Members

**Grounds for Removal**:
- Fraudulent ULU reporting (repeated)
- Violating governance rules
- Inactive for 6+ months (no ULU, no votes)
- Voluntary exit

**Process**:
1. Supermajority vote (≥66%)
2. Settle outstanding ULU/bond obligations
3. Return capital if applicable
4. Revoke access

---

## Transparency Requirements

### Public Information

All members have access to:

✅ Full financial ledger (revenue, expenses, distributions)
✅ All member ULU logs
✅ Bond balances and payments
✅ Reserve pool balance
✅ Yield deployment positions
✅ Vote history and outcomes

**Implementation**: Real-time dashboard + SQLite database export

---

### Private Information

Protected information:

🔒 Member bank account numbers
🔒 Personal identification
🔒 Individual member balances (unless shared voluntarily)

---

## Automated Enforcement

### Smart Rules

Certain governance rules enforced by code:

```python
# Example: Enforce bond payment priority
def distribute_revenue(revenue: float):
    # 1. Bond obligations (enforced - cannot be skipped)
    revenue = pay_bonds(revenue)

    # 2. Reserve top-up (enforced - cannot be skipped)
    revenue = top_up_reserve(revenue)

    # 3. Member distribution (automatic - no vote needed)
    revenue = distribute_to_members(revenue)

    # 4. Yield deployment (automatic - no vote needed)
    deploy_to_yield(revenue)
```

**Key**: Critical financial rules run automatically, preventing human error or malice.

---

## Conflict of Interest

### Rules

1. **Vote Abstention**: Members cannot vote on proposals directly benefiting them
2. **Disclosure**: All conflicts must be disclosed upfront
3. **Third-Party Review**: High-value conflicts reviewed by external auditor

**Example**:
- Alice proposes issuing $50,000 bond to herself
- Alice must abstain from vote
- Only Bob and Carol vote
- Requires ≥66% of non-abstaining members (both must agree)

---

## Future Enhancements

1. **Quadratic Voting**: Weight votes by ULU contribution
2. **Delegation**: Members delegate votes to trusted proxies
3. **Futarchy**: Prediction markets inform decision-making
4. **DAO Integration**: On-chain governance for transparency
5. **Reputation System**: Track vote quality and participation

---

## Governance Philosophy

> **We believe in:**
> - Transparency over secrecy
> - Consensus over authority
> - Automation over bureaucracy
> - Fairness over efficiency (when trade-offs exist)

**Result**: A company that runs itself, governed by the people who do the work.

---

*Last Updated: 2026-01-18*
*Version: 1.0*
*Status: Active*
