# Frequently Asked Questions (FAQ)

## General Questions

### What is the Veteran Holding Company Platform?

We're a turnkey service that helps veterans form holding companies (LLCs or C-Corps), set up trusts for estate planning, and launch compliant trading or small-business operations. We bundle legal coordination, entity formation, financial onboarding, secure technology, and training into three simple packages.

### Who is this for?

This platform is designed for U.S. military veterans who want to:
- Protect assets for their family through trusts
- Start a trading operation (stocks, crypto, forex)
- Launch a small business or consulting practice
- Qualify for a VA home loan while protecting assets in a trust
- Reduce tax liability through smart entity structuring
- Build generational wealth

### Do I need to be a veteran to use this service?

The platform is optimized for veterans' needs (VA loans, veteran-owned business certifications, etc.), but we also serve active-duty servicemembers and their families. If you're not a veteran, contact us to see if we're a good fit.

### What makes this different from just hiring an attorney or CPA?

We coordinate ALL the moving pieces for you:
- **Legal**: Partner with licensed attorneys for trust drafting and entity formation
- **Financial**: Bank account setup, exchange KYC, VA loan coordination
- **Technical**: Secure trading infrastructure (CCXT kit) with risk controls
- **Compliance**: KYC/AML checklists, tax reporting templates, 7-year recordkeeping

Instead of hiring 5 different professionals and managing coordination yourself, we handle it end-to-end with standardized processes that reduce costs and timelines.

---

## Pricing & Packages

### What's included in each package?

| Package | What's Included | Price |
|---------|-----------------|-------|
| **Starter** | Entity formation, trust intake packet, bank/exchange KYC pack, 2 onboarding calls | $1,500 one-time |
| **Growth** | Starter + trust drafting coordination, CCXT starter kit, 60 days support, bookkeeping template | $4,500 one-time |
| **Enterprise** | Growth + managed hosting, monthly compliance, attorney/CPA retainer coordination, priority support | $1,000+/month |

See the [full pricing breakdown](../README.md#-service-packages).

### Are there any hidden fees?

No. The package prices are all-inclusive for platform services. You'll also pay:
- **State filing fees** for LLC/Corp formation ($50-$500 depending on state)
- **Attorney fees** for trust drafting (included in Growth/Enterprise, or $1,500-$2,000 if added separately)
- **Exchange fees** if you trade (standard trading commissions/spreads)

We'll give you a complete cost breakdown during your discovery call.

### Can I upgrade from Starter to Growth later?

Yes. You can upgrade anytime and we'll credit your Starter fee toward Growth. For example, if you paid $1,500 for Starter and want to upgrade to Growth ($4,500), you'd pay the $3,000 difference.

### Do you offer payment plans?

Yes. For Growth and Enterprise packages, we offer 3- or 6-month payment plans with 0% interest. Ask about payment options during your discovery call.

---

## Entity Formation

### What type of entity should I form?

It depends on your goals:
- **Single-Member LLC**: Best for most veterans. Simple, flexible, and pass-through taxation. Ideal for trading, consulting, or small business.
- **Multi-Member LLC**: If you have a spouse or business partner and want to allocate ownership.
- **C-Corp**: If you plan to raise capital, issue stock options, or go public someday. More complex and double taxation (but lower corporate tax rate).

We'll recommend the best structure during your discovery call based on your goals, income, and assets.

### Which state should I form in?

Usually your home state (where you live and operate). However:
- **Delaware**: Popular for C-Corps due to business-friendly laws and established case law.
- **Wyoming or Nevada**: Privacy benefits and no state income tax for LLCs.

We'll guide you based on your state, business type, and asset protection needs.

### How long does entity formation take?

- **EIN (Employer Identification Number)**: Instant (same day via IRS online)
- **LLC/Corp Filing**: 1-7 business days (varies by state; expedited filing available for extra fee)
- **Operating Agreement**: 3-5 days (we draft, you review and sign)
- **Bank Account**: 7-14 days (after entity formation, requires KYC)

**Total timeline**: 2-4 weeks from payment to fully operational entity.

### Can I use a DBA (Doing Business As)?

Yes. If you want to operate under a brand name different from your legal entity name (e.g., "Veteran Trading Group" instead of "John Smith LLC"), we'll register a DBA for you. Note: A DBA is NOT a separate legal entity - it's just a trade name.

---

## Trust Planning

### What type of trust do I need?

Most veterans benefit from a **Revocable Living Trust (RLT)**:
- Avoids probate (faster, private transfer to heirs)
- Allows you to retain control during your lifetime
- Protects assets if you become incapacitated
- Can be amended or revoked anytime

If you have a large life insurance policy (SGLI, VGLI, or private), you may also want an **Irrevocable Life Insurance Trust (ILIT)** to remove the death benefit from your taxable estate.

We'll assess your needs during the discovery call and coordinate with a licensed attorney in your state.

### Do I need a trust if I don't have a lot of assets?

A trust isn't just for the wealthy. Even with modest assets, a trust:
- Avoids probate (saves time and legal fees for your family)
- Ensures your wishes are followed (e.g., minor children's inheritance managed until adulthood)
- Protects privacy (wills are public record; trusts are not)

If your total assets (home + retirement + life insurance + business) exceed $100k, a trust is usually worth it.

### How much does trust drafting cost?

- **Included in Growth/Enterprise packages**
- **Standalone**: $1,500 - $2,500 (depending on complexity and state)

We coordinate with partner attorneys who provide veteran discounts and use our standardized templates to reduce drafting time (and costs).

### Can I put my LLC ownership in a trust?

Yes, and we recommend it for asset protection and estate planning. You'll transfer your LLC membership interest to the trust via an "Assignment of Membership Interest" (we draft this for you). The trustee (usually you) then manages the LLC on behalf of the trust.

### How does a trust affect my VA home loan eligibility?

**Important**: VA lenders require the veteran borrower to hold legal title at closing (not the trust). Our process:
1. You buy the home in your name (or joint with spouse) using your VA loan
2. After closing (30-60 days), you transfer the property to your trust via quitclaim deed
3. This doesn't violate the VA loan terms or trigger the due-on-sale clause (protected by federal law)

We provide a coordination memo to your VA lender to explain the trust structure and confirm eligibility. See our [VA Loan Coordination Guide](../training/va-loan-coordination.md).

---

## Trading Operations

### What is the CCXT starter kit?

CCXT (CryptoCurrency eXchange Trading Library) is an open-source library that connects to 100+ exchanges (crypto, stocks, forex) via a unified API. Our starter kit includes:
- Docker-based deployment (PostgreSQL, Vault, Prometheus, Grafana)
- Secrets management (API keys never stored in code)
- Risk controls (hard limits, kill switch, withdrawal approval)
- Daily reconciliation (exchange vs. local ledger)
- Tax reporting templates (Form 8949 for capital gains)

See the [full CCXT documentation](../ccxt-starter/README.md).

### Do I need coding experience?

No. The starter kit is pre-configured with Docker (one-command deployment). We provide:
- Step-by-step setup guide
- Video walkthrough
- One-on-one onboarding call
- 60 days of support (Growth package)

If you want to customize strategies or automation, basic Python knowledge helps (we can recommend resources or handle customization as a paid add-on).

### Which exchanges are supported?

**Crypto**: Coinbase Pro, Kraken, Binance.US, Gemini, Bitfinex, and 95+ more
**Stocks**: Alpaca (commission-free, API-first)
**Forex**: OANDA, Interactive Brokers

We'll help you choose exchanges during onboarding based on your trading goals and state regulations.

### Is my money safe?

Yes. We enforce multiple layers of security:
- **API keys stored in Vault** (never in code or config files)
- **IP allowlists** on exchange keys (only your server can use them)
- **Withdrawal controls** (manual approval for all withdrawals)
- **Hard limits** (max order size, max daily volume)
- **Kill switch** (emergency stop for all trading)

You retain full custody of funds - we NEVER hold your money or have withdrawal access.

### What if I don't want to trade? Can I still use the platform?

Absolutely. Many veterans use our service just for entity formation and trust planning (Starter package). The CCXT trading kit is optional (included in Growth/Enterprise for those who want it).

---

## Security & Compliance

### How do you protect my personal information?

- **Encryption**: All data encrypted at rest (AES-256) and in transit (TLS 1.3)
- **Access controls**: 2FA required for all admin access
- **Audit logs**: Immutable logs of all actions
- **Compliance**: HIPAA-level security practices (encrypted storage, access logging)

We NEVER share your information except:
- Partner attorneys/CPAs (under attorney-client privilege or NDA)
- Financial institutions for KYC (required by law)
- Service providers under strict NDA (hosting, payment processing)

### Do you comply with KYC/AML regulations?

Yes. We provide KYC/AML checklists for:
- Corporate bank accounts (EIN, operating agreement, proof of address)
- Exchange accounts (ID, proof of address, source of funds)

We coordinate with your bank and exchanges to ensure smooth account opening without compliance issues.

### How do you handle tax reporting?

- **Trade logs**: All trades logged in PostgreSQL (immutable, 7-year retention)
- **Form 8949 data**: Script generates CSV with all required fields (date acquired, date sold, proceeds, cost basis, gain/loss)
- **CPA coordination**: We refer you to CPAs who specialize in veteran tax issues (trading, VA benefits, estate tax)

You're responsible for filing taxes, but we provide all the data your CPA needs.

### What if I get audited by the IRS?

Our recordkeeping system is designed for IRS compliance:
- 7-year retention of all trade logs
- Immutable audit trail (tamper-evident)
- Daily reconciliation (proves accuracy of reported gains/losses)

Your CPA can access all records to respond to IRS inquiries. We'll also provide a letter documenting our recordkeeping practices if requested.

---

## Support & Onboarding

### How long does onboarding take?

**Starter**: 2-4 weeks (entity formation + bank account)
**Growth**: 4-8 weeks (entity + trust + trading setup)
**Enterprise**: Same as Growth, but with dedicated support throughout

We'll provide a detailed timeline during your discovery call.

### What kind of support do you offer?

- **Starter**: 30 days of email support
- **Growth**: 60 days of email + phone support
- **Enterprise**: Ongoing monthly support, quarterly compliance reviews, priority response

All packages include:
- 2 onboarding calls (Starter) or 4+ calls (Growth/Enterprise)
- Access to training videos and documentation
- Ticketing system for questions

### Can I talk to a real person, or is it all automated?

You'll have a dedicated account manager for onboarding and can schedule calls anytime. Enterprise clients get priority access and quarterly strategy sessions.

### What if I need help after my support period ends?

You can:
- Upgrade to Enterprise (ongoing support included)
- Purchase support credits ($150/hour for ad-hoc questions)
- Renew annual support ($500/year for Starter, $1,000/year for Growth)

---

## Legal & Disclaimers

### Are you a law firm?

No. We coordinate legal services but do NOT provide legal advice. Legal work (trust drafting, entity formation review) is handled by licensed attorneys in your state. You'll have a direct attorney-client relationship with them.

### Are you a registered investment advisor?

No. We provide trading infrastructure and operational tools, but we do NOT recommend specific investments or trading strategies. Any trading decisions are yours alone.

### What happens if something goes wrong?

We carry:
- **General liability insurance** ($1M)
- **Cyber liability insurance** ($2M)
- **E&O insurance** ($1M)

Partner attorneys carry their own malpractice insurance. If there's a service issue, contact us immediately and we'll work to resolve it.

### Can you guarantee specific outcomes (tax savings, trading profits, etc.)?

No. Legal and financial outcomes depend on many factors (your unique situation, market conditions, proper execution). We provide tools, coordination, and best practices, but we cannot guarantee results.

---

## Getting Started

### How do I sign up?

1. **Fill out the intake form**: [CLIENT_INTAKE_TEMPLATE.md](../CLIENT_INTAKE_TEMPLATE.md)
2. **Schedule discovery call**: We'll send you a calendar link within 24 hours
3. **Choose package**: Based on your goals, we'll recommend Starter, Growth, or Enterprise
4. **Sign agreement and pay**: We'll send a service agreement and invoice
5. **Kick off**: Entity formation and onboarding begins within 2 business days

### Do you offer free consultations?

Yes. The initial discovery call (45 minutes) is free with no obligation. We'll assess your needs, answer questions, and recommend a package. If we're not a good fit, we'll refer you to other resources.

### What if I'm not ready to commit yet?

No problem. You can:
- Download our [90-Day Project Plan](../PROJECT_PLAN_90_DAY.md) to learn more
- Review the [Attorney Packet](../ATTORNEY_PACKET.md) (for transparency on legal process)
- Explore the [CCXT Starter Kit](../ccxt-starter/README.md) (open-source, free to use)
- Email questions to support@veteranholdingco.com

---

## Contact

**Email**: support@veteranholdingco.com
**Phone**: (555) 123-4567 (Mon-Fri 9am-5pm ET)
**GitHub**: [https://github.com/Peekabot/Couch.Potato](https://github.com/Peekabot/Couch.Potato)

---

**Still have questions? Email us or schedule a free consultation.**

🎖️ **Thank you for your service.**
