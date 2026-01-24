# CCXT Trading Starter Kit - Veteran Holding Company Platform

## Overview

A production-ready, security-first trading infrastructure for veterans managing algorithmic trading operations through their LLC or trust. Built on CCXT (CryptoCurrency eXchange Trading Library), this kit provides:

- **Secure secrets management** (HashiCorp Vault or AWS Secrets Manager)
- **Multi-exchange support** (crypto, stocks via Alpaca, forex)
- **Automated reconciliation** (exchange balances vs. local ledger)
- **Risk controls** (hard limits, kill switch, withdrawal approval)
- **Audit logging** (immutable trade history for tax/compliance)
- **Paper trading mode** (test strategies without real capital)

**Target Users**: Veterans with Growth or Enterprise packages who want to run automated trading strategies or manual trading with enhanced operational controls.

---

## Table of Contents

1. [Architecture](#architecture)
2. [Security Model](#security-model)
3. [Prerequisites](#prerequisites)
4. [Quick Start](#quick-start)
5. [Configuration](#configuration)
6. [Reconciliation Script](#reconciliation-script)
7. [Risk Controls](#risk-controls)
8. [Deployment](#deployment)
9. [Monitoring](#monitoring)
10. [Compliance & Tax](#compliance--tax)
11. [Troubleshooting](#troubleshooting)
12. [Roadmap](#roadmap)

---

## Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────┐
│                     Trading Application                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  Strategy    │  │  Execution   │  │  Risk        │      │
│  │  Engine      │  │  Engine      │  │  Manager     │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└────────────┬────────────────┬────────────────┬─────────────┘
             │                │                │
             ▼                ▼                ▼
┌─────────────────────────────────────────────────────────────┐
│                       CCXT Library                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  Coinbase    │  │  Kraken      │  │  Binance.US  │      │
│  │  Pro         │  │              │  │              │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└────────────┬────────────────┬────────────────┬─────────────┘
             │                │                │
             ▼                ▼                ▼
┌─────────────────────────────────────────────────────────────┐
│                    Exchange APIs                             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                  Supporting Infrastructure                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  PostgreSQL  │  │  Vault       │  │  Prometheus  │      │
│  │  (Trade DB)  │  │  (Secrets)   │  │  (Metrics)   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

### Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Trading Library** | CCXT (Python) | Unified API for 100+ exchanges |
| **Database** | PostgreSQL | Trade history, balances, ledger |
| **Secrets Management** | HashiCorp Vault or AWS Secrets | API keys, passwords, encryption keys |
| **Containerization** | Docker + Docker Compose | Reproducible deployment |
| **Monitoring** | Prometheus + Grafana | Metrics, alerts, dashboards |
| **Risk Controls** | Custom Python | Hard limits, kill switch, approval workflows |
| **Reconciliation** | Python script (cron) | Daily balance checks |
| **Web UI** | Streamlit (optional) | Simple dashboard for monitoring |

---

## Security Model

### Threat Model

**Assets to Protect**:
- API keys (exchange access)
- Private keys (wallet access, if applicable)
- Trade strategies (intellectual property)
- Personal information (KYC documents)

**Threats**:
- API key theft or leakage
- Unauthorized withdrawals
- Strategy parameter tampering
- Database compromise (trade history)
- Man-in-the-middle attacks (API calls)

### Defense in Depth

**Layer 1: Secrets Management**
- ✅ API keys stored in Vault or AWS Secrets Manager (NEVER in code or config files)
- ✅ Keys encrypted at rest (AES-256)
- ✅ Keys rotated every 90 days (automated or manual)
- ✅ Least privilege (read-only keys for monitoring, trade keys with IP allowlists)

**Layer 2: Network Security**
- ✅ IP allowlists on exchange API keys (only allow server IPs)
- ✅ TLS for all API calls (enforce HTTPS)
- ✅ Firewall rules (PostgreSQL and Vault only accessible from localhost or VPN)

**Layer 3: Application Security**
- ✅ Hard limits (max order size, max daily volume, max position size)
- ✅ Kill switch (emergency stop for all trading)
- ✅ Withdrawal controls (manual approval for withdrawals > $X)
- ✅ Input validation (sanitize all user inputs)

**Layer 4: Operational Security**
- ✅ Audit logs (immutable, tamper-evident trade history)
- ✅ Daily reconciliation (exchange vs. local ledger)
- ✅ Alert on anomalies (unexpected withdrawals, large losses)
- ✅ Backup and disaster recovery (daily DB backups, encrypted)

**Layer 5: Compliance**
- ✅ KYC/AML documentation (stored securely, shared only with exchanges)
- ✅ Tax reporting (Form 8949 data from trade logs)
- ✅ Recordkeeping (7-year retention for IRS)

---

## Prerequisites

### System Requirements

**Minimum**:
- **OS**: Linux (Ubuntu 22.04+, Debian 11+) or macOS
- **CPU**: 2 cores
- **RAM**: 4 GB
- **Disk**: 20 GB SSD
- **Network**: Stable internet, low latency to exchange APIs

**Recommended (Production)**:
- **CPU**: 4+ cores
- **RAM**: 8+ GB
- **Disk**: 50+ GB SSD
- **Hosting**: AWS EC2 (t3.medium), DigitalOcean Droplet, or dedicated server

### Software Dependencies

- **Docker**: 24.0+ and Docker Compose 2.0+
- **Python**: 3.11+ (if running outside Docker)
- **PostgreSQL**: 15+ (included in Docker Compose)
- **Git**: For version control
- **(Optional) Vault**: If self-hosting secrets management

### Exchange Accounts

**Supported Exchanges**:
- **Crypto**: Coinbase Pro, Kraken, Binance.US, Gemini, Bitfinex
- **Stocks**: Alpaca (commission-free, API-first)
- **Forex**: OANDA, Interactive Brokers (via CCXT)

**Account Setup**:
1. Complete KYC with exchange (provide ID, proof of address, SSN/EIN)
2. Link corporate bank account (for fiat deposits/withdrawals)
3. Enable 2FA (YubiKey or Google Authenticator)
4. Generate API keys:
   - **Read-only key** (for balance checks, order history)
   - **Trade key** (for placing orders, NO withdrawal permission)
   - **Withdrawal key** (separate key, manually approved only)

---

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/veteranholdingco/ccxt-starter.git
cd ccxt-starter
```

### 2. Configure Secrets

**Option A: Vault (Recommended for Production)**

```bash
# Start Vault in dev mode (for testing only; use prod mode with TLS in production)
docker run --cap-add=IPC_LOCK -d --name=vault -p 8200:8200 vault

# Set Vault address
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='your-root-token'

# Store API keys
vault kv put secret/exchanges/coinbase \
  api_key="YOUR_COINBASE_API_KEY" \
  api_secret="YOUR_COINBASE_API_SECRET" \
  passphrase="YOUR_COINBASE_PASSPHRASE"

vault kv put secret/exchanges/kraken \
  api_key="YOUR_KRAKEN_API_KEY" \
  api_secret="YOUR_KRAKEN_API_SECRET"
```

**Option B: AWS Secrets Manager (Cloud-Native)**

```bash
# Store secrets using AWS CLI
aws secretsmanager create-secret \
  --name trading/exchanges/coinbase \
  --secret-string '{"api_key":"YOUR_KEY","api_secret":"YOUR_SECRET","passphrase":"YOUR_PASSPHRASE"}'

aws secretsmanager create-secret \
  --name trading/exchanges/kraken \
  --secret-string '{"api_key":"YOUR_KEY","api_secret":"YOUR_SECRET"}'
```

**Option C: .env File (Dev/Testing Only - NEVER commit to git)**

```bash
cp config/.env.example config/.env
nano config/.env

# Add your keys (DO NOT commit this file)
COINBASE_API_KEY=your_key_here
COINBASE_API_SECRET=your_secret_here
COINBASE_PASSPHRASE=your_passphrase_here
```

### 3. Start the Stack

```bash
# Start PostgreSQL, Vault (if self-hosting), and Prometheus
docker-compose up -d

# Verify all containers are running
docker-compose ps
```

### 4. Run Paper Trading Test

```bash
# Install Python dependencies
pip install -r requirements.txt

# Run a simple buy/sell test (paper trading mode)
python scripts/paper_trade_test.py

# Check logs
tail -f logs/trading.log
```

### 5. Run Reconciliation

```bash
# Daily reconciliation (compare exchange vs. local DB)
python scripts/reconcile.py --exchange coinbase --date 2025-01-23

# Output: reconciliation_report_2025-01-23.csv
```

---

## Configuration

### config/trading_config.yaml

**Purpose**: Define risk limits, exchange preferences, and operational parameters.

```yaml
# Trading Configuration
version: "1.0"

# Exchanges
exchanges:
  coinbase:
    enabled: true
    sandbox: false  # Set to true for testnet/paper trading
    rate_limit: 10  # API calls per second (stay below exchange limits)
    ip_allowlist:
      - "203.0.113.5"  # Your server IP
      - "203.0.113.6"  # Backup server IP
  kraken:
    enabled: true
    sandbox: false
    rate_limit: 15

# Risk Limits
risk:
  max_order_value: 10000  # USD (single order)
  max_daily_volume: 50000  # USD (across all exchanges)
  max_position_size: 25000  # USD (per asset)
  max_drawdown_pct: 15  # Stop trading if portfolio drops 15%
  kill_switch_enabled: true  # Emergency stop

# Withdrawal Controls
withdrawals:
  auto_approve_under: 0  # USD (0 = all withdrawals require manual approval)
  approval_method: "email"  # email, SMS, or manual (via dashboard)
  recipient_allowlist:
    - "0x1234567890abcdef1234567890abcdef12345678"  # Whitelisted wallet
    - "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"  # Whitelisted BTC address

# Logging
logging:
  level: INFO  # DEBUG, INFO, WARNING, ERROR
  retention_days: 2555  # 7 years for IRS compliance
  immutable: true  # Append-only logs (tamper-evident)

# Reconciliation
reconciliation:
  frequency: "daily"  # daily, hourly, or manual
  alert_threshold: 0.01  # USD (alert if discrepancy > 1 cent)

# Monitoring
monitoring:
  prometheus_port: 9090
  grafana_port: 3000
  healthcheck_interval: 60  # seconds
```

### Secrets Configuration

**Vault Path Conventions**:
- `secret/exchanges/{exchange_name}` - API keys
- `secret/wallets/{chain}` - Private keys (if applicable)
- `secret/database` - PostgreSQL credentials
- `secret/monitoring` - Grafana admin password

**AWS Secrets Manager Naming**:
- `trading/exchanges/{exchange_name}`
- `trading/wallets/{chain}`
- `trading/database`

---

## Reconciliation Script

### Purpose

Compares exchange-reported balances and trade history with local PostgreSQL ledger to detect:
- Missing trades (API call failed, network issue)
- Phantom trades (logged locally but not executed)
- Balance discrepancies (withdrawal, deposit, fee miscalculation)
- Unauthorized activity (unexpected trades or withdrawals)

### How It Works

```
1. Fetch exchange data (balances, trades, deposits, withdrawals)
   ↓
2. Query local database (PostgreSQL ledger)
   ↓
3. Compare and identify discrepancies
   ↓
4. Generate report (CSV + alert if threshold exceeded)
   ↓
5. Optional: Auto-sync (update local DB with missing trades)
```

### Usage

```bash
# Reconcile all exchanges for yesterday
python scripts/reconcile.py --date yesterday

# Reconcile specific exchange for date range
python scripts/reconcile.py --exchange kraken --start 2025-01-01 --end 2025-01-23

# Reconcile and auto-sync missing trades
python scripts/reconcile.py --date today --auto-sync

# Output location
# reports/reconciliation_2025-01-23.csv
```

### Sample Output

**reconciliation_2025-01-23.csv**:

| Exchange | Asset | Local Balance | Exchange Balance | Discrepancy | Status |
|----------|-------|--------------|------------------|-------------|--------|
| Coinbase | BTC | 0.12345 | 0.12345 | 0.00000 | ✅ OK |
| Coinbase | USD | 5000.00 | 4998.50 | -1.50 | ⚠️ Fee mismatch |
| Kraken | ETH | 2.5000 | 2.5000 | 0.0000 | ✅ OK |
| Kraken | USD | 10000.00 | 10025.00 | +25.00 | 🔴 Missing deposit |

**Alert Triggered**: Email sent to admin for Kraken USD discrepancy.

### Reconciliation Script (Pseudocode)

See `scripts/reconcile.py` (full implementation below).

---

## Risk Controls

### Hard Limits (Pre-Trade Validation)

**Enforced BEFORE order is placed**:
- Order value ≤ max_order_value
- Daily volume ≤ max_daily_volume
- Position size ≤ max_position_size
- Sufficient balance (available funds - reserved funds)

**Example**:
```python
def validate_order(order, config):
    if order.value > config['risk']['max_order_value']:
        raise RiskLimitExceeded(f"Order value {order.value} exceeds limit {config['risk']['max_order_value']}")

    daily_volume = get_daily_volume()
    if daily_volume + order.value > config['risk']['max_daily_volume']:
        raise RiskLimitExceeded(f"Daily volume limit exceeded")

    # More checks...
```

### Kill Switch

**Purpose**: Immediately halt all trading and cancel open orders.

**Triggers**:
- Manual activation (admin dashboard or CLI)
- Max drawdown exceeded (portfolio down 15%)
- Anomaly detection (e.g., 10 failed orders in 5 minutes)
- Security incident (suspected API key compromise)

**Implementation**:
```bash
# Manual kill switch
python scripts/kill_switch.py --activate --reason "Suspected unauthorized access"

# Check status
python scripts/kill_switch.py --status

# Deactivate (after investigation)
python scripts/kill_switch.py --deactivate --auth-code YOUR_2FA_CODE
```

### Withdrawal Controls

**Policy**: ALL withdrawals require manual approval (email or SMS confirmation).

**Workflow**:
1. Strategy or admin initiates withdrawal request
2. System logs request (pending status)
3. Email sent to admin with approval link
4. Admin clicks link (with 2FA code)
5. Withdrawal executed
6. Confirmation email sent

**Auto-Approve (Optional)**:
- Amounts under $X to whitelisted addresses
- Requires config: `withdrawals.auto_approve_under: 500`

---

## Deployment

### Local Development (Docker Compose)

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f trading-app

# Stop all services
docker-compose down
```

### Production (AWS EC2)

**1. Launch EC2 Instance**
- AMI: Ubuntu 22.04
- Instance type: t3.medium (2 vCPU, 4 GB RAM)
- Storage: 50 GB gp3 SSD
- Security group: Allow SSH (22), HTTPS (443), Prometheus (9090), Grafana (3000)

**2. Install Docker**
```bash
sudo apt update
sudo apt install -y docker.io docker-compose
sudo systemctl enable docker
sudo usermod -aG docker ubuntu
```

**3. Clone Repo and Configure**
```bash
git clone https://github.com/veteranholdingco/ccxt-starter.git
cd ccxt-starter
cp config/.env.example config/.env
nano config/.env  # Add production secrets
```

**4. Use AWS Secrets Manager**
```bash
# Install AWS CLI
sudo apt install -y awscli

# Configure IAM role (attach to EC2 instance)
# Policy: SecretsManagerReadWrite

# Update docker-compose.yml to use AWS Secrets
# See docker/docker-compose-aws.yml
docker-compose -f docker/docker-compose-aws.yml up -d
```

**5. Set Up Monitoring**
- Access Grafana: `http://your-ec2-ip:3000` (admin/admin)
- Import dashboard: `grafana-dashboards/trading-overview.json`

**6. Enable Auto-Start**
```bash
# Create systemd service
sudo nano /etc/systemd/system/ccxt-trading.service

# Paste:
[Unit]
Description=CCXT Trading Stack
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/home/ubuntu/ccxt-starter
ExecStart=/usr/bin/docker-compose up -d
ExecStop=/usr/bin/docker-compose down
User=ubuntu

[Install]
WantedBy=multi-user.target

# Enable
sudo systemctl enable ccxt-trading
sudo systemctl start ccxt-trading
```

### Production (Managed Kubernetes - Future)

**For Enterprise clients with high-frequency trading**:
- Deploy to AWS EKS, GCP GKE, or DigitalOcean Kubernetes
- Use Helm chart (see `k8s/helm-chart/`)
- Horizontal autoscaling based on API call volume

---

## Monitoring

### Metrics (Prometheus)

**Key Metrics**:
- `trading_orders_total` (counter) - Total orders placed
- `trading_orders_filled` (counter) - Successfully filled orders
- `trading_orders_rejected` (counter) - Rejected orders (risk limits, API errors)
- `trading_balance_usd` (gauge) - Total portfolio value in USD
- `trading_pnl_daily_usd` (gauge) - Daily profit/loss
- `trading_api_latency_ms` (histogram) - Exchange API response time
- `trading_reconciliation_discrepancy_usd` (gauge) - Balance mismatch

### Dashboards (Grafana)

**Pre-Built Dashboards**:
1. **Trading Overview** - Orders, fills, PnL, balance
2. **Risk Metrics** - Daily volume, position sizes, drawdown
3. **System Health** - API latency, error rates, uptime
4. **Reconciliation** - Discrepancies over time

**Import**:
```bash
# In Grafana UI:
# + > Import > Upload JSON file > select grafana-dashboards/trading-overview.json
```

### Alerts

**Configured in Prometheus** (`prometheus/alerts.yml`):

- **High Discrepancy**: Reconciliation mismatch > $100
- **Max Drawdown**: Portfolio down 10% (warning), 15% (critical)
- **Failed Orders**: > 5 failed orders in 5 minutes
- **API Downtime**: Exchange API unavailable for > 2 minutes

**Alert Destinations**:
- Email (via SMTP)
- SMS (via Twilio)
- Slack (webhook)

---

## Compliance & Tax

### Trade Logging for IRS

**Requirements**:
- Log ALL trades (date, time, asset, quantity, price, exchange, fees)
- Retain for 7 years (IRS statute of limitations)
- Generate Form 8949 data (capital gains/losses)

**Database Schema** (PostgreSQL):

```sql
CREATE TABLE trades (
  id SERIAL PRIMARY KEY,
  timestamp TIMESTAMP NOT NULL,
  exchange VARCHAR(50) NOT NULL,
  order_id VARCHAR(100) UNIQUE NOT NULL,
  side VARCHAR(10) NOT NULL,  -- buy, sell
  asset VARCHAR(20) NOT NULL,  -- BTC, ETH, AAPL
  quantity DECIMAL(18, 8) NOT NULL,
  price DECIMAL(18, 8) NOT NULL,
  fee DECIMAL(18, 8) DEFAULT 0,
  fee_asset VARCHAR(20),
  total_usd DECIMAL(18, 2) NOT NULL,
  strategy VARCHAR(100),
  notes TEXT
);

CREATE INDEX idx_trades_timestamp ON trades(timestamp);
CREATE INDEX idx_trades_asset ON trades(asset);
```

### Tax Reporting Script

```bash
# Generate Form 8949 CSV for tax year
python scripts/tax_report.py --year 2025 --output tax_2025.csv

# Output: Columns required for Form 8949
# Date Acquired, Date Sold, Proceeds, Cost Basis, Gain/Loss
```

### KYC/AML Documentation

**Stored Securely**:
- Copy of government ID (driver's license, passport)
- Proof of address (utility bill, bank statement)
- EIN confirmation letter (for LLC/Corp accounts)
- Operating agreement or trust instrument (for entity accounts)

**Storage**:
- Encrypted S3 bucket (AES-256, access logging enabled)
- Retention: Permanent (for regulatory compliance)
- Access: Admin only, 2FA required

---

## Troubleshooting

### Common Issues

**1. API Key Invalid / Unauthorized**
- **Symptom**: `AuthenticationError: Invalid API key`
- **Fix**: Verify API key and secret in Vault/Secrets Manager. Check IP allowlist on exchange.

**2. Insufficient Balance**
- **Symptom**: `InsufficientFunds: Not enough balance`
- **Fix**: Check available balance (not total balance). Ensure funds not reserved in open orders.

**3. Reconciliation Discrepancy**
- **Symptom**: Local balance ≠ exchange balance
- **Fix**: Run `reconcile.py --auto-sync` to fetch missing trades. Check for manual withdrawals/deposits not logged locally.

**4. Rate Limit Exceeded**
- **Symptom**: `RateLimitExceeded: Too many requests`
- **Fix**: Reduce `rate_limit` in config. Use CCXT's built-in rate limiter (`enableRateLimit: true`).

**5. Database Connection Error**
- **Symptom**: `psycopg2.OperationalError: could not connect to server`
- **Fix**: Verify PostgreSQL container running (`docker-compose ps`). Check credentials in `.env`.

### Logs

**Locations**:
- Application logs: `logs/trading.log`
- Docker logs: `docker-compose logs -f trading-app`
- PostgreSQL logs: `docker-compose logs -f postgres`
- Vault logs: `docker-compose logs -f vault`

**Log Levels**:
- DEBUG: Verbose (API calls, order details)
- INFO: Standard (order placed, filled, reconciliation)
- WARNING: Potential issues (high latency, near risk limit)
- ERROR: Failures (API error, database error, order rejected)

---

## Roadmap

### Phase 1: Core Infrastructure (Complete)
- ✅ CCXT integration
- ✅ PostgreSQL trade ledger
- ✅ Secrets management (Vault/AWS)
- ✅ Risk controls (hard limits, kill switch)
- ✅ Reconciliation script
- ✅ Docker Compose deployment

### Phase 2: Monitoring & Alerts (Complete)
- ✅ Prometheus metrics
- ✅ Grafana dashboards
- ✅ Email/SMS alerts

### Phase 3: Strategy Framework (In Progress)
- 🔄 Plugin architecture for custom strategies
- 🔄 Backtesting framework (historical data)
- 🔄 Paper trading mode (live data, fake orders)

### Phase 4: Advanced Features (Planned)
- ⏳ Multi-account support (manage multiple exchanges/clients)
- ⏳ DCA (dollar-cost averaging) scheduler
- ⏳ Rebalancing automation (maintain target portfolio allocation)
- ⏳ Tax-loss harvesting (automatic loss realization for tax benefits)

### Phase 5: Enterprise Features (Future)
- ⏳ Kubernetes deployment (Helm chart)
- ⏳ Multi-tenancy (SaaS offering for multiple veteran clients)
- ⏳ White-label UI (custom branding for VSOs)

---

## Support

### Documentation
- **Full Docs**: `/docs` folder
- **API Reference**: `/docs/api.md`
- **Security Best Practices**: `/docs/security.md`

### Contact
- **Platform Support**: support@veteranholdingco.com
- **Security Issues**: security@veteranholdingco.com (PGP key available)
- **GitHub Issues**: https://github.com/veteranholdingco/ccxt-starter/issues

### Training
- **Video Walkthrough**: [YouTube Playlist](https://youtube.com/playlist?list=xxx)
- **Live Onboarding**: Included with Growth/Enterprise packages

---

## License

**MIT License** (permissive, allows commercial use)

```
Copyright (c) 2025 Veteran Holding Company Platform

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

[Full MIT License text...]
```

---

## Disclaimer

**This software is provided for operational purposes only. It is NOT investment advice.**

- No warranties or guarantees of profitability
- Trading involves risk of loss
- Past performance does not indicate future results
- Consult a licensed financial advisor before trading
- Ensure compliance with local regulations (SEC, CFTC, FinCEN)

**The platform is not a registered investment advisor, broker-dealer, or money manager.**

---

**Veteran Holding Company Platform**
*Empowering veterans with secure, compliant trading infrastructure.*

**Built with ❤️ for veterans, by veterans.**
