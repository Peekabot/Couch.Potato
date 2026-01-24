-- Trading Database Schema
-- PostgreSQL initialization script

-- Trades table: Immutable audit log of all trades
CREATE TABLE IF NOT EXISTS trades (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    exchange VARCHAR(50) NOT NULL,
    order_id VARCHAR(100) UNIQUE NOT NULL,
    side VARCHAR(10) NOT NULL CHECK (side IN ('buy', 'sell')),
    asset VARCHAR(20) NOT NULL,
    quantity DECIMAL(18, 8) NOT NULL,
    price DECIMAL(18, 8) NOT NULL,
    fee DECIMAL(18, 8) DEFAULT 0,
    fee_asset VARCHAR(20),
    total_usd DECIMAL(18, 2) NOT NULL,
    strategy VARCHAR(100),
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX idx_trades_timestamp ON trades(timestamp);
CREATE INDEX idx_trades_exchange ON trades(exchange);
CREATE INDEX idx_trades_asset ON trades(asset);
CREATE INDEX idx_trades_order_id ON trades(order_id);

-- Balances table: Current snapshot (updated by reconciliation)
CREATE TABLE IF NOT EXISTS balances (
    id SERIAL PRIMARY KEY,
    exchange VARCHAR(50) NOT NULL,
    asset VARCHAR(20) NOT NULL,
    balance DECIMAL(18, 8) NOT NULL,
    available DECIMAL(18, 8) NOT NULL,
    reserved DECIMAL(18, 8) DEFAULT 0,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(exchange, asset)
);

CREATE INDEX idx_balances_exchange ON balances(exchange);

-- Orders table: Active and historical orders
CREATE TABLE IF NOT EXISTS orders (
    id SERIAL PRIMARY KEY,
    order_id VARCHAR(100) UNIQUE NOT NULL,
    exchange VARCHAR(50) NOT NULL,
    symbol VARCHAR(20) NOT NULL,
    side VARCHAR(10) NOT NULL CHECK (side IN ('buy', 'sell')),
    order_type VARCHAR(20) NOT NULL CHECK (order_type IN ('market', 'limit', 'stop_loss', 'stop_limit')),
    quantity DECIMAL(18, 8) NOT NULL,
    price DECIMAL(18, 8),
    status VARCHAR(20) NOT NULL CHECK (status IN ('pending', 'open', 'filled', 'partially_filled', 'canceled', 'rejected')),
    filled_quantity DECIMAL(18, 8) DEFAULT 0,
    avg_fill_price DECIMAL(18, 8),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_orders_status ON orders(status);
CREATE INDEX idx_orders_exchange ON orders(exchange);

-- Risk events table: Log all risk limit triggers and kill switch activations
CREATE TABLE IF NOT EXISTS risk_events (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    exchange VARCHAR(50),
    description TEXT NOT NULL,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_risk_events_created_at ON risk_events(created_at);
CREATE INDEX idx_risk_events_severity ON risk_events(severity);

-- Withdrawals table: All withdrawal requests (requires manual approval)
CREATE TABLE IF NOT EXISTS withdrawals (
    id SERIAL PRIMARY KEY,
    withdrawal_id VARCHAR(100) UNIQUE,
    exchange VARCHAR(50) NOT NULL,
    asset VARCHAR(20) NOT NULL,
    amount DECIMAL(18, 8) NOT NULL,
    destination_address TEXT NOT NULL,
    status VARCHAR(20) NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'completed', 'failed')),
    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    approved_at TIMESTAMP,
    approved_by VARCHAR(100),
    completed_at TIMESTAMP,
    tx_hash VARCHAR(100),
    notes TEXT
);

CREATE INDEX idx_withdrawals_status ON withdrawals(status);

-- Reconciliation log: Track daily reconciliation results
CREATE TABLE IF NOT EXISTS reconciliation_log (
    id SERIAL PRIMARY KEY,
    date DATE NOT NULL,
    exchange VARCHAR(50) NOT NULL,
    asset VARCHAR(20) NOT NULL,
    local_balance DECIMAL(18, 8) NOT NULL,
    exchange_balance DECIMAL(18, 8) NOT NULL,
    discrepancy DECIMAL(18, 8) NOT NULL,
    status VARCHAR(20) NOT NULL CHECK (status IN ('ok', 'mismatch', 'missing_trades')),
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(date, exchange, asset)
);

CREATE INDEX idx_reconciliation_date ON reconciliation_log(date);

-- Kill switch table: Current status and history
CREATE TABLE IF NOT EXISTS kill_switch (
    id SERIAL PRIMARY KEY,
    active BOOLEAN NOT NULL DEFAULT false,
    reason TEXT,
    activated_at TIMESTAMP,
    activated_by VARCHAR(100),
    deactivated_at TIMESTAMP,
    deactivated_by VARCHAR(100)
);

-- Insert initial kill switch record (inactive)
INSERT INTO kill_switch (active, reason) VALUES (false, 'System initialized');

-- Function to update timestamps automatically
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger for orders table
CREATE TRIGGER update_orders_updated_at BEFORE UPDATE ON orders
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Audit log for compliance (immutable)
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    user_id VARCHAR(100),
    action TEXT NOT NULL,
    metadata JSONB,
    ip_address INET,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);
CREATE INDEX idx_audit_log_event_type ON audit_log(event_type);

-- Permissions: Ensure trading_user can read/write
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO trading_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO trading_user;

-- Sample data for testing (optional, comment out for production)
-- INSERT INTO trades (timestamp, exchange, order_id, side, asset, quantity, price, fee, fee_asset, total_usd, strategy)
-- VALUES ('2025-01-23 10:30:00', 'coinbase', 'test-order-001', 'buy', 'BTC', 0.01, 50000, 5, 'USD', 500, 'manual');

COMMENT ON TABLE trades IS 'Immutable audit log of all executed trades';
COMMENT ON TABLE balances IS 'Current balances per exchange (updated by reconciliation)';
COMMENT ON TABLE orders IS 'Active and historical orders';
COMMENT ON TABLE risk_events IS 'Risk limit triggers and kill switch activations';
COMMENT ON TABLE withdrawals IS 'Withdrawal requests requiring manual approval';
COMMENT ON TABLE reconciliation_log IS 'Daily reconciliation results';
COMMENT ON TABLE kill_switch IS 'Emergency stop mechanism';
COMMENT ON TABLE audit_log IS 'Immutable audit trail for compliance';
