#!/usr/bin/env python3
"""
Reconciliation Script - CCXT Trading Starter Kit

Compares exchange-reported balances and trades with local PostgreSQL ledger.
Detects discrepancies, missing trades, and unauthorized activity.

Usage:
    python reconcile.py --date yesterday
    python reconcile.py --exchange coinbase --start 2025-01-01 --end 2025-01-23
    python reconcile.py --date today --auto-sync

Author: Veteran Holding Company Platform
License: MIT
"""

import argparse
import ccxt
import csv
import logging
import os
import sys
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Dict, List, Tuple

import psycopg2
from psycopg2.extras import RealDictCursor

# Secrets management (choose one)
try:
    import hvac  # HashiCorp Vault
    SECRETS_BACKEND = 'vault'
except ImportError:
    try:
        import boto3  # AWS Secrets Manager
        SECRETS_BACKEND = 'aws'
    except ImportError:
        SECRETS_BACKEND = 'env'  # Fallback to environment variables

# Configuration
LOG_DIR = Path(__file__).parent.parent / 'logs'
REPORT_DIR = Path(__file__).parent.parent / 'reports'
LOG_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / 'reconciliation.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class SecretsManager:
    """Fetch API keys and credentials from Vault, AWS, or environment."""

    def __init__(self, backend: str = SECRETS_BACKEND):
        self.backend = backend
        if backend == 'vault':
            vault_addr = os.getenv('VAULT_ADDR', 'http://127.0.0.1:8200')
            vault_token = os.getenv('VAULT_TOKEN')
            self.client = hvac.Client(url=vault_addr, token=vault_token)
        elif backend == 'aws':
            self.client = boto3.client('secretsmanager')

    def get_exchange_credentials(self, exchange: str) -> Dict[str, str]:
        """Retrieve API key and secret for given exchange."""
        if self.backend == 'vault':
            secret_path = f'secret/exchanges/{exchange}'
            secret = self.client.secrets.kv.v2.read_secret_version(path=secret_path)
            return secret['data']['data']
        elif self.backend == 'aws':
            secret_name = f'trading/exchanges/{exchange}'
            response = self.client.get_secret_value(SecretId=secret_name)
            import json
            return json.loads(response['SecretString'])
        else:  # env
            return {
                'api_key': os.getenv(f'{exchange.upper()}_API_KEY'),
                'api_secret': os.getenv(f'{exchange.upper()}_API_SECRET'),
                'passphrase': os.getenv(f'{exchange.upper()}_PASSPHRASE')  # for Coinbase
            }

    def get_database_credentials(self) -> Dict[str, str]:
        """Retrieve PostgreSQL credentials."""
        if self.backend == 'vault':
            secret = self.client.secrets.kv.v2.read_secret_version(path='secret/database')
            return secret['data']['data']
        elif self.backend == 'aws':
            response = self.client.get_secret_value(SecretId='trading/database')
            import json
            return json.loads(response['SecretString'])
        else:
            return {
                'host': os.getenv('DB_HOST', 'localhost'),
                'port': os.getenv('DB_PORT', '5432'),
                'database': os.getenv('DB_NAME', 'trading'),
                'user': os.getenv('DB_USER', 'trading_user'),
                'password': os.getenv('DB_PASSWORD', 'changeme')
            }


class Database:
    """PostgreSQL interface for trade ledger."""

    def __init__(self, credentials: Dict[str, str]):
        self.conn = psycopg2.connect(**credentials)
        self.cursor = self.conn.cursor(cursor_factory=RealDictCursor)

    def get_balances(self, exchange: str, date: str) -> Dict[str, Decimal]:
        """Get balances from local ledger as of date."""
        query = """
            SELECT
                asset,
                SUM(CASE WHEN side = 'buy' THEN quantity ELSE -quantity END) as balance
            FROM trades
            WHERE exchange = %s
              AND DATE(timestamp) <= %s
            GROUP BY asset
            HAVING SUM(CASE WHEN side = 'buy' THEN quantity ELSE -quantity END) > 0
        """
        self.cursor.execute(query, (exchange, date))
        return {row['asset']: Decimal(row['balance']) for row in self.cursor.fetchall()}

    def get_trades(self, exchange: str, start_date: str, end_date: str) -> List[Dict]:
        """Get trades from local ledger within date range."""
        query = """
            SELECT * FROM trades
            WHERE exchange = %s
              AND DATE(timestamp) >= %s
              AND DATE(timestamp) <= %s
            ORDER BY timestamp
        """
        self.cursor.execute(query, (exchange, start_date, end_date))
        return self.cursor.fetchall()

    def insert_trade(self, trade: Dict):
        """Insert missing trade into local ledger."""
        query = """
            INSERT INTO trades
            (timestamp, exchange, order_id, side, asset, quantity, price, fee, fee_asset, total_usd, notes)
            VALUES (%(timestamp)s, %(exchange)s, %(order_id)s, %(side)s, %(asset)s,
                    %(quantity)s, %(price)s, %(fee)s, %(fee_asset)s, %(total_usd)s, %(notes)s)
            ON CONFLICT (order_id) DO NOTHING
        """
        self.cursor.execute(query, trade)
        self.conn.commit()

    def close(self):
        self.cursor.close()
        self.conn.close()


class Reconciler:
    """Reconciliation engine comparing exchange vs. local ledger."""

    def __init__(self, exchange_name: str, secrets_manager: SecretsManager):
        self.exchange_name = exchange_name
        self.secrets = secrets_manager

        # Initialize CCXT exchange
        credentials = self.secrets.get_exchange_credentials(exchange_name)
        exchange_class = getattr(ccxt, exchange_name)
        self.exchange = exchange_class({
            'apiKey': credentials['api_key'],
            'secret': credentials['api_secret'],
            'password': credentials.get('passphrase'),  # Coinbase only
            'enableRateLimit': True
        })

        # Initialize database
        db_creds = self.secrets.get_database_credentials()
        self.db = Database(db_creds)

    def get_exchange_balances(self) -> Dict[str, Decimal]:
        """Fetch current balances from exchange."""
        balance = self.exchange.fetch_balance()
        return {
            asset: Decimal(str(amount))
            for asset, amount in balance['total'].items()
            if amount > 0
        }

    def get_exchange_trades(self, start_timestamp: int, end_timestamp: int) -> List[Dict]:
        """Fetch trades from exchange within timestamp range."""
        all_trades = []
        markets = self.exchange.load_markets()

        for symbol in markets:
            try:
                trades = self.exchange.fetch_my_trades(
                    symbol=symbol,
                    since=start_timestamp,
                    limit=1000
                )
                all_trades.extend(trades)
            except Exception as e:
                logger.warning(f"Failed to fetch trades for {symbol}: {e}")

        return all_trades

    def compare_balances(self, date: str) -> List[Tuple[str, Decimal, Decimal, Decimal]]:
        """Compare exchange vs. local balances. Returns list of (asset, local, exchange, diff)."""
        local_balances = self.db.get_balances(self.exchange_name, date)
        exchange_balances = self.get_exchange_balances()

        all_assets = set(local_balances.keys()) | set(exchange_balances.keys())
        discrepancies = []

        for asset in all_assets:
            local = local_balances.get(asset, Decimal('0'))
            exchange = exchange_balances.get(asset, Decimal('0'))
            diff = exchange - local

            if abs(diff) > Decimal('0.00000001'):  # Tolerance for rounding errors
                discrepancies.append((asset, local, exchange, diff))

        return discrepancies

    def compare_trades(self, start_date: str, end_date: str) -> Tuple[List[Dict], List[Dict]]:
        """Compare exchange vs. local trades. Returns (missing_in_local, missing_in_exchange)."""
        # Convert dates to timestamps
        start_ts = int(datetime.strptime(start_date, '%Y-%m-%d').timestamp() * 1000)
        end_ts = int(datetime.strptime(end_date, '%Y-%m-%d').timestamp() * 1000) + 86400000

        exchange_trades = self.get_exchange_trades(start_ts, end_ts)
        local_trades = self.db.get_trades(self.exchange_name, start_date, end_date)

        # Create sets of order IDs
        exchange_order_ids = {t['order'] for t in exchange_trades}
        local_order_ids = {t['order_id'] for t in local_trades}

        missing_in_local = [t for t in exchange_trades if t['order'] not in local_order_ids]
        missing_in_exchange = [t for t in local_trades if t['order_id'] not in exchange_order_ids]

        return missing_in_local, missing_in_exchange

    def generate_report(self, date: str, discrepancies: List, missing_local: List,
                       missing_exchange: List, output_path: Path):
        """Generate CSV reconciliation report."""
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)

            # Balance discrepancies
            writer.writerow(['=== BALANCE DISCREPANCIES ==='])
            writer.writerow(['Exchange', 'Asset', 'Local Balance', 'Exchange Balance',
                           'Discrepancy', 'Status'])

            for asset, local, exchange, diff in discrepancies:
                status = '✅ OK' if abs(diff) < Decimal('0.01') else '🔴 MISMATCH'
                writer.writerow([self.exchange_name, asset, f'{local:.8f}',
                               f'{exchange:.8f}', f'{diff:.8f}', status])

            writer.writerow([])

            # Missing trades in local
            writer.writerow(['=== MISSING IN LOCAL DATABASE ==='])
            writer.writerow(['Order ID', 'Timestamp', 'Symbol', 'Side', 'Amount',
                           'Price', 'Fee'])

            for trade in missing_local:
                writer.writerow([
                    trade['order'],
                    datetime.fromtimestamp(trade['timestamp'] / 1000),
                    trade['symbol'],
                    trade['side'],
                    trade['amount'],
                    trade['price'],
                    trade.get('fee', {}).get('cost', 0)
                ])

            writer.writerow([])

            # Missing trades in exchange
            writer.writerow(['=== MISSING IN EXCHANGE (PHANTOM TRADES) ==='])
            writer.writerow(['Order ID', 'Timestamp', 'Asset', 'Side', 'Quantity',
                           'Price', 'Fee'])

            for trade in missing_exchange:
                writer.writerow([
                    trade['order_id'],
                    trade['timestamp'],
                    trade['asset'],
                    trade['side'],
                    trade['quantity'],
                    trade['price'],
                    trade['fee']
                ])

        logger.info(f"Report generated: {output_path}")

    def auto_sync(self, missing_trades: List[Dict]):
        """Sync missing trades from exchange to local database."""
        for trade in missing_trades:
            trade_data = {
                'timestamp': datetime.fromtimestamp(trade['timestamp'] / 1000),
                'exchange': self.exchange_name,
                'order_id': trade['order'],
                'side': trade['side'],
                'asset': trade['symbol'].split('/')[0],  # BTC/USD -> BTC
                'quantity': Decimal(str(trade['amount'])),
                'price': Decimal(str(trade['price'])),
                'fee': Decimal(str(trade.get('fee', {}).get('cost', 0))),
                'fee_asset': trade.get('fee', {}).get('currency'),
                'total_usd': Decimal(str(trade['cost'])),
                'notes': 'Auto-synced via reconciliation script'
            }
            self.db.insert_trade(trade_data)
            logger.info(f"Synced trade {trade_data['order_id']}")

    def reconcile(self, date: str, auto_sync: bool = False) -> Path:
        """Run full reconciliation for given date."""
        logger.info(f"Reconciling {self.exchange_name} for {date}")

        # Compare balances
        balance_discrepancies = self.compare_balances(date)

        # Compare trades (for the given date only)
        missing_local, missing_exchange = self.compare_trades(date, date)

        # Generate report
        output_path = REPORT_DIR / f'reconciliation_{self.exchange_name}_{date}.csv'
        self.generate_report(date, balance_discrepancies, missing_local,
                           missing_exchange, output_path)

        # Auto-sync if requested
        if auto_sync and missing_local:
            logger.info(f"Auto-syncing {len(missing_local)} missing trades")
            self.auto_sync(missing_local)

        # Alert if significant discrepancies
        total_discrepancy = sum(abs(diff) for _, _, _, diff in balance_discrepancies)
        if total_discrepancy > Decimal('1.00'):  # Alert threshold: $1
            logger.warning(f"⚠️ Total discrepancy: ${total_discrepancy:.2f}")
            # TODO: Send email/SMS alert

        return output_path

    def close(self):
        self.db.close()


def parse_args():
    parser = argparse.ArgumentParser(description='Reconcile exchange vs. local ledger')
    parser.add_argument('--exchange', type=str, help='Exchange name (e.g., coinbase, kraken)')
    parser.add_argument('--date', type=str, help='Date to reconcile (YYYY-MM-DD or "today"/"yesterday")')
    parser.add_argument('--start', type=str, help='Start date for range (YYYY-MM-DD)')
    parser.add_argument('--end', type=str, help='End date for range (YYYY-MM-DD)')
    parser.add_argument('--auto-sync', action='store_true',
                       help='Automatically sync missing trades to local DB')
    parser.add_argument('--all-exchanges', action='store_true',
                       help='Reconcile all configured exchanges')
    return parser.parse_args()


def parse_date(date_str: str) -> str:
    """Convert 'today', 'yesterday', or YYYY-MM-DD to YYYY-MM-DD."""
    if date_str == 'today':
        return datetime.now().strftime('%Y-%m-%d')
    elif date_str == 'yesterday':
        return (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
    else:
        # Validate format
        datetime.strptime(date_str, '%Y-%m-%d')
        return date_str


def main():
    args = parse_args()
    secrets = SecretsManager()

    # Determine exchanges to reconcile
    if args.all_exchanges:
        exchanges = ['coinbase', 'kraken', 'binanceus']  # Add all configured exchanges
    elif args.exchange:
        exchanges = [args.exchange]
    else:
        logger.error("Must specify --exchange or --all-exchanges")
        sys.exit(1)

    # Determine date(s)
    if args.date:
        dates = [parse_date(args.date)]
    elif args.start and args.end:
        start = datetime.strptime(args.start, '%Y-%m-%d')
        end = datetime.strptime(args.end, '%Y-%m-%d')
        dates = [(start + timedelta(days=i)).strftime('%Y-%m-%d')
                for i in range((end - start).days + 1)]
    else:
        logger.error("Must specify --date or --start/--end")
        sys.exit(1)

    # Run reconciliation
    for exchange_name in exchanges:
        reconciler = Reconciler(exchange_name, secrets)
        try:
            for date in dates:
                report_path = reconciler.reconcile(date, auto_sync=args.auto_sync)
                print(f"✅ Reconciliation complete: {report_path}")
        finally:
            reconciler.close()


if __name__ == '__main__':
    main()
