# Setup Instructions

## 1. Prerequisites

- n8n instance (cloud or self-hosted) — v0.198+ required for paired item references in one-share-emotion
- Telegram bot token (from @BotFather)
- Google Sheets API access
- API keys: TwelveData (required for price feeds), Alpaca (optional, for live execution)
- No API key needed for SEC EDGAR — the workflows use the public REST API with a User-Agent header

## 2. Telegram Bot Setup

1. Open Telegram, search @BotFather
2. Send `/newbot` and follow prompts
3. Save the token
4. Get your chat ID: send a message to @userinfobot
5. Replace `YOUR_TELEGRAM_CHAT_ID` in all workflows

## 3. Google Sheets Setup

1. Create a new Google Sheet
2. Share with the email from n8n Google OAuth
3. Create tabs with these exact names (workflows reference them literally):
   - `Insider Log` — GME Form 4 audit trail (columns: accessionNumber, filingDate, currentPrice, insiderFloor, alertPriority)
   - `Burry Capex Log` — AI capex alerts
   - `Reality Log` — Paper trade friction simulation results
   - `Portfolio Core` — One row with a `Core Value` column (e.g. `Core Value | 100000`)
   - `Active Signals` — Signal state for the rebalancer. Two columns: `Signal` and `Active`. Add rows as needed:
     ```
     Signal | Active
     GME    | FALSE
     BURRY  | FALSE
     ```
     Set `Active` to `TRUE` to activate a signal, `FALSE` to deactivate. The rebalancer reads this live every Sunday.
   - `One Share Trades` — Open positions (columns: Symbol, Entry Price, Shares, Date, Notes)
   - `Rebalance Log` — Manual log of executed rebalances
4. Copy Sheet ID from URL (the long string between `/d/` and `/edit`)

## 4. API Keys

### TwelveData (free tier)
- Sign up at twelvedata.com
- Get API key from dashboard
- Replace `YOUR_API_KEY` in price fetch nodes
- Free tier limits: 8 requests/minute, 800/day — the workflows stay well within this
- Note: `price` field is returned as a string, not a number — the workflows handle this with `parseFloat()`

### SEC EDGAR (no key needed)
- All EDGAR API calls use the public data.sec.gov REST API
- The only requirement is a descriptive `User-Agent` header (already set in the workflows)
- Rate limit: 10 requests/second — easily safe for these workflows
- Update the User-Agent in all HTTP nodes from `admin@wolfbarbell.example.com` to your real email

### Alpaca (paper trading)
- Sign up at app.alpaca.markets
- Get API key and secret
- Use paper trading URL: https://paper-api.alpaca.markets

## 5. Importing to n8n

1. In n8n, click "Import from File"
2. Upload each JSON file
3. Update credentials in all HTTP nodes
4. Test with manual trigger first

## 6. Testing Flow

1. **GME tracker**: Run manually → should return filings from EDGAR submissions API. If it returns 0 items, no Form 4s were filed in the last 2 hours (that's normal — wait for a real filing or temporarily widen the cutoff to 48 hours for testing).
2. **Burry sensor**: Run manually → should return capex data for all 5 companies. If AMZN returns a SKIP error, it may be using an extension tag — this is a known caveat documented in the node.
3. **Rebalancer**: Set one signal to `TRUE` in the Active Signals sheet, run manually → should show REBALANCE in the Telegram message. Reset to `FALSE` after confirming.
4. **Reality Bridge**: POST a test payload to the webhook URL with `{ "price": 100, "side": "buy", "shares": 50, "avgVolume": 1000000 }`.
5. Enable schedules only after all manual tests pass.
6. Start with paper mode (Alpaca) before live.

## 7. Security Notes

- Never commit API keys to GitHub
- Use n8n credentials for sensitive data
- Set up 2FA on all accounts
- Start with tiny position sizes
