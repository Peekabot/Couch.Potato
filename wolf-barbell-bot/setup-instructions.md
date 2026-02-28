# Setup Instructions

## 1. Prerequisites

- n8n instance (cloud or self-hosted)
- Telegram bot token (from @BotFather)
- Google Sheets API access
- API keys: TwelveData, Polygon (optional), Alpaca (optional)

## 2. Telegram Bot Setup

1. Open Telegram, search @BotFather
2. Send `/newbot` and follow prompts
3. Save the token
4. Get your chat ID: send a message to @userinfobot
5. Replace `YOUR_TELEGRAM_CHAT_ID` in all workflows

## 3. Google Sheets Setup

1. Create a new Google Sheet
2. Share with the email from n8n Google OAuth
3. Create tabs:
   - `Insider Log`
   - `Burry Capex Log`
   - `Reality Log`
   - `Portfolio Core`
   - `Rebalance Log`
4. Copy Sheet ID from URL

## 4. API Keys

### TwelveData (free tier)
- Sign up at twelvedata.com
- Get API key from dashboard
- Replace `YOUR_API_KEY` in price fetch nodes

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

1. Run GME tracker manually → should fetch recent filings
2. Check Reality Bridge with test payload
3. Enable schedules only after manual tests pass
4. Start with paper mode (Alpaca) before live

## 7. Security Notes

- Never commit API keys to GitHub
- Use n8n credentials for sensitive data
- Set up 2FA on all accounts
- Start with tiny position sizes
