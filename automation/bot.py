#!/usr/bin/env python3
"""
Telegram Bot - The Actuator
Handles commands, push notifications, and serves as the portable interface.
"""

import os
import asyncio
import logging
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

from brain import ask_claude, triage_alert, analyze_recon

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Config
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
ALLOWED_USERS = [int(x) for x in os.getenv("TELEGRAM_ALLOWED_USERS", "").split(",") if x]


def auth_required(func):
    """Decorator to restrict commands to allowed users."""
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if ALLOWED_USERS and update.effective_user.id not in ALLOWED_USERS:
            await update.message.reply_text("Unauthorized.")
            return
        return await func(update, context)
    return wrapper


# ============ COMMANDS ============

@auth_required
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Welcome message and command list."""
    msg = """*Couch.Potato Automation Bot*

Commands:
/ask <question> - Ask Claude anything
/triage <alert> - Triage an alert/finding
/recon <data> - Analyze recon output
/status - System status
/help - Show this message

Just send text to chat with Claude directly."""
    await update.message.reply_text(msg, parse_mode="Markdown")


@auth_required
async def ask(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Ask Claude a question."""
    if not context.args:
        await update.message.reply_text("Usage: /ask <your question>")
        return

    question = " ".join(context.args)
    await update.message.reply_text("Thinking...")

    response = await ask_claude(question)
    await update.message.reply_text(response[:4000])  # Telegram limit


@auth_required
async def triage(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Triage an alert or finding."""
    if not context.args:
        await update.message.reply_text("Usage: /triage <alert details>")
        return

    alert = " ".join(context.args)
    await update.message.reply_text("Analyzing...")

    result = await triage_alert(alert)
    await update.message.reply_text(result[:4000])


@auth_required
async def recon(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Analyze recon output."""
    if not context.args:
        await update.message.reply_text("Usage: /recon <paste recon output>")
        return

    data = " ".join(context.args)
    await update.message.reply_text("Analyzing recon data...")

    analysis = await analyze_recon(data)
    await update.message.reply_text(analysis[:4000])


@auth_required
async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """System status check."""
    import platform
    import psutil

    cpu = psutil.cpu_percent()
    mem = psutil.virtual_memory().percent

    msg = f"""*System Status*
Host: {platform.node()}
CPU: {cpu}%
Memory: {mem}%
Bot: Running"""
    await update.message.reply_text(msg, parse_mode="Markdown")


@auth_required
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle plain text messages - direct chat with Claude."""
    text = update.message.text
    await update.message.reply_text("Thinking...")

    response = await ask_claude(text)
    await update.message.reply_text(response[:4000])


# ============ NOTIFICATIONS ============

async def send_notification(app: Application, chat_id: int, message: str):
    """Send a push notification to a chat."""
    await app.bot.send_message(chat_id=chat_id, text=message)


# ============ MAIN ============

def main():
    if not BOT_TOKEN:
        logger.error("TELEGRAM_BOT_TOKEN not set")
        return

    app = Application.builder().token(BOT_TOKEN).build()

    # Register handlers
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", start))
    app.add_handler(CommandHandler("ask", ask))
    app.add_handler(CommandHandler("triage", triage))
    app.add_handler(CommandHandler("recon", recon))
    app.add_handler(CommandHandler("status", status))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    logger.info("Bot starting...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
