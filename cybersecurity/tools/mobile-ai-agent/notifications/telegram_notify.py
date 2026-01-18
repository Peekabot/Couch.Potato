"""
Telegram notification module
Send notifications via Telegram Bot API
"""

import requests
import logging

logger = logging.getLogger(__name__)


def send_telegram_message(bot_token, chat_id, message, parse_mode="Markdown"):
    """
    Send a message via Telegram Bot API

    Args:
        bot_token: Telegram bot token from @BotFather
        chat_id: Target chat ID
        message: Message text to send
        parse_mode: Message formatting (Markdown, HTML, or None)

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

        payload = {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": parse_mode
        }

        response = requests.post(url, json=payload, timeout=10)

        if response.status_code == 200:
            logger.info("Telegram message sent successfully")
            return True
        else:
            logger.error(f"Telegram API error: {response.status_code} - {response.text}")
            return False

    except Exception as e:
        logger.error(f"Failed to send Telegram message: {e}")
        return False


def send_telegram_document(bot_token, chat_id, file_path, caption=None):
    """
    Send a document via Telegram Bot API

    Args:
        bot_token: Telegram bot token
        chat_id: Target chat ID
        file_path: Path to file to send
        caption: Optional caption for the document

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        url = f"https://api.telegram.org/bot{bot_token}/sendDocument"

        with open(file_path, 'rb') as file:
            files = {'document': file}
            data = {'chat_id': chat_id}
            if caption:
                data['caption'] = caption

            response = requests.post(url, data=data, files=files, timeout=30)

            if response.status_code == 200:
                logger.info(f"Document sent successfully: {file_path}")
                return True
            else:
                logger.error(f"Telegram API error: {response.status_code}")
                return False

    except Exception as e:
        logger.error(f"Failed to send document: {e}")
        return False


def get_telegram_updates(bot_token):
    """
    Get updates from Telegram (for testing/debugging)

    Args:
        bot_token: Telegram bot token

    Returns:
        dict: Updates from Telegram API
    """
    try:
        url = f"https://api.telegram.org/bot{bot_token}/getUpdates"
        response = requests.get(url, timeout=10)

        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"Failed to get updates: {response.status_code}")
            return None

    except Exception as e:
        logger.error(f"Error getting updates: {e}")
        return None


if __name__ == "__main__":
    # Test module
    import sys

    if len(sys.argv) < 3:
        print("Usage: python telegram_notify.py <bot_token> <chat_id> [message]")
        print("To get chat ID: python telegram_notify.py <bot_token> get_updates")
        sys.exit(1)

    bot_token = sys.argv[1]

    if len(sys.argv) >= 3 and sys.argv[2] == "get_updates":
        # Get updates to find chat ID
        updates = get_telegram_updates(bot_token)
        if updates:
            print("Recent updates:")
            print(updates)
            if updates.get('result'):
                for update in updates['result']:
                    if 'message' in update:
                        print(f"\nChat ID: {update['message']['chat']['id']}")
    else:
        # Send test message
        chat_id = sys.argv[2]
        message = sys.argv[3] if len(sys.argv) > 3 else "Test message from Recon Agent 🤖"

        success = send_telegram_message(bot_token, chat_id, message)
        print(f"Message sent: {success}")
