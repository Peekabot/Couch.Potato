"""
Email notification module
Send email reports via SMTP
"""

import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime

logger = logging.getLogger(__name__)


def send_email_report(config, subject, body, attachments=None):
    """
    Send email report via SMTP

    Args:
        config: Email configuration dict with keys:
                - email_to: Recipient email
                - smtp_server: SMTP server address
                - smtp_port: SMTP port (usually 587 for TLS)
                - smtp_user: SMTP username
                - smtp_password: SMTP password
        subject: Email subject
        body: Email body (plain text or HTML)
        attachments: List of file paths to attach

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = config.get('smtp_user')
        msg['To'] = config.get('email_to')
        msg['Subject'] = subject
        msg['Date'] = datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')

        # Add body
        msg.attach(MIMEText(body, 'plain'))

        # Add attachments
        if attachments:
            for file_path in attachments:
                try:
                    with open(file_path, 'rb') as f:
                        part = MIMEBase('application', 'octet-stream')
                        part.set_payload(f.read())
                        encoders.encode_base64(part)
                        part.add_header(
                            'Content-Disposition',
                            f'attachment; filename= {file_path.split("/")[-1]}'
                        )
                        msg.attach(part)
                except Exception as e:
                    logger.warning(f"Failed to attach {file_path}: {e}")

        # Send email
        server = smtplib.SMTP(config['smtp_server'], config['smtp_port'])
        server.starttls()
        server.login(config['smtp_user'], config['smtp_password'])
        server.send_message(msg)
        server.quit()

        logger.info(f"Email sent to {config['email_to']}")
        return True

    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        return False


def send_html_email(config, subject, html_body, attachments=None):
    """
    Send HTML email report

    Args:
        config: Email configuration dict
        subject: Email subject
        html_body: HTML formatted email body
        attachments: List of file paths to attach

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = config.get('smtp_user')
        msg['To'] = config.get('email_to')
        msg['Subject'] = subject

        # Add HTML body
        html_part = MIMEText(html_body, 'html')
        msg.attach(html_part)

        # Add attachments
        if attachments:
            for file_path in attachments:
                try:
                    with open(file_path, 'rb') as f:
                        part = MIMEBase('application', 'octet-stream')
                        part.set_payload(f.read())
                        encoders.encode_base64(part)
                        part.add_header(
                            'Content-Disposition',
                            f'attachment; filename= {file_path.split("/")[-1]}'
                        )
                        msg.attach(part)
                except Exception as e:
                    logger.warning(f"Failed to attach {file_path}: {e}")

        # Send
        server = smtplib.SMTP(config['smtp_server'], config['smtp_port'])
        server.starttls()
        server.login(config['smtp_user'], config['smtp_password'])
        server.send_message(msg)
        server.quit()

        logger.info(f"HTML email sent to {config['email_to']}")
        return True

    except Exception as e:
        logger.error(f"Failed to send HTML email: {e}")
        return False


if __name__ == "__main__":
    # Test module
    import sys

    if len(sys.argv) < 2:
        print("Usage: python email_notify.py <to_email>")
        sys.exit(1)

    # Test configuration (use environment variables or config file in production)
    test_config = {
        'email_to': sys.argv[1],
        'smtp_server': 'smtp.gmail.com',
        'smtp_port': 587,
        'smtp_user': 'your_email@gmail.com',  # Replace with your email
        'smtp_password': 'your_app_password'   # Replace with app password
    }

    subject = "Test Email from Recon Agent"
    body = """
This is a test email from the Mobile AI Recon Agent.

If you receive this, email notifications are working correctly!

Time: {}
""".format(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    success = send_email_report(test_config, subject, body)
    print(f"Email sent: {success}")
