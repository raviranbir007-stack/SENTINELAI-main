from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import asyncio
import logging
import smtplib
from typing import Dict

from ..config import settings


logger = logging.getLogger(__name__)


class NotificationEngine:
    @staticmethod
    async def send_email(recipient: str, subject: str, body: str) -> bool:
        """Send email notification"""
        try:
            if not recipient:
                logger.warning("Email notification skipped: recipient missing")
                return False
            if not settings.SMTP_USERNAME or not settings.SMTP_PASSWORD:
                logger.warning("Email notification skipped: SMTP credentials not configured")
                return False

            msg = MIMEMultipart()
            msg["From"] = settings.FROM_EMAIL
            msg["To"] = recipient
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "html"))

            def _send_blocking():
                with smtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT, timeout=15) as server:
                    server.ehlo()
                    server.starttls()
                    server.ehlo()
                    server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                    server.sendmail(settings.FROM_EMAIL, [recipient], msg.as_string())

            await asyncio.to_thread(_send_blocking)
            return True
        except Exception as exc:
            logger.warning("Email notification failed: %s", exc)
            return False

    @staticmethod
    async def send_webhook(url: str, data: Dict) -> bool:
        """Send webhook notification"""
        import httpx

        try:
            async with httpx.AsyncClient() as client:
                await client.post(url, json=data)
            return True
        except Exception:
            return False
