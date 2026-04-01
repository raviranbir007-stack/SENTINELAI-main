from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import asyncio
import logging
import smtplib
from typing import Dict, Iterable

from ..config import settings


logger = logging.getLogger(__name__)


class NotificationEngine:
    @staticmethod
    def _normalize_recipients(recipient: str | Iterable[str]) -> list[str]:
        if isinstance(recipient, str):
            raw_items = [p.strip() for p in recipient.replace(";", ",").split(",")]
        else:
            raw_items = []
            for value in recipient or []:
                if not value:
                    continue
                raw_items.extend([p.strip() for p in str(value).replace(";", ",").split(",")])

        normalized: list[str] = []
        seen = set()
        for item in raw_items:
            if not item or "@" not in item:
                continue
            key = item.lower()
            if key in seen:
                continue
            seen.add(key)
            normalized.append(item)
        return normalized

    @staticmethod
    async def send_email(recipient: str | Iterable[str], subject: str, body: str) -> bool:
        """Send email notification"""
        try:
            recipients = NotificationEngine._normalize_recipients(recipient)
            if not recipients:
                logger.warning("Email notification skipped: recipient missing")
                return False
            if not settings.SMTP_USERNAME or not settings.SMTP_PASSWORD:
                logger.warning("Email notification skipped: SMTP credentials not configured")
                return False

            msg = MIMEMultipart()
            msg["From"] = settings.FROM_EMAIL
            msg["To"] = ", ".join(recipients)
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "html"))

            def _send_blocking():
                with smtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT, timeout=15) as server:
                    server.ehlo()
                    server.starttls()
                    server.ehlo()
                    server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                    server.sendmail(settings.FROM_EMAIL, recipients, msg.as_string())

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
