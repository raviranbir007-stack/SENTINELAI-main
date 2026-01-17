from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict

from ..config import settings


class NotificationEngine:
    @staticmethod
    async def send_email(recipient: str, subject: str, body: str) -> bool:
        """Send email notification"""
        try:
            msg = MIMEMultipart()
            msg["From"] = settings.FROM_EMAIL
            msg["To"] = recipient
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "html"))

            # Send email (implement actual SMTP logic)
            return True
        except Exception:
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
