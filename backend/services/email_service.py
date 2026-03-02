import os
import smtplib
from pathlib import Path
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging

logger = logging.getLogger(__name__)

class EmailService:
    """Service to handle email notifications and password resets"""
    
    SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
    SMTP_USER = os.environ.get("SMTP_USER", "")
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
    FROM_EMAIL = os.environ.get("FROM_EMAIL", "no-reply@cerberus.corp")
    OUTBOX_DIR = os.environ.get("EMAIL_OUTBOX_DIR", "")
    
    @classmethod
    async def send_reset_email(cls, to_email: str, username: str, token: str):
        """Send password reset email with token"""
        reset_link = f"https://cerberus.corp/reset-password?token={token}" # Conceptual
        
        subject = "Cerberus Pro - Recuperación de Contraseña"
        body = f"""
        Hola {username},
        
        Se ha solicitado un restablecimiento de contraseña para tu cuenta en Cerberus Pro.
        
        Tu token de recuperación es: {token}
        
        Si no solicitaste esto, puedes ignorar este mensaje. Este token expirará en 1 hora.
        
        ---
        Cerberus Pro Security Team
        """
        
        await cls._send_email(to_email, subject, body)

    @classmethod
    async def _send_email(cls, to_email: str, subject: str, body: str):
        """Internal method to send email with SMTP or local outbox fallback."""
        if not cls.SMTP_USER:
            cls._write_local_outbox(to_email, subject, body, reason="missing_smtp_user")
            return

        try:
            msg = MIMEMultipart()
            msg['From'] = cls.FROM_EMAIL
            msg['To'] = to_email
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'plain'))
            
            with smtplib.SMTP(cls.SMTP_SERVER, cls.SMTP_PORT) as server:
                server.starttls()
                server.login(cls.SMTP_USER, cls.SMTP_PASSWORD)
                server.send_message(msg)
                
            logger.info(f"✅ Email sent successfully to {to_email}")
        except Exception as e:
            logger.error(f"❌ Failed to send email to {to_email}: {e}")
            cls._write_local_outbox(to_email, subject, body, reason=f"smtp_error:{type(e).__name__}")

    @classmethod
    def _write_local_outbox(cls, to_email: str, subject: str, body: str, reason: str):
        outbox_root = cls.OUTBOX_DIR or os.path.join(os.getcwd(), "var", "mail_outbox")
        Path(outbox_root).mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_recipient = "".join(ch for ch in to_email if ch.isalnum() or ch in ("@", ".", "_", "-")).replace("@", "_at_")
        filename = f"{stamp}_{safe_recipient}.eml"
        destination = Path(outbox_root) / filename
        envelope = (
            f"X-Cerberus-Delivery: local-outbox\n"
            f"X-Cerberus-Reason: {reason}\n"
            f"From: {cls.FROM_EMAIL}\n"
            f"To: {to_email}\n"
            f"Subject: {subject}\n\n"
            f"{body.strip()}\n"
        )
        destination.write_text(envelope, encoding="utf-8")
        logger.warning(f"📨 Email written to local outbox: {destination}")
