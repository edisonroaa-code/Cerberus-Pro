import os
import smtplib
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
        """Internal method to send email (supports DEV mode log)"""
        
        if os.environ.get('ENVIRONMENT') == 'development' or not cls.SMTP_USER:
            logger.info(f"📧 [DEV EMAIL] To: {to_email} | Subject: {subject}")
            logger.info(f"📝 Body:\n{body}")
            # In DEV, we print to console instead of sending real email
            print(f"\n--- [SIMULATED EMAIL TO {to_email}] ---\nSubject: {subject}\n{body}\n--- END EMAIL ---\n")
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
