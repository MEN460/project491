"""
Email service utilities for sending transactional emails.

Handles password resets, notifications, and other system emails.
"""

from datetime import datetime
from typing import Optional

from flask import current_app, render_template
from flask_mailing import Mail, Message
from pydantic import EmailStr
from jinja2 import TemplateNotFound

# Initialize outside to allow reuse across app
mail = Mail()


class EmailService:
    @staticmethod
    async def send_email(
        to: EmailStr,
        subject: str,
        template: str = None,
        context: dict = None,
        body: str = None
    ) -> bool:
        """
        Send an email with either template or raw body.
        
        Args:
            to: Recipient email address
            subject: Email subject line
            template: Path to Jinja2 template (without extension)
            context: Variables for template rendering
            body: Raw text content (alternative to template)
            
        Returns:
            bool: True if email was sent successfully
        """
        if not any([template, body]):
            raise ValueError("Either template or body must be provided")

        # Prepare message
        msg = Message(
            subject=subject,
            recipients=[to],
            sender=current_app.config['MAIL_DEFAULT_SENDER']
        )

        try:
            # Try to use template if provided
            if template:
                msg.html = render_template(f"{template}.html", **context or {})
                msg.body = render_template(f"{template}.txt", **context or {})
            else:
                msg.body = body

            await mail.send_message(msg)
            current_app.logger.info(
                f"Email sent to {to} with subject: {subject}")
            return True

        except TemplateNotFound as e:
            current_app.logger.error(
                f"Email template not found: {template} - {str(e)}")
            return False
        except Exception as e:
            current_app.logger.error(f"Failed to send email to {to}: {str(e)}")
            return False

    @staticmethod
    async def send_password_reset(email: EmailStr, reset_token: str) -> bool:
        """Send password reset email with token."""
        reset_url = (
            f"{current_app.config['FRONTEND_BASE_URL']}/"
            f"reset-password?token={reset_token}"
        )

        return await EmailService.send_email(
            to=email,
            subject="Your Password Reset Request",
            template="emails/password_reset",
            context={
                'reset_url': reset_url,
                'expiry_minutes': current_app.config['PASSWORD_RESET_EXPIRE_MINUTES'],
                'support_email': current_app.config['SUPPORT_EMAIL']
            }
        )

    @staticmethod
    async def send_welcome_email(email: EmailStr, username: str) -> bool:
        """Send welcome email to new users."""
        return await EmailService.send_email(
            to=email,
            subject="Welcome to Mechanic Finder!",
            template="emails/welcome",
            context={
                'username': username,
                'login_url': f"{current_app.config['FRONTEND_BASE_URL']}/login",
                'support_email': current_app.config['SUPPORT_EMAIL']
            }
        )

    @staticmethod
    async def send_verification_email(email: EmailStr, verification_token: str) -> bool:
        """Send email verification email."""
        verify_url = (
            f"{current_app.config['FRONTEND_BASE_URL']}/"
            f"verify-email?token={verification_token}"
        )

        return await EmailService.send_email(
            to=email,
            subject="Verify Your Email Address",
            template="emails/verify_email",
            context={
                'verify_url': verify_url,
                'expiry_hours': 24,
                'support_email': current_app.config['SUPPORT_EMAIL']
            }
        )
