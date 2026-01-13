"""
Email notification service for PKI operations.

Supports multiple email backends: SMTP, SendGrid, Mailgun, AWS SES.
Handles graceful failure without disrupting PKI workflows.
"""

import logging
from typing import Optional, Dict, Any, List
from django.conf import settings
from django.contrib.auth.models import User
from django.template.loader import render_to_string
from django.utils.html import strip_tags

logger = logging.getLogger(__name__)


class EmailService:
    """Base email service class."""

    def __init__(self, app_settings):
        """
        Initialize email service with app settings.

        Args:
            app_settings: AppSettings instance with email configuration
        """
        self.settings = app_settings
        self.from_email = f"{app_settings.email_from_name} <{app_settings.email_from_address}>"

    def send_email(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        plain_content: Optional[str] = None
    ) -> bool:
        """
        Send an email.

        Args:
            to_email: Recipient email address
            subject: Email subject
            html_content: HTML email body
            plain_content: Plain text fallback (auto-generated if not provided)

        Returns:
            True if sent successfully, False otherwise
        """
        raise NotImplementedError("Subclasses must implement send_email")

    def send_test_email(self, to_email: str) -> bool:
        """Send a test email to verify configuration."""
        subject = "Pemly PKI - Test Email"
        html_content = render_to_string('emails/test_email.html', {
            'app_name': 'Pemly PKI'
        })
        plain_content = strip_tags(html_content)

        return self.send_email(to_email, subject, html_content, plain_content)


class SMTPEmailService(EmailService):
    """SMTP email backend."""

    def send_email(self, to_email: str, subject: str, html_content: str,
                   plain_content: Optional[str] = None) -> bool:
        """Send email via SMTP."""
        try:
            from django.core.mail import EmailMultiAlternatives, get_connection

            if plain_content is None:
                plain_content = strip_tags(html_content)

            # Configure SMTP backend dynamically
            connection = get_connection(
                backend='django.core.mail.backends.smtp.EmailBackend',
                host=self.settings.smtp_host,
                port=self.settings.smtp_port,
                username=self.settings.smtp_username,
                password=self.settings.get_smtp_password(),
                use_tls=self.settings.smtp_use_tls,
                use_ssl=self.settings.smtp_use_ssl,
                fail_silently=False,
            )

            email = EmailMultiAlternatives(
                subject=subject,
                body=plain_content,
                from_email=self.from_email,
                to=[to_email],
                connection=connection
            )
            email.attach_alternative(html_content, "text/html")
            email.send()

            logger.info(f"Email sent successfully via SMTP to {to_email}: {subject}")
            return True

        except Exception as e:
            logger.error(f"Failed to send email via SMTP to {to_email}: {e}", exc_info=True)
            return False


class SendGridEmailService(EmailService):
    """SendGrid API email backend."""

    def send_email(self, to_email: str, subject: str, html_content: str,
                   plain_content: Optional[str] = None) -> bool:
        """Send email via SendGrid API."""
        try:
            import sendgrid
            from sendgrid.helpers.mail import Mail, Email, To, Content

            if plain_content is None:
                plain_content = strip_tags(html_content)

            sg = sendgrid.SendGridAPIClient(api_key=self.settings.get_sendgrid_api_key())

            message = Mail(
                from_email=Email(self.settings.email_from_address, self.settings.email_from_name),
                to_emails=To(to_email),
                subject=subject,
                plain_text_content=Content("text/plain", plain_content),
                html_content=Content("text/html", html_content)
            )

            response = sg.send(message)

            if response.status_code >= 200 and response.status_code < 300:
                logger.info(f"Email sent successfully via SendGrid to {to_email}: {subject}")
                return True
            else:
                logger.error(f"SendGrid API returned status {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"Failed to send email via SendGrid to {to_email}: {e}", exc_info=True)
            return False


class MailgunEmailService(EmailService):
    """Mailgun API email backend."""

    def send_email(self, to_email: str, subject: str, html_content: str,
                   plain_content: Optional[str] = None) -> bool:
        """Send email via Mailgun API."""
        try:
            import requests

            if plain_content is None:
                plain_content = strip_tags(html_content)

            # Determine API endpoint based on region
            if self.settings.mailgun_region == 'eu':
                api_url = f"https://api.eu.mailgun.net/v3/{self.settings.mailgun_domain}/messages"
            else:
                api_url = f"https://api.mailgun.net/v3/{self.settings.mailgun_domain}/messages"

            response = requests.post(
                api_url,
                auth=("api", self.settings.get_mailgun_api_key()),
                data={
                    "from": self.from_email,
                    "to": to_email,
                    "subject": subject,
                    "text": plain_content,
                    "html": html_content
                }
            )

            if response.status_code == 200:
                logger.info(f"Email sent successfully via Mailgun to {to_email}: {subject}")
                return True
            else:
                logger.error(f"Mailgun API returned status {response.status_code}: {response.text}")
                return False

        except Exception as e:
            logger.error(f"Failed to send email via Mailgun to {to_email}: {e}", exc_info=True)
            return False


class SESEmailService(EmailService):
    """AWS SES email backend."""

    def send_email(self, to_email: str, subject: str, html_content: str,
                   plain_content: Optional[str] = None) -> bool:
        """Send email via AWS SES."""
        try:
            import boto3
            from botocore.exceptions import ClientError

            if plain_content is None:
                plain_content = strip_tags(html_content)

            client = boto3.client(
                'ses',
                region_name=self.settings.ses_region,
                aws_access_key_id=self.settings.get_ses_access_key_id(),
                aws_secret_access_key=self.settings.get_ses_secret_access_key()
            )

            response = client.send_email(
                Source=self.from_email,
                Destination={'ToAddresses': [to_email]},
                Message={
                    'Subject': {'Data': subject},
                    'Body': {
                        'Text': {'Data': plain_content},
                        'Html': {'Data': html_content}
                    }
                }
            )

            logger.info(f"Email sent successfully via AWS SES to {to_email}: {subject}")
            return True

        except ClientError as e:
            logger.error(f"AWS SES error sending to {to_email}: {e.response['Error']['Message']}", exc_info=True)
            return False
        except Exception as e:
            logger.error(f"Failed to send email via AWS SES to {to_email}: {e}", exc_info=True)
            return False


def get_email_service() -> Optional[EmailService]:
    """
    Get the configured email service instance.

    Returns:
        EmailService instance or None if email is disabled
    """
    from core.models import AppSettings

    app_settings = AppSettings.get()

    if not app_settings.email_enabled:
        logger.debug("Email notifications are disabled")
        return None

    backend = app_settings.email_backend

    if backend == 'smtp':
        return SMTPEmailService(app_settings)
    elif backend == 'sendgrid':
        return SendGridEmailService(app_settings)
    elif backend == 'mailgun':
        return MailgunEmailService(app_settings)
    elif backend == 'ses':
        return SESEmailService(app_settings)
    else:
        logger.error(f"Unknown email backend: {backend}")
        return None


def send_notification(
    to_user: User,
    notification_type: str,
    context: Dict[str, Any]
) -> bool:
    """
    Send a notification email to a user.

    Args:
        to_user: User to send notification to
        notification_type: Type of notification (maps to template)
        context: Template context data

    Returns:
        True if sent successfully, False otherwise
    """
    from core.models import AppSettings

    app_settings = AppSettings.get()

    # Check if this notification type is enabled
    notification_flags = {
        'request_submitted': app_settings.notify_on_request_submitted,
        'request_approved': app_settings.notify_on_request_approved,
        'request_rejected': app_settings.notify_on_request_rejected,
        'certificate_revoked': app_settings.notify_on_certificate_revoked,
        'expiration_warning': app_settings.notify_expiration_warnings,
    }

    if not notification_flags.get(notification_type, True):
        logger.debug(f"Notification type {notification_type} is disabled")
        return False

    email_service = get_email_service()
    if not email_service:
        logger.debug("Email service not available")
        return False

    if not to_user.email:
        logger.warning(f"User {to_user.username} has no email address")
        return False

    try:
        # Render email template
        template_name = f'emails/{notification_type}.html'
        html_content = render_to_string(template_name, context)
        plain_content = strip_tags(html_content)

        # Get subject from context or use default
        subject = context.get('subject', f'Pemly PKI Notification: {notification_type}')

        return email_service.send_email(
            to_email=to_user.email,
            subject=subject,
            html_content=html_content,
            plain_content=plain_content
        )

    except Exception as e:
        logger.error(f"Error sending {notification_type} notification to {to_user.username}: {e}", exc_info=True)
        return False


def send_bulk_notification(
    users: List[User],
    notification_type: str,
    context: Dict[str, Any]
) -> int:
    """
    Send notification to multiple users.

    Args:
        users: List of users to notify
        notification_type: Type of notification
        context: Template context data

    Returns:
        Number of successfully sent emails
    """
    sent_count = 0
    for user in users:
        if send_notification(user, notification_type, context):
            sent_count += 1
    return sent_count
