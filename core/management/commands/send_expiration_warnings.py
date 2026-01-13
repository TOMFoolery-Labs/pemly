"""
Django management command to send certificate expiration warnings.

Run this command daily via cron to check for expiring certificates
and send notifications to certificate owners.
"""

import logging
from datetime import timedelta
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.urls import reverse

from core.models import Certificate, CertificateStatus, AppSettings, ExpirationWarningLog
from core.services.email import send_notification

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Send email notifications for certificates expiring soon'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be sent without actually sending emails',
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Send warnings even if already sent for this threshold',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        force = options['force']

        app_settings = AppSettings.get()

        if not app_settings.email_enabled:
            self.stdout.write(self.style.WARNING('Email notifications are disabled'))
            return

        if not app_settings.notify_expiration_warnings:
            self.stdout.write(self.style.WARNING('Expiration warnings are disabled'))
            return

        # Get warning thresholds (default: 30, 14, 7 days)
        warning_days = app_settings.expiration_warning_days or [30, 14, 7]

        self.stdout.write(f'Checking for certificates expiring within {warning_days} days...')

        total_sent = 0
        now = timezone.now()

        # Get all active certificates
        active_certs = Certificate.objects.filter(
            status=CertificateStatus.ACTIVE,
            not_after__isnull=False
        ).select_related('created_by', 'ca')

        for certificate in active_certs:
            days_until_expiry = (certificate.not_after - now).days

            # Check if certificate is within any warning threshold
            for threshold in warning_days:
                if days_until_expiry <= threshold:
                    # Check if we've already sent this warning
                    if not force:
                        already_sent = ExpirationWarningLog.objects.filter(
                            certificate=certificate,
                            warning_threshold=threshold
                        ).exists()

                        if already_sent:
                            continue

                    # Send notification
                    if dry_run:
                        self.stdout.write(
                            f'[DRY RUN] Would send {threshold}-day warning for '
                            f'{certificate.common_name} to {certificate.created_by.email}'
                        )
                        total_sent += 1
                    else:
                        # Build certificate URL - use a placeholder domain in management commands
                        # In production, configure your actual domain
                        certificate_url = f'/certificates/{certificate.pk}/'

                        success = send_notification(
                            to_user=certificate.created_by,
                            notification_type='expiration_warning',
                            context={
                                'subject': f'Certificate Expiring in {days_until_expiry} Days: {certificate.common_name}',
                                'certificate': certificate,
                                'days_until_expiry': days_until_expiry,
                                'certificate_url': certificate_url,
                            }
                        )

                        if success:
                            # Log that we sent this warning
                            ExpirationWarningLog.objects.create(
                                certificate=certificate,
                                warning_threshold=threshold,
                                sent_to=certificate.created_by
                            )
                            total_sent += 1
                            self.stdout.write(
                                self.style.SUCCESS(
                                    f'Sent {threshold}-day warning for {certificate.common_name} '
                                    f'to {certificate.created_by.email}'
                                )
                            )
                        else:
                            self.stdout.write(
                                self.style.ERROR(
                                    f'Failed to send warning for {certificate.common_name}'
                                )
                            )

                    # Only send one warning per certificate per run (the most urgent one)
                    break

        if dry_run:
            self.stdout.write(self.style.SUCCESS(f'[DRY RUN] Would have sent {total_sent} warnings'))
        else:
            self.stdout.write(self.style.SUCCESS(f'Sent {total_sent} expiration warnings'))
