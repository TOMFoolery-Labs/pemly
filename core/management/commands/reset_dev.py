"""
Management command to reset the development environment.

Usage:
    python manage.py reset_dev
    python manage.py reset_dev --no-input  # Skip confirmations, use default superuser
"""

import os
import shutil
from pathlib import Path

from django.conf import settings
from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = 'Reset the development environment: clear database and storage, re-run migrations'

    def add_arguments(self, parser):
        parser.add_argument(
            '--no-input',
            action='store_true',
            help='Skip all prompts and use defaults (username: admin, password: admin)',
        )

    def handle(self, *args, **options):
        no_input = options['no_input']
        base_dir = settings.BASE_DIR

        # Safety check - only allow in DEBUG mode
        if not settings.DEBUG:
            raise CommandError('This command can only be run with DEBUG=True')

        if not no_input:
            self.stdout.write(self.style.WARNING(
                '\nThis will DELETE all data:\n'
                '  - SQLite database\n'
                '  - All CA certificates and keys\n'
                '  - All issued certificates\n'
                '  - CFSSL data\n'
            ))
            confirm = input('Are you sure you want to continue? [y/N] ')
            if confirm.lower() != 'y':
                self.stdout.write(self.style.NOTICE('Cancelled.'))
                return

        # 1. Remove database
        db_path = base_dir / 'db.sqlite3'
        if db_path.exists():
            os.remove(db_path)
            self.stdout.write(f'  Removed {db_path}')
        else:
            self.stdout.write(f'  Database not found at {db_path}')

        # 2. Clear storage directories
        storage_dirs = [
            base_dir / 'storage' / 'ca',
            base_dir / 'storage' / 'certificates',
            base_dir / 'storage' / 'cfssl',
        ]

        for storage_dir in storage_dirs:
            if storage_dir.exists():
                for item in storage_dir.iterdir():
                    if item.is_file():
                        item.unlink()
                    elif item.is_dir():
                        shutil.rmtree(item)
                self.stdout.write(f'  Cleared {storage_dir}')

        self.stdout.write(self.style.SUCCESS('\nStorage cleared.'))

        # 3. Run migrations
        self.stdout.write('\nRunning migrations...')
        call_command('migrate', verbosity=1)
        self.stdout.write(self.style.SUCCESS('Migrations complete.'))

        # 4. Create superuser
        self.stdout.write('\nCreating superuser...')
        if no_input:
            from django.contrib.auth import get_user_model
            User = get_user_model()
            User.objects.create_superuser(
                username='admin',
                email='admin@example.com',
                password='admin'
            )
            self.stdout.write(self.style.SUCCESS(
                'Created superuser: admin / admin'
            ))
        else:
            call_command('createsuperuser')

        self.stdout.write(self.style.SUCCESS(
            '\nDevelopment environment reset complete!\n'
            'You can now run: python manage.py runserver'
        ))
