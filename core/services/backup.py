"""
Backup and restore service for PKI data.

Provides functionality to create encrypted backup archives and restore them.
"""
import gzip
import hashlib
import json
import os
import struct
from datetime import datetime
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from django.core import serializers
from django.db import transaction

from core.models import (
    CertificateAuthority,
    Certificate,
    CertificateProfile,
    AppSettings,
    AuditLog,
)


BACKUP_VERSION = 1
MAGIC_BYTES = b'PEMLY\x00\x01\x00'  # Magic identifier + version


class BackupError(Exception):
    """Base exception for backup operations."""
    pass


class BackupService:
    """Service for creating and restoring PKI backups."""

    @staticmethod
    def create_backup(
        include_audit_logs: bool = False,
        password: Optional[str] = None
    ) -> bytes:
        """
        Create a backup archive.

        Args:
            include_audit_logs: Whether to include audit log entries
            password: Optional password for AES encryption

        Returns:
            Binary backup archive
        """
        # Serialize models
        data = {
            'version': BACKUP_VERSION,
            'created_at': datetime.utcnow().isoformat(),
            'includes_audit_logs': include_audit_logs,
            'certificate_authorities': json.loads(
                serializers.serialize('json', CertificateAuthority.objects.all())
            ),
            'certificates': json.loads(
                serializers.serialize('json', Certificate.objects.all())
            ),
            'certificate_profiles': json.loads(
                serializers.serialize('json', CertificateProfile.objects.all())
            ),
            'app_settings': json.loads(
                serializers.serialize('json', AppSettings.objects.all())
            ),
        }

        if include_audit_logs:
            data['audit_logs'] = json.loads(
                serializers.serialize('json', AuditLog.objects.all())
            )

        # Serialize to JSON and compress
        json_data = json.dumps(data).encode('utf-8')
        compressed = gzip.compress(json_data)

        # Calculate checksum of compressed data
        checksum = hashlib.sha256(compressed).hexdigest()

        # Build header
        header = {
            'version': BACKUP_VERSION,
            'checksum': checksum,
            'encrypted': password is not None,
            'includes_audit_logs': include_audit_logs,
            'created_at': data['created_at'],
        }
        header_json = json.dumps(header).encode('utf-8')

        # Encrypt if password provided
        if password:
            payload = BackupService._encrypt(compressed, password)
        else:
            payload = compressed

        # Build final archive: MAGIC + header_len (4 bytes) + header + payload
        archive = bytearray(MAGIC_BYTES)
        archive.extend(struct.pack('>I', len(header_json)))
        archive.extend(header_json)
        archive.extend(payload)

        return bytes(archive)

    @staticmethod
    def _encrypt(data: bytes, password: str) -> bytes:
        """Encrypt data using AES-256-GCM with PBKDF2-derived key."""
        salt = os.urandom(16)
        nonce = os.urandom(12)

        # Derive key from password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = kdf.derive(password.encode('utf-8'))

        # Encrypt
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None)

        # Return salt + nonce + ciphertext
        return salt + nonce + ciphertext

    @staticmethod
    def _decrypt(data: bytes, password: str) -> bytes:
        """Decrypt AES-256-GCM encrypted data."""
        salt = data[:16]
        nonce = data[16:28]
        ciphertext = data[28:]

        # Derive key from password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = kdf.derive(password.encode('utf-8'))

        # Decrypt
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    @staticmethod
    def parse_backup(
        archive: bytes,
        password: Optional[str] = None
    ) -> dict:
        """
        Parse and validate a backup archive.

        Args:
            archive: Binary backup archive
            password: Password if encrypted

        Returns:
            Parsed backup data with metadata

        Raises:
            BackupError: If validation fails
        """
        # Verify magic bytes
        if not archive.startswith(MAGIC_BYTES):
            raise BackupError("Invalid backup file format")

        # Parse header
        offset = len(MAGIC_BYTES)
        header_len = struct.unpack('>I', archive[offset:offset + 4])[0]
        offset += 4

        header_json = archive[offset:offset + header_len]
        header = json.loads(header_json.decode('utf-8'))
        offset += header_len

        payload = archive[offset:]

        # Check version compatibility
        if header['version'] > BACKUP_VERSION:
            raise BackupError(
                f"Backup version {header['version']} is newer than supported "
                f"version {BACKUP_VERSION}"
            )

        # Decrypt if needed
        if header['encrypted']:
            if not password:
                raise BackupError("This backup is password-protected")
            try:
                payload = BackupService._decrypt(payload, password)
            except Exception:
                raise BackupError("Invalid password or corrupted backup")

        # Verify checksum
        if hashlib.sha256(payload).hexdigest() != header['checksum']:
            raise BackupError("Backup integrity check failed - data may be corrupted")

        # Decompress and parse
        json_data = gzip.decompress(payload)
        data = json.loads(json_data.decode('utf-8'))

        return {
            'header': header,
            'data': data,
        }

    @staticmethod
    def get_backup_preview(parsed_backup: dict) -> dict:
        """
        Generate a preview of what will be restored.

        Returns counts and potential conflicts.
        """
        data = parsed_backup['data']

        preview = {
            'created_at': parsed_backup['header']['created_at'],
            'includes_audit_logs': parsed_backup['header'].get('includes_audit_logs', False),
            'counts': {
                'certificate_authorities': len(data.get('certificate_authorities', [])),
                'certificates': len(data.get('certificates', [])),
                'certificate_profiles': len(data.get('certificate_profiles', [])),
                'audit_logs': len(data.get('audit_logs', [])),
            },
            'conflicts': {
                'certificate_authorities': 0,
                'certificates': 0,
                'certificate_profiles': 0,
            },
        }

        # Check for conflicts (existing records with same UUIDs)
        ca_ids = [item['pk'] for item in data.get('certificate_authorities', [])]
        preview['conflicts']['certificate_authorities'] = (
            CertificateAuthority.objects.filter(id__in=ca_ids).count()
        )

        cert_ids = [item['pk'] for item in data.get('certificates', [])]
        preview['conflicts']['certificates'] = (
            Certificate.objects.filter(id__in=cert_ids).count()
        )

        profile_ids = [item['pk'] for item in data.get('certificate_profiles', [])]
        preview['conflicts']['certificate_profiles'] = (
            CertificateProfile.objects.filter(id__in=profile_ids).count()
        )

        return preview

    @staticmethod
    @transaction.atomic
    def restore_backup(
        parsed_backup: dict,
        mode: str = 'merge'
    ) -> dict:
        """
        Restore data from a parsed backup.

        Args:
            parsed_backup: Output from parse_backup()
            mode: 'merge' (add new, skip existing) or 'replace' (delete all, restore)

        Returns:
            Summary of restored items
        """
        data = parsed_backup['data']
        summary = {
            'certificate_authorities': {'created': 0, 'skipped': 0, 'updated': 0},
            'certificates': {'created': 0, 'skipped': 0, 'updated': 0},
            'certificate_profiles': {'created': 0, 'skipped': 0, 'updated': 0},
            'audit_logs': {'created': 0, 'skipped': 0},
        }

        if mode == 'replace':
            # Delete existing data (preserve User references)
            Certificate.objects.all().delete()
            CertificateAuthority.objects.all().delete()
            CertificateProfile.objects.filter(is_builtin=False).delete()
            AppSettings.objects.all().delete()

        # Restore CAs - first pass: create all CAs without parent references
        # to handle circular references in hierarchy
        ca_parent_map = {}  # pk -> parent_id for second pass
        for item in data.get('certificate_authorities', []):
            pk = item['pk']
            fields = item['fields'].copy()

            if mode == 'merge' and CertificateAuthority.objects.filter(id=pk).exists():
                summary['certificate_authorities']['skipped'] += 1
                continue

            # Store parent reference for second pass
            parent_id = fields.pop('parent', None)
            if parent_id:
                ca_parent_map[pk] = parent_id

            # Remove foreign key fields that need special handling
            created_by_id = fields.pop('created_by', None)
            key_removed_by_id = fields.pop('key_removed_by', None)

            # Handle binary field for crl_der
            crl_der = fields.pop('crl_der', None)

            ca = CertificateAuthority(id=pk, **fields)
            ca.created_by_id = created_by_id
            ca.key_removed_by_id = key_removed_by_id
            if crl_der:
                # Django serializes binary as base64
                import base64
                ca.crl_der = base64.b64decode(crl_der)
            ca.save()
            summary['certificate_authorities']['created'] += 1

        # Second pass: update parent references
        for pk, parent_id in ca_parent_map.items():
            try:
                ca = CertificateAuthority.objects.get(id=pk)
                ca.parent_id = parent_id
                ca.save(update_fields=['parent'])
            except CertificateAuthority.DoesNotExist:
                pass

        # Restore certificates
        for item in data.get('certificates', []):
            pk = item['pk']
            fields = item['fields'].copy()

            if mode == 'merge' and Certificate.objects.filter(id=pk).exists():
                summary['certificates']['skipped'] += 1
                continue

            # Remove foreign key fields
            ca_id = fields.pop('ca', None)
            created_by_id = fields.pop('created_by', None)

            cert = Certificate(id=pk, **fields)
            cert.ca_id = ca_id
            cert.created_by_id = created_by_id
            cert.save()
            summary['certificates']['created'] += 1

        # Restore profiles (skip built-in, they can be regenerated)
        for item in data.get('certificate_profiles', []):
            pk = item['pk']
            fields = item['fields'].copy()

            # Skip built-in profiles in merge mode
            if fields.get('is_builtin', False) and mode == 'merge':
                summary['certificate_profiles']['skipped'] += 1
                continue

            if mode == 'merge' and CertificateProfile.objects.filter(id=pk).exists():
                summary['certificate_profiles']['skipped'] += 1
                continue

            # Remove foreign key fields
            created_by_id = fields.pop('created_by', None)

            profile = CertificateProfile(id=pk, **fields)
            profile.created_by_id = created_by_id
            profile.save()
            summary['certificate_profiles']['created'] += 1

        # Restore app settings
        if data.get('app_settings'):
            for item in data['app_settings']:
                fields = item['fields'].copy()
                AppSettings.objects.update_or_create(pk=1, defaults=fields)

        # Restore audit logs only in replace mode
        if mode == 'replace' and data.get('audit_logs'):
            AuditLog.objects.all().delete()
            for item in data['audit_logs']:
                pk = item['pk']
                fields = item['fields'].copy()

                # Remove foreign key fields
                user_id = fields.pop('user', None)

                log = AuditLog(id=pk, **fields)
                log.user_id = user_id
                log.save()
                summary['audit_logs']['created'] += 1

        return summary
