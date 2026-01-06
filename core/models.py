import uuid

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from django.conf import settings
from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone


class KeyAlgorithm(models.TextChoices):
    """Supported key algorithms."""
    RSA = 'rsa', 'RSA'
    ECDSA = 'ecdsa', 'ECDSA'


class CertificateType(models.TextChoices):
    """Types of certificates that can be issued."""
    SERVER_TLS = 'server_tls', 'Server TLS'
    CLIENT_AUTH = 'client_auth', 'Client Authentication'


class CertificateStatus(models.TextChoices):
    """Certificate lifecycle status."""
    ACTIVE = 'active', 'Active'
    REVOKED = 'revoked', 'Revoked'
    EXPIRED = 'expired', 'Expired'


class RevocationReason(models.TextChoices):
    """Standard certificate revocation reasons (RFC 5280)."""
    UNSPECIFIED = 'unspecified', 'Unspecified'
    KEY_COMPROMISE = 'key_compromise', 'Key Compromise'
    CA_COMPROMISE = 'ca_compromise', 'CA Compromise'
    AFFILIATION_CHANGED = 'affiliation_changed', 'Affiliation Changed'
    SUPERSEDED = 'superseded', 'Superseded'
    CESSATION_OF_OPERATION = 'cessation_of_operation', 'Cessation of Operation'
    CERTIFICATE_HOLD = 'certificate_hold', 'Certificate Hold'
    PRIVILEGE_WITHDRAWN = 'privilege_withdrawn', 'Privilege Withdrawn'


class CAType(models.TextChoices):
    """Types of Certificate Authorities."""
    ROOT = 'root', 'Root CA'
    INTERMEDIATE = 'intermediate', 'Intermediate CA'


class CAStatus(models.TextChoices):
    """CA operational status."""
    ACTIVE = 'active', 'Active'
    AIR_GAPPED = 'air_gapped', 'Air-Gapped (Key Removed)'
    PENDING = 'pending', 'Pending (Awaiting Certificate)'
    REVOKED = 'revoked', 'Revoked'
    EXPIRED = 'expired', 'Expired'


class CertificateAuthority(models.Model):
    """
    Certificate Authority for signing certificates.

    Supports hierarchical CA structure: Root CA → Intermediate CA(s) → Certificates.
    Private key is encrypted at rest using Fernet.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, help_text="Friendly name for this CA")
    common_name = models.CharField(max_length=255)
    organization = models.CharField(max_length=255)
    organizational_unit = models.CharField(max_length=255, blank=True)
    country = models.CharField(max_length=2, help_text="Two-letter country code")
    state = models.CharField(max_length=255)
    locality = models.CharField(max_length=255)

    # CA hierarchy
    ca_type = models.CharField(
        max_length=20,
        choices=CAType.choices,
        default=CAType.ROOT,
        help_text="Whether this is a root or intermediate CA"
    )
    parent = models.ForeignKey(
        'self',
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name='children',
        help_text="Parent CA that signed this CA's certificate"
    )
    status = models.CharField(
        max_length=20,
        choices=CAStatus.choices,
        default=CAStatus.ACTIVE
    )
    path_length = models.IntegerField(
        null=True,
        blank=True,
        help_text="Maximum CA path length constraint (0 = can only sign end-entity certs)"
    )

    # Key configuration
    key_algorithm = models.CharField(
        max_length=10,
        choices=KeyAlgorithm.choices,
        default=KeyAlgorithm.RSA
    )
    key_size = models.IntegerField(
        default=4096,
        help_text="Key size in bits (RSA: 2048, 4096; ECDSA: 256, 384)"
    )
    validity_years = models.IntegerField(default=10)

    # Certificate data
    certificate_pem = models.TextField(blank=True)
    private_key_pem_encrypted = models.TextField(blank=True)
    public_key_pem = models.TextField(blank=True)
    csr_pem = models.TextField(blank=True, help_text="CSR for pending intermediates awaiting external signing")
    serial_number = models.CharField(max_length=255, blank=True)

    # Validity dates
    not_before = models.DateTimeField(null=True, blank=True)
    not_after = models.DateTimeField(null=True, blank=True)

    # Legacy status field (kept for backwards compatibility)
    is_active = models.BooleanField(default=True)

    # Air-gap tracking
    key_removed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When the private key was removed for air-gapping"
    )
    key_removed_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name='airgapped_cas',
        help_text="User who removed the private key"
    )

    # CRL cache
    crl_pem = models.TextField(blank=True, help_text="Cached CRL in PEM format")
    crl_der = models.BinaryField(blank=True, null=True, help_text="Cached CRL in DER format")
    crl_generated_at = models.DateTimeField(null=True, blank=True)
    crl_next_update = models.DateTimeField(null=True, blank=True)

    # Audit fields
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name='created_cas'
    )

    class Meta:
        verbose_name = "Certificate Authority"
        verbose_name_plural = "Certificate Authorities"
        ordering = ['-created_at']

    def __str__(self):
        return self.name

    def set_private_key(self, plaintext_key: str) -> None:
        """Encrypt and store the private key."""
        if not settings.ENCRYPTION_KEY:
            raise ValueError("ENCRYPTION_KEY not configured")
        f = Fernet(settings.ENCRYPTION_KEY.encode())
        self.private_key_pem_encrypted = f.encrypt(plaintext_key.encode()).decode()

    def get_private_key(self) -> str:
        """Decrypt and return the private key."""
        if not settings.ENCRYPTION_KEY:
            raise ValueError("ENCRYPTION_KEY not configured")
        if not self.private_key_pem_encrypted:
            return ""
        f = Fernet(settings.ENCRYPTION_KEY.encode())
        return f.decrypt(self.private_key_pem_encrypted.encode()).decode()

    @property
    def is_expired(self) -> bool:
        """Check if the CA certificate has expired."""
        if not self.not_after:
            return False
        return timezone.now() > self.not_after

    @property
    def days_until_expiry(self) -> int | None:
        """Days until CA certificate expires."""
        if not self.not_after:
            return None
        delta = self.not_after - timezone.now()
        return max(0, delta.days)

    @property
    def is_root(self) -> bool:
        """Check if this is a root CA."""
        return self.ca_type == CAType.ROOT

    @property
    def is_intermediate(self) -> bool:
        """Check if this is an intermediate CA."""
        return self.ca_type == CAType.INTERMEDIATE

    @property
    def is_air_gapped(self) -> bool:
        """Check if private key has been removed."""
        return self.status == CAStatus.AIR_GAPPED

    @property
    def can_sign(self) -> bool:
        """Check if this CA can sign certificates."""
        return (
            self.status == CAStatus.ACTIVE and
            bool(self.private_key_pem_encrypted) and
            not self.is_expired
        )

    @property
    def has_private_key(self) -> bool:
        """Check if private key is available."""
        return bool(self.private_key_pem_encrypted)

    @property
    def depth(self) -> int:
        """Return the depth in the CA hierarchy (root = 0)."""
        if self.parent is None:
            return 0
        return self.parent.depth + 1

    def get_chain(self) -> list['CertificateAuthority']:
        """Return the full certificate chain from this CA up to root."""
        chain = [self]
        current = self
        while current.parent:
            chain.append(current.parent)
            current = current.parent
        return chain

    def get_chain_pem(self) -> str:
        """Return concatenated PEM certificates for the full chain."""
        return '\n'.join(ca.certificate_pem for ca in self.get_chain() if ca.certificate_pem)

    def remove_private_key(self, user: User) -> str:
        """
        Remove and return the private key for air-gapping.

        Args:
            user: User performing the operation

        Returns:
            The plaintext private key (for download)

        Raises:
            ValueError: If no private key exists
        """
        if not self.private_key_pem_encrypted:
            raise ValueError("No private key to remove")

        private_key = self.get_private_key()
        self.private_key_pem_encrypted = ''
        self.status = CAStatus.AIR_GAPPED
        self.key_removed_at = timezone.now()
        self.key_removed_by = user
        self.save()
        return private_key

    def restore_private_key(self, private_key: str, user: User) -> None:
        """
        Restore a private key (for signing new intermediates).

        Args:
            private_key: The plaintext private key PEM
            user: User performing the operation

        Raises:
            ValueError: If key doesn't match certificate
        """
        # Validate the key matches the certificate's public key
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from cryptography import x509

        try:
            loaded_key = load_pem_private_key(private_key.encode(), password=None)
            cert = x509.load_pem_x509_certificate(self.certificate_pem.encode())

            # Compare public keys
            key_public = loaded_key.public_key()
            cert_public = cert.public_key()

            # Serialize both to compare
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
            key_pub_bytes = key_public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            cert_pub_bytes = cert_public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

            if key_pub_bytes != cert_pub_bytes:
                raise ValueError("Private key does not match certificate")

        except Exception as e:
            if "does not match" in str(e):
                raise
            raise ValueError(f"Invalid private key: {e}")

        self.set_private_key(private_key)
        self.status = CAStatus.ACTIVE
        self.key_removed_at = None
        self.key_removed_by = None
        self.save()

    @property
    def crl_cache_valid(self) -> bool:
        """Check if the cached CRL is still valid."""
        if not self.crl_pem or not self.crl_generated_at:
            return False
        # CRL is cached for 6 hours
        cache_duration = timezone.timedelta(hours=6)
        return timezone.now() < self.crl_generated_at + cache_duration

    def refresh_crl(self, force: bool = False) -> None:
        """
        Generate a new CRL using the cryptography library.

        Args:
            force: If True, refresh even if cache is valid
        """
        if not force and self.crl_cache_valid:
            return

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from datetime import datetime, timedelta
        import datetime as dt

        # Load CA certificate and private key
        ca_cert = x509.load_pem_x509_certificate(self.certificate_pem.encode())
        ca_key = load_pem_private_key(
            self.get_private_key().encode(),
            password=None
        )

        # Build CRL
        now = datetime.now(dt.timezone.utc)
        next_update = now + timedelta(hours=24)

        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(ca_cert.subject)
        builder = builder.last_update(now)
        builder = builder.next_update(next_update)

        # Add all revoked certificates
        from core.models import Certificate, CertificateStatus
        revoked_certs = Certificate.objects.filter(
            ca=self,
            status=CertificateStatus.REVOKED
        ).exclude(serial_number='')

        for cert in revoked_certs:
            try:
                serial = int(cert.serial_number, 16)
                revoked_cert = (
                    x509.RevokedCertificateBuilder()
                    .serial_number(serial)
                    .revocation_date(cert.revoked_at)
                    .build()
                )
                builder = builder.add_revoked_certificate(revoked_cert)
            except (ValueError, TypeError):
                # Skip certificates with invalid serial numbers
                continue

        # Sign the CRL
        crl = builder.sign(ca_key, hashes.SHA256())

        # Store in both formats
        self.crl_pem = crl.public_bytes(serialization.Encoding.PEM).decode()
        self.crl_der = crl.public_bytes(serialization.Encoding.DER)
        self.crl_generated_at = timezone.now()
        self.crl_next_update = next_update
        self.save(update_fields=['crl_pem', 'crl_der', 'crl_generated_at', 'crl_next_update'])


class Certificate(models.Model):
    """
    Individual certificate issued by the CA.

    Supports both server-side key generation and CSR-based issuance.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    ca = models.ForeignKey(
        CertificateAuthority,
        on_delete=models.PROTECT,
        related_name='certificates'
    )

    # Certificate type
    type = models.CharField(
        max_length=20,
        choices=CertificateType.choices,
        default=CertificateType.SERVER_TLS
    )

    # Subject information
    common_name = models.CharField(max_length=255)
    organization = models.CharField(max_length=255, blank=True)

    # Subject Alternative Names (SANs)
    san_dns_names = models.JSONField(default=list, blank=True)
    san_ip_addresses = models.JSONField(default=list, blank=True)
    san_email_addresses = models.JSONField(default=list, blank=True)

    # Key configuration
    key_algorithm = models.CharField(
        max_length=10,
        choices=KeyAlgorithm.choices,
        default=KeyAlgorithm.RSA
    )
    key_size = models.IntegerField(default=2048)
    validity_days = models.IntegerField(default=365)

    # Certificate data
    certificate_pem = models.TextField(blank=True)
    private_key_pem_encrypted = models.TextField(
        blank=True,
        help_text="Only stored for server-generated keys"
    )
    public_key_pem = models.TextField(blank=True)
    csr_pem = models.TextField(blank=True, help_text="Original CSR if user-submitted")
    serial_number = models.CharField(max_length=255, blank=True)

    # Validity dates
    not_before = models.DateTimeField(null=True, blank=True)
    not_after = models.DateTimeField(null=True, blank=True)

    # Status and revocation
    status = models.CharField(
        max_length=20,
        choices=CertificateStatus.choices,
        default=CertificateStatus.ACTIVE
    )
    revoked_at = models.DateTimeField(null=True, blank=True)
    revocation_reason = models.CharField(
        max_length=30,
        choices=RevocationReason.choices,
        blank=True
    )

    # Audit fields
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name='created_certificates'
    )

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.common_name} ({self.get_type_display()})"

    def set_private_key(self, plaintext_key: str) -> None:
        """Encrypt and store the private key."""
        if not settings.ENCRYPTION_KEY:
            raise ValueError("ENCRYPTION_KEY not configured")
        f = Fernet(settings.ENCRYPTION_KEY.encode())
        self.private_key_pem_encrypted = f.encrypt(plaintext_key.encode()).decode()

    def get_private_key(self) -> str:
        """Decrypt and return the private key."""
        if not settings.ENCRYPTION_KEY:
            raise ValueError("ENCRYPTION_KEY not configured")
        if not self.private_key_pem_encrypted:
            return ""
        f = Fernet(settings.ENCRYPTION_KEY.encode())
        return f.decrypt(self.private_key_pem_encrypted.encode()).decode()

    @property
    def has_private_key(self) -> bool:
        """Check if private key is stored (server-generated)."""
        return bool(self.private_key_pem_encrypted)

    @property
    def is_expired(self) -> bool:
        """Check if the certificate has expired."""
        if not self.not_after:
            return False
        return timezone.now() > self.not_after

    @property
    def days_until_expiry(self) -> int | None:
        """Days until certificate expires."""
        if not self.not_after:
            return None
        delta = self.not_after - timezone.now()
        return max(0, delta.days)

    @property
    def is_expiring_soon(self) -> bool:
        """Check if certificate expires within 30 days."""
        days = self.days_until_expiry
        return days is not None and days <= 30

    def get_chain_pem(self) -> str:
        """Return full certificate chain: cert → intermediate(s) → root."""
        chain_parts = [self.certificate_pem]
        chain_parts.append(self.ca.get_chain_pem())
        return '\n'.join(part for part in chain_parts if part)

    def revoke(self, reason: str = RevocationReason.UNSPECIFIED) -> None:
        """Mark the certificate as revoked."""
        self.status = CertificateStatus.REVOKED
        self.revoked_at = timezone.now()
        self.revocation_reason = reason
        self.save(update_fields=['status', 'revoked_at', 'revocation_reason'])


class AuditLog(models.Model):
    """
    Immutable audit log for all certificate operations.

    Records who did what, when, and from where.
    """

    class Action(models.TextChoices):
        CA_CREATED = 'ca_created', 'CA Created'
        CA_UPDATED = 'ca_updated', 'CA Updated'
        INTERMEDIATE_CA_CREATED = 'intermediate_created', 'Intermediate CA Created'
        CA_KEY_EXPORTED = 'ca_key_exported', 'CA Key Exported'
        CA_KEY_REMOVED = 'ca_key_removed', 'CA Key Removed (Air-Gapped)'
        CA_KEY_RESTORED = 'ca_key_restored', 'CA Key Restored'
        CA_CSR_GENERATED = 'ca_csr_generated', 'CA CSR Generated'
        CA_CERT_IMPORTED = 'ca_cert_imported', 'CA Certificate Imported'
        CERT_ISSUED = 'cert_issued', 'Certificate Issued'
        CERT_REVOKED = 'cert_revoked', 'Certificate Revoked'
        CERT_DOWNLOADED = 'cert_downloaded', 'Certificate Downloaded'
        USER_LOGIN = 'user_login', 'User Login'
        USER_LOGOUT = 'user_logout', 'User Logout'
        BACKUP_CREATED = 'backup_created', 'Backup Created'
        BACKUP_RESTORED = 'backup_restored', 'Backup Restored'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_logs'
    )
    action = models.CharField(max_length=30, choices=Action.choices, db_index=True)
    resource_type = models.CharField(max_length=50, db_index=True)
    resource_id = models.UUIDField(null=True, blank=True)
    resource_name = models.CharField(max_length=255, blank=True)
    details = models.JSONField(default=dict, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=500, blank=True)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = "Audit Log"
        verbose_name_plural = "Audit Logs"

    def __str__(self):
        return f"{self.timestamp} - {self.get_action_display()} by {self.user}"

    @classmethod
    def log(
        cls,
        action: str,
        resource_type: str,
        resource_id: uuid.UUID | None = None,
        resource_name: str = "",
        user: User | None = None,
        details: dict | None = None,
        ip_address: str | None = None,
        user_agent: str = ""
    ) -> "AuditLog":
        """Create an audit log entry."""
        return cls.objects.create(
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            user=user,
            details=details or {},
            ip_address=ip_address,
            user_agent=user_agent
        )


class AppSettings(models.Model):
    """
    Application settings stored in the database.

    Singleton model - only one instance should exist.
    These settings override environment variables when set.
    """

    # CFSSL Settings
    cfssl_auto_start = models.BooleanField(
        default=True,
        help_text="Automatically start CFSSL when the application starts"
    )
    cfssl_binary_path = models.CharField(
        max_length=500,
        blank=True,
        help_text="Path to CFSSL binary (leave empty for auto-detection)"
    )
    cfssl_host = models.CharField(
        max_length=255,
        default='localhost',
        help_text="Host for CFSSL to bind to"
    )
    cfssl_port = models.PositiveIntegerField(
        default=8888,
        help_text="Port for CFSSL to listen on"
    )

    # Metadata
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Application Settings"
        verbose_name_plural = "Application Settings"

    def __str__(self):
        return "Application Settings"

    def save(self, *args, **kwargs):
        """Ensure only one instance exists."""
        self.pk = 1
        super().save(*args, **kwargs)

    @classmethod
    def get(cls) -> "AppSettings":
        """Get the settings instance, creating it if necessary."""
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj


class CertificateProfile(models.Model):
    """
    Pre-defined certificate templates for common use cases.

    Profiles speed up certificate issuance by pre-filling form fields
    with sensible defaults for specific use cases.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, help_text="Profile name")
    description = models.TextField(blank=True, help_text="Description of when to use this profile")

    # Whether this is a built-in profile (cannot be deleted)
    is_builtin = models.BooleanField(default=False)

    # Certificate defaults
    certificate_type = models.CharField(
        max_length=50,
        choices=CertificateType.choices,
        default=CertificateType.SERVER_TLS
    )
    validity_days = models.PositiveIntegerField(
        default=365,
        help_text="Default certificate validity in days"
    )

    # Key configuration defaults
    key_algorithm = models.CharField(
        max_length=10,
        choices=KeyAlgorithm.choices,
        default=KeyAlgorithm.RSA
    )
    key_size = models.PositiveIntegerField(
        default=2048,
        help_text="Key size in bits (RSA: 2048/4096, ECDSA: 256/384)"
    )

    # Optional organization default
    organization = models.CharField(
        max_length=255,
        blank=True,
        help_text="Default organization (leave empty to inherit from CA)"
    )

    # Metadata
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='certificate_profiles'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['is_builtin', 'name']

    def __str__(self):
        return self.name

    @classmethod
    def get_builtin_profiles(cls):
        """Return queryset of built-in profiles."""
        return cls.objects.filter(is_builtin=True)

    @classmethod
    def get_user_profiles(cls):
        """Return queryset of user-created profiles."""
        return cls.objects.filter(is_builtin=False)
